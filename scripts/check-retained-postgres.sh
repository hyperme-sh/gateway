#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# Same disposable PostgreSQL build as Infra's owner-fixture contracts.
image=postgres:16-alpine@sha256:20edbde7749f822887a1a022ad526fde0a47d6b2be9a8364433605cf65099416
container=''
cleanup() {
  if [[ -n "$container" ]]; then docker rm -f "$container" >/dev/null; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

POSTGRES_PASSWORD=$(openssl rand -hex 32)
export POSTGRES_PASSWORD
container=$(docker run --detach --network none --tmpfs /var/lib/postgresql/data \
  --env POSTGRES_PASSWORD "$image")
unset POSTGRES_PASSWORD

ready=false
for _ in {1..45}; do
  # The entrypoint starts a provisional server while creating the cluster.
  if docker exec "$container" sh -c '[ "$(cat /proc/1/comm)" = postgres ] && pg_isready -U postgres >/dev/null'; then
    ready=true
    break
  fi
  sleep 1
done
[[ "$ready" == true ]]

sql() {
  docker exec -i "$container" psql -X -U postgres -d "$1" --set ON_ERROR_STOP=1 --quiet
}

sql postgres <<'SQL'
CREATE ROLE gateway_history_runtime LOGIN NOINHERIT;
CREATE ROLE gateway_training_runtime LOGIN NOINHERIT;
CREATE DATABASE gateway_history;
CREATE DATABASE gateway_training;
SQL

sql gateway_history < deployment/retained-data/0001-history.sql
sql gateway_training < deployment/retained-data/0001-training.sql
sql postgres <<'SQL'
DO $check$
BEGIN
    IF NOT has_database_privilege('gateway_history_runtime', 'gateway_history', 'CONNECT')
       OR NOT has_database_privilege('gateway_training_runtime', 'gateway_training', 'CONNECT')
       OR has_database_privilege('gateway_history_runtime', 'gateway_training', 'CONNECT')
       OR has_database_privilege('gateway_training_runtime', 'gateway_history', 'CONNECT') THEN
        RAISE EXCEPTION 'The Gateway store role cannot cross its database boundary';
    END IF;
END;
$check$;
SQL

test_store() {
  local store=$1 payload=$2 conditional_columns=$3 conditional_values=$4 audit=$5 audit_columns=$6 audit_values=$7
  local own=00000000-0000-4000-8000-000000000001
  local other=00000000-0000-4000-8000-000000000002
  local db="gateway_$store"
  # Arguments are fixed identifiers and expressions from the two calls below.
  sql "$db" <<SQL
INSERT INTO public.tenants (id) VALUES ('$own'), ('$other');
INSERT INTO public.$payload (id,tenant_id,subject,created_at,prompt,output,media_type$conditional_columns)
VALUES (gen_random_uuid(),'$own','subject',now(),'{}',decode('01','hex'),'text/plain'$conditional_values),
       (gen_random_uuid(),'$other','subject',now(),'{}',decode('02','hex'),'text/plain'$conditional_values);
SET ROLE ${db}_runtime;
DO \$check\$
BEGIN
    IF (SELECT count(*) FROM public.$payload) <> 0 THEN
        RAISE EXCEPTION 'Tenant context must fail closed';
    END IF;
    PERFORM set_config('app.current_tenant_id', '$own', true);
    IF (SELECT array_agg(tenant_id) FROM public.$payload) IS DISTINCT FROM ARRAY['$own'::uuid]
       OR has_table_privilege(current_user, 'public.$payload', 'INSERT')
       OR has_table_privilege(current_user, 'public.tenants', 'SELECT') THEN
        RAISE EXCEPTION 'Unexpected runtime access';
    END IF;
    INSERT INTO public.$audit (id,tenant_id,subject,actor,deleted_count,created_at$audit_columns)
    VALUES (gen_random_uuid(),'$own','subject','fixture',0,now()$audit_values);
    BEGIN
        INSERT INTO public.$audit (id,tenant_id,subject,actor,deleted_count,created_at$audit_columns)
        VALUES (gen_random_uuid(),'$other','subject','fixture',0,now()$audit_values);
        RAISE EXCEPTION 'A runtime role inserted a different tenant row';
    EXCEPTION WHEN insufficient_privilege THEN
        NULL;
    END;
    DELETE FROM public.$payload;
END;
\$check\$;
RESET ROLE;
DO \$check\$
BEGIN
    IF (SELECT array_agg(tenant_id) FROM public.$payload) IS DISTINCT FROM ARRAY['$other'::uuid] THEN
        RAISE EXCEPTION 'Runtime deletion did not preserve the other tenant';
    END IF;
END;
\$check\$;
SQL
  printf '%s schema and runtime grants passed.\n' "$db"
}

test_store history hypermesh_history_entries '' '' hypermesh_history_audit ',action' ",'closure_purge'"
test_store training hypermesh_training_submissions ',consent_at' ',now()' hypermesh_training_deletions '' ''
