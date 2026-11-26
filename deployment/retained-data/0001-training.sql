-- Gateway retained training schema, migration 0001.
BEGIN;
SET LOCAL search_path = pg_catalog;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

DO $guard$
BEGIN
    IF current_database() <> 'gateway_training' THEN
        RAISE EXCEPTION 'Incorrect Gateway owner database';
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'gateway_training_runtime'
        AND rolcanlogin AND NOT (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication))
        OR EXISTS (SELECT FROM pg_auth_members WHERE member =
            (SELECT oid FROM pg_roles WHERE rolname = 'gateway_training_runtime')) THEN
        RAISE EXCEPTION 'Expected a restricted Gateway owner runtime role';
    END IF;
END;
$guard$;

REVOKE ALL ON DATABASE gateway_training FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT CONNECT ON DATABASE gateway_training TO gateway_training_runtime;
GRANT USAGE ON SCHEMA public TO gateway_training_runtime;

-- Infra imports the authoritative tenant UUIDs through its deployment principal.
CREATE TABLE public.tenants (id UUID PRIMARY KEY);
REVOKE ALL ON TABLE public.tenants FROM PUBLIC;

CREATE TABLE public.hypermesh_training_consents (
    tenant_id UUID NOT NULL,
    subject VARCHAR(512) NOT NULL,
    enabled BOOLEAN NOT NULL,
    generation INTEGER NOT NULL,
    consent_at TIMESTAMP WITH TIME ZONE,
    collect_after TIMESTAMP WITH TIME ZONE,
    PRIMARY KEY (tenant_id, subject),
    CONSTRAINT ck_training_generation CHECK (generation >= 0),
    CONSTRAINT ck_training_consent_time CHECK ((enabled AND consent_at IS NOT NULL AND collect_after IS NOT NULL) OR (NOT enabled AND consent_at IS NULL)),
    FOREIGN KEY(tenant_id) REFERENCES public.tenants (id) ON DELETE RESTRICT
);
ALTER TABLE public.hypermesh_training_consents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.hypermesh_training_consents FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON public.hypermesh_training_consents TO gateway_training_runtime
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);
REVOKE ALL ON TABLE public.hypermesh_training_consents FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.hypermesh_training_consents TO gateway_training_runtime;

CREATE TABLE public.hypermesh_training_submissions (
    id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    subject VARCHAR(512) NOT NULL,
    consent_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    prompt JSONB NOT NULL,
    output BYTEA NOT NULL,
    media_type VARCHAR(128) NOT NULL,
    PRIMARY KEY (id),
    FOREIGN KEY(tenant_id) REFERENCES public.tenants (id) ON DELETE RESTRICT
);
CREATE INDEX ix_training_account ON public.hypermesh_training_submissions (tenant_id, subject);
ALTER TABLE public.hypermesh_training_submissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.hypermesh_training_submissions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON public.hypermesh_training_submissions TO gateway_training_runtime
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);
REVOKE ALL ON TABLE public.hypermesh_training_submissions FROM PUBLIC;
GRANT SELECT, DELETE ON TABLE public.hypermesh_training_submissions TO gateway_training_runtime;

CREATE TABLE public.hypermesh_training_deletions (
    id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    subject VARCHAR(512) NOT NULL,
    actor VARCHAR(512) NOT NULL,
    deleted_count INTEGER NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    PRIMARY KEY (id),
    FOREIGN KEY(tenant_id) REFERENCES public.tenants (id) ON DELETE RESTRICT
);
ALTER TABLE public.hypermesh_training_deletions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.hypermesh_training_deletions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON public.hypermesh_training_deletions TO gateway_training_runtime
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);
REVOKE ALL ON TABLE public.hypermesh_training_deletions FROM PUBLIC;
GRANT SELECT, INSERT ON TABLE public.hypermesh_training_deletions TO gateway_training_runtime;

COMMIT;
