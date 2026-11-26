-- Gateway retained history schema, migration 0001.
BEGIN;
SET LOCAL search_path = pg_catalog;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

DO $guard$
BEGIN
    IF current_database() <> 'gateway_history' THEN
        RAISE EXCEPTION 'Incorrect Gateway owner database';
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'gateway_history_runtime'
        AND rolcanlogin AND NOT (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication))
        OR EXISTS (SELECT FROM pg_auth_members WHERE member =
            (SELECT oid FROM pg_roles WHERE rolname = 'gateway_history_runtime')) THEN
        RAISE EXCEPTION 'Expected a restricted Gateway owner runtime role';
    END IF;
END;
$guard$;

REVOKE ALL ON DATABASE gateway_history FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT CONNECT ON DATABASE gateway_history TO gateway_history_runtime;
GRANT USAGE ON SCHEMA public TO gateway_history_runtime;

-- Infra imports the authoritative tenant UUIDs through its deployment principal.
CREATE TABLE public.tenants (id UUID PRIMARY KEY);
REVOKE ALL ON TABLE public.tenants FROM PUBLIC;

CREATE TABLE public.hypermesh_history_preferences (
    tenant_id UUID NOT NULL,
    subject VARCHAR(512) NOT NULL,
    enabled BOOLEAN NOT NULL,
    generation INTEGER NOT NULL,
    consent_at TIMESTAMP WITH TIME ZONE,
    collect_after TIMESTAMP WITH TIME ZONE,
    closed_at TIMESTAMP WITH TIME ZONE,
    purged_at TIMESTAMP WITH TIME ZONE,
    PRIMARY KEY (tenant_id, subject),
    CONSTRAINT ck_history_generation CHECK (generation >= 0),
    CONSTRAINT ck_history_enabled CHECK ((NOT enabled) OR (consent_at IS NOT NULL AND collect_after IS NOT NULL AND closed_at IS NULL)),
    FOREIGN KEY(tenant_id) REFERENCES public.tenants (id) ON DELETE RESTRICT
);
CREATE INDEX ix_history_retention ON public.hypermesh_history_preferences (tenant_id, closed_at, subject);
ALTER TABLE public.hypermesh_history_preferences ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.hypermesh_history_preferences FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON public.hypermesh_history_preferences TO gateway_history_runtime
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);
REVOKE ALL ON TABLE public.hypermesh_history_preferences FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON TABLE public.hypermesh_history_preferences TO gateway_history_runtime;

CREATE TABLE public.hypermesh_history_entries (
    id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    subject VARCHAR(512) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    prompt JSONB NOT NULL,
    output BYTEA NOT NULL,
    media_type VARCHAR(128) NOT NULL,
    PRIMARY KEY (id),
    FOREIGN KEY(tenant_id) REFERENCES public.tenants (id) ON DELETE RESTRICT
);
CREATE INDEX ix_history_owner ON public.hypermesh_history_entries (tenant_id, subject, created_at, id);
ALTER TABLE public.hypermesh_history_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.hypermesh_history_entries FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON public.hypermesh_history_entries TO gateway_history_runtime
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);
REVOKE ALL ON TABLE public.hypermesh_history_entries FROM PUBLIC;
GRANT SELECT, DELETE ON TABLE public.hypermesh_history_entries TO gateway_history_runtime;

CREATE TABLE public.hypermesh_history_audit (
    id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    subject VARCHAR(512) NOT NULL,
    actor VARCHAR(512) NOT NULL,
    action VARCHAR(32) NOT NULL,
    deleted_count INTEGER NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    PRIMARY KEY (id),
    FOREIGN KEY(tenant_id) REFERENCES public.tenants (id) ON DELETE RESTRICT
);
ALTER TABLE public.hypermesh_history_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.hypermesh_history_audit FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON public.hypermesh_history_audit TO gateway_history_runtime
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);
REVOKE ALL ON TABLE public.hypermesh_history_audit FROM PUBLIC;
GRANT SELECT, INSERT ON TABLE public.hypermesh_history_audit TO gateway_history_runtime;

COMMIT;
