-- 0006_enterprise.sql — Enterprise integrations. Idempotent.

ALTER TABLE users ADD COLUMN IF NOT EXISTS invite_token_hash text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_active_at timestamptz;

-- Reusable helper: enable + force RLS with an org-isolation policy.
-- (Expressed inline per table below for clarity.)

-- ── Metering (billing-ready, append-only) ───────────────────────────────────
CREATE TABLE IF NOT EXISTS metering_events (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  event_type    text NOT NULL CHECK (event_type IN ('LLM_CALL','DOCUMENT_UPLOAD','QUERY','STORAGE_GB_DAY')),
  quantity      numeric NOT NULL DEFAULT 1,
  unit          text NOT NULL DEFAULT 'count',
  model         text,
  provider      text,
  metadata_json jsonb,
  created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS metering_org_id_idx ON metering_events (org_id);
ALTER TABLE metering_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE metering_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS metering_isolation ON metering_events;
CREATE POLICY metering_isolation ON metering_events
  USING (org_id = current_setting('app.current_org', true)::uuid)
  WITH CHECK (org_id = current_setting('app.current_org', true)::uuid);
GRANT SELECT, INSERT ON metering_events TO capybara_app;
REVOKE UPDATE, DELETE ON metering_events FROM capybara_app;

-- ── Data export jobs (GDPR Art. 20) ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS export_jobs (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id              uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  requested_by        uuid REFERENCES users(id) ON DELETE SET NULL,
  status              text NOT NULL DEFAULT 'PENDING'
                        CHECK (status IN ('PENDING','RUNNING','DONE','FAILED','EXPIRED')),
  file_path           text,
  download_token_hash text,
  expires_at          timestamptz,
  error               text,
  created_at          timestamptz NOT NULL DEFAULT now(),
  completed_at        timestamptz
);
CREATE INDEX IF NOT EXISTS export_jobs_org_id_idx ON export_jobs (org_id);
ALTER TABLE export_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE export_jobs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS export_jobs_isolation ON export_jobs;
CREATE POLICY export_jobs_isolation ON export_jobs
  USING (org_id = current_setting('app.current_org', true)::uuid)
  WITH CHECK (org_id = current_setting('app.current_org', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON export_jobs TO capybara_app;

-- ── Per-tenant OIDC configuration ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS oidc_configs (
  id                     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id                 uuid NOT NULL UNIQUE REFERENCES organizations(id) ON DELETE CASCADE,
  issuer                 text NOT NULL,
  client_id              text NOT NULL,
  client_secret_encrypted text NOT NULL,
  redirect_uri           text NOT NULL,
  auto_provision         boolean NOT NULL DEFAULT true,
  default_role           text NOT NULL DEFAULT 'member'
                           CHECK (default_role IN ('owner','admin','member','viewer')),
  domain_hint            text,
  active                 boolean NOT NULL DEFAULT true,
  created_at             timestamptz NOT NULL DEFAULT now(),
  updated_at             timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS oidc_configs_domain_idx ON oidc_configs (domain_hint);
ALTER TABLE oidc_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE oidc_configs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS oidc_configs_isolation ON oidc_configs;
CREATE POLICY oidc_configs_isolation ON oidc_configs
  USING (org_id = current_setting('app.current_org', true)::uuid)
  WITH CHECK (org_id = current_setting('app.current_org', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON oidc_configs TO capybara_app;

-- A SECURITY DEFINER lookup for domain→org during SSO login (before any tenant
-- context exists). Returns only non-secret routing fields for ACTIVE configs.
CREATE OR REPLACE FUNCTION oidc_config_by_domain(p_domain text)
  RETURNS TABLE(org_id uuid, issuer text, client_id text, redirect_uri text, auto_provision boolean, default_role text)
  LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  SELECT org_id, issuer, client_id, redirect_uri, auto_provision, default_role
  FROM oidc_configs WHERE domain_hint = p_domain AND active = true LIMIT 1;
$$;
REVOKE ALL ON FUNCTION oidc_config_by_domain(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION oidc_config_by_domain(text) TO capybara_app;

-- ── API keys ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS api_keys (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id       uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  created_by   uuid REFERENCES users(id) ON DELETE SET NULL,
  name         text NOT NULL,
  key_hash     text NOT NULL UNIQUE,
  key_prefix   text NOT NULL,
  scopes       text[] NOT NULL DEFAULT '{}',
  last_used_at timestamptz,
  expires_at   timestamptz,
  active       boolean NOT NULL DEFAULT true,
  created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS api_keys_org_id_idx ON api_keys (org_id);
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS api_keys_isolation ON api_keys;
CREATE POLICY api_keys_isolation ON api_keys
  USING (org_id = current_setting('app.current_org', true)::uuid)
  WITH CHECK (org_id = current_setting('app.current_org', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON api_keys TO capybara_app;

-- SECURITY DEFINER lookup by key hash for authentication (no tenant context yet).
CREATE OR REPLACE FUNCTION api_key_by_hash(p_hash text)
  RETURNS TABLE(id uuid, org_id uuid, scopes text[], expires_at timestamptz, active boolean)
  LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  SELECT id, org_id, scopes, expires_at, active FROM api_keys WHERE key_hash = p_hash LIMIT 1;
$$;
REVOKE ALL ON FUNCTION api_key_by_hash(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION api_key_by_hash(text) TO capybara_app;

-- ── Webhooks ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS webhook_configs (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id           uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  url              text NOT NULL,
  secret_encrypted text NOT NULL,
  events           text[] NOT NULL DEFAULT '{}',
  active           boolean NOT NULL DEFAULT true,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS webhook_configs_org_id_idx ON webhook_configs (org_id);
ALTER TABLE webhook_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_configs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS webhook_configs_isolation ON webhook_configs;
CREATE POLICY webhook_configs_isolation ON webhook_configs
  USING (org_id = current_setting('app.current_org', true)::uuid)
  WITH CHECK (org_id = current_setting('app.current_org', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON webhook_configs TO capybara_app;

CREATE TABLE IF NOT EXISTS webhook_deliveries (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id       uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  webhook_id   uuid NOT NULL REFERENCES webhook_configs(id) ON DELETE CASCADE,
  event_type   text NOT NULL,
  status       text NOT NULL DEFAULT 'pending'
                 CHECK (status IN ('pending','delivered','failed')),
  status_code  integer,
  attempt      integer NOT NULL DEFAULT 0,
  delivered_at timestamptz,
  created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS webhook_deliveries_webhook_idx ON webhook_deliveries (webhook_id);
ALTER TABLE webhook_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_deliveries FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS webhook_deliveries_isolation ON webhook_deliveries;
CREATE POLICY webhook_deliveries_isolation ON webhook_deliveries
  USING (org_id = current_setting('app.current_org', true)::uuid)
  WITH CHECK (org_id = current_setting('app.current_org', true)::uuid);
GRANT SELECT, INSERT, UPDATE ON webhook_deliveries TO capybara_app;
REVOKE DELETE ON webhook_deliveries FROM capybara_app;
