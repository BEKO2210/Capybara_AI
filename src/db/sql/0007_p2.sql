-- 0007_p2.sql — P2 hardening: SCIM provisioning + versioned encryption keys.

-- ── SCIM config (per-org bearer token) ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS scim_configs (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id            uuid NOT NULL UNIQUE REFERENCES organizations(id) ON DELETE CASCADE,
  bearer_token_hash text NOT NULL,
  token_prefix      text NOT NULL,
  active            boolean NOT NULL DEFAULT true,
  last_sync_at      timestamptz,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE scim_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_configs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS scim_configs_isolation ON scim_configs;
CREATE POLICY scim_configs_isolation ON scim_configs
  USING (org_id = current_setting('app.current_org', true)::uuid)
  WITH CHECK (org_id = current_setting('app.current_org', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON scim_configs TO capybara_app;

-- Resolve org by SCIM token hash (pre-auth, no tenant context yet).
CREATE OR REPLACE FUNCTION scim_org_by_token(p_hash text)
  RETURNS uuid LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  SELECT org_id FROM scim_configs WHERE bearer_token_hash = p_hash AND active = true LIMIT 1;
$$;
REVOKE ALL ON FUNCTION scim_org_by_token(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION scim_org_by_token(text) TO capybara_app;

-- ── Versioned encryption keys (envelope encryption) ─────────────────────────
CREATE TABLE IF NOT EXISTS encryption_key_versions (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  key_version   integer NOT NULL,
  key_encrypted text NOT NULL,                 -- DEK wrapped with the master KEK
  algorithm     text NOT NULL DEFAULT 'AES-256-GCM',
  active        boolean NOT NULL DEFAULT true,
  created_at    timestamptz NOT NULL DEFAULT now(),
  retired_at    timestamptz,
  CONSTRAINT encryption_key_org_version_unique UNIQUE (org_id, key_version)
);
CREATE INDEX IF NOT EXISTS encryption_key_org_idx ON encryption_key_versions (org_id);
ALTER TABLE encryption_key_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE encryption_key_versions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS encryption_key_isolation ON encryption_key_versions;
CREATE POLICY encryption_key_isolation ON encryption_key_versions
  USING (org_id = current_setting('app.current_org', true)::uuid)
  WITH CHECK (org_id = current_setting('app.current_org', true)::uuid);
-- INSERT + SELECT + UPDATE (to retire); never DELETE (audit retention).
GRANT SELECT, INSERT, UPDATE ON encryption_key_versions TO capybara_app;
REVOKE DELETE ON encryption_key_versions FROM capybara_app;
