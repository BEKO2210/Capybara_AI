-- 0005_compliance.sql — EU AI Act compliance module. Idempotent.

-- ── KI-Inventar (Art. 4) ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ai_inventory_entries (
  id                         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id                     uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  model_id                   text,
  model_name                 text NOT NULL,
  provider                   text NOT NULL,
  purpose                    text NOT NULL DEFAULT '',
  risk_class                 text NOT NULL DEFAULT 'LIMITED'
                               CHECK (risk_class IN ('MINIMAL','LIMITED','HIGH','UNACCEPTABLE')),
  in_use_since               date NOT NULL DEFAULT CURRENT_DATE,
  human_oversight_required   boolean NOT NULL DEFAULT true,
  data_categories_processed  text[] NOT NULL DEFAULT '{}',
  legal_basis                text NOT NULL DEFAULT '',
  notes                      text NOT NULL DEFAULT '',
  created_by                 uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at                 timestamptz NOT NULL DEFAULT now(),
  updated_at                 timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ai_inventory_org_model_unique UNIQUE (org_id, model_name, provider)
);
CREATE INDEX IF NOT EXISTS ai_inventory_org_id_idx ON ai_inventory_entries (org_id);

ALTER TABLE ai_inventory_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_inventory_entries FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ai_inventory_isolation ON ai_inventory_entries;
CREATE POLICY ai_inventory_isolation ON ai_inventory_entries
  USING (org_id = current_setting('app.current_org', true)::uuid)
  WITH CHECK (org_id = current_setting('app.current_org', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON ai_inventory_entries TO capybara_app;

-- ── Human Oversight (Art. 14) ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS oversight_requests (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id              uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  requested_by        uuid REFERENCES users(id) ON DELETE SET NULL,
  tool_name           text NOT NULL,
  tool_args_hash      text NOT NULL,
  tool_args_encrypted text NOT NULL,
  risk_level          text NOT NULL
                        CHECK (risk_level IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  status              text NOT NULL DEFAULT 'PENDING'
                        CHECK (status IN ('PENDING','APPROVED','REJECTED','EXPIRED')),
  decided_by          uuid REFERENCES users(id) ON DELETE SET NULL,
  decided_at          timestamptz,
  expires_at          timestamptz NOT NULL DEFAULT (now() + interval '24 hours'),
  outcome_summary     text,
  created_at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS oversight_org_id_idx ON oversight_requests (org_id);
CREATE INDEX IF NOT EXISTS oversight_status_idx ON oversight_requests (status);

ALTER TABLE oversight_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE oversight_requests FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS oversight_isolation ON oversight_requests;
CREATE POLICY oversight_isolation ON oversight_requests
  USING (org_id = current_setting('app.current_org', true)::uuid)
  WITH CHECK (org_id = current_setting('app.current_org', true)::uuid);

-- Forward-only status + immutable identity/args (append-only semantics on the
-- sensitive columns): a decided request can never be re-decided or rewritten.
CREATE OR REPLACE FUNCTION oversight_forward_only() RETURNS trigger
  LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.status <> 'PENDING' THEN
    RAISE EXCEPTION 'oversight request already decided (status=%)', OLD.status
      USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.tool_name <> OLD.tool_name
     OR NEW.tool_args_hash <> OLD.tool_args_hash
     OR NEW.org_id <> OLD.org_id
     OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION 'immutable oversight column changed' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$$;
DROP TRIGGER IF EXISTS oversight_forward_only_trg ON oversight_requests;
CREATE TRIGGER oversight_forward_only_trg BEFORE UPDATE ON oversight_requests
  FOR EACH ROW EXECUTE FUNCTION oversight_forward_only();

-- INSERT + SELECT + UPDATE (to move status forward); DELETE not granted.
GRANT SELECT, INSERT, UPDATE ON oversight_requests TO capybara_app;
REVOKE DELETE ON oversight_requests FROM capybara_app;
