-- 0002_audit.sql — audit trail + tamper-evident security event log.
-- Idempotent. The security_events log is append-only at the DB-permission
-- layer: the application role may SELECT/INSERT but NOT UPDATE/DELETE, so a
-- compromised app cannot rewrite history without detection.

CREATE TABLE IF NOT EXISTS audit_log (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id         uuid,
  actor_user_id  uuid,
  action         text NOT NULL,
  target_type    text,
  target_id      text,
  metadata       jsonb,
  ip             text,
  created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS audit_log_org_id_idx ON audit_log (org_id);

CREATE TABLE IF NOT EXISTS security_events (
  id          bigserial PRIMARY KEY,
  org_id      uuid,
  event_type  text NOT NULL,
  severity    text NOT NULL,
  payload     jsonb NOT NULL,
  prev_hash   text NOT NULL,
  hash        text NOT NULL,
  created_at  timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS security_events_org_id_idx ON security_events (org_id);

-- Least-privilege grants for the application role.
GRANT SELECT, INSERT ON audit_log TO capybara_app;
GRANT SELECT, INSERT ON security_events TO capybara_app;
GRANT USAGE, SELECT ON SEQUENCE security_events_id_seq TO capybara_app;

-- Tamper-evidence: the app role cannot mutate or delete history.
REVOKE UPDATE, DELETE ON audit_log FROM capybara_app;
REVOKE UPDATE, DELETE ON security_events FROM capybara_app;
