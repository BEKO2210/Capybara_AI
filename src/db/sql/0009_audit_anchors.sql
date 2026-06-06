-- 0009_audit_anchors.sql — off-box anchoring of the security-event hash chain.
--
-- Periodically a signed *checkpoint* commits to the current chain head. The
-- signature is produced with an Ed25519 key the application role never holds in
-- a mutable form, and checkpoints can additionally be shipped off-box (file /
-- webhook). Because the signatures are verifiable with a public key held
-- outside the database, even a DB superuser who rewrites `security_events`
-- cannot forge a matching anchor — the rewrite is detectable.
--
-- Append-only at the permission layer, exactly like security_events.

CREATE TABLE IF NOT EXISTS audit_anchors (
  id             bigserial PRIMARY KEY,
  checkpoint_seq bigint NOT NULL UNIQUE,   -- monotonically increasing
  event_id       bigint NOT NULL,          -- security_events.id at anchor time (0 = empty chain)
  event_count    bigint NOT NULL,          -- number of events covered
  chain_hash     text   NOT NULL,          -- the anchored head hash
  algorithm      text   NOT NULL,          -- signature algorithm (e.g. 'ed25519')
  signature      text   NOT NULL,          -- base64 detached signature over the canonical checkpoint
  created_at     timestamptz NOT NULL
);

GRANT SELECT, INSERT ON audit_anchors TO capybara_app;
GRANT USAGE, SELECT ON SEQUENCE audit_anchors_id_seq TO capybara_app;
-- Tamper-evidence: the app role cannot rewrite or delete anchors.
REVOKE UPDATE, DELETE ON audit_anchors FROM capybara_app;
