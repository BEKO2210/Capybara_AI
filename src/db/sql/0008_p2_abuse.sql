-- 0008_p2_abuse.sql — P2 hardening: account abuse lockout (brute-force defense).
--
-- Login attempts are pre-tenant (no org context yet), so `auth_lockouts` is a
-- GLOBAL table governed at the application layer — the same posture as
-- `users`/`sessions`. It is keyed by a normalized identifier (email) and tracks
-- a sliding failure window plus an exponential-backoff lock.

CREATE TABLE IF NOT EXISTS auth_lockouts (
  identifier      text PRIMARY KEY,             -- normalized (lowercased) email
  failed_count    integer NOT NULL DEFAULT 0,   -- failures in the current window
  lockout_count   integer NOT NULL DEFAULT 0,   -- successive locks (drives backoff)
  first_failed_at timestamptz NOT NULL DEFAULT now(),
  last_failed_at  timestamptz NOT NULL DEFAULT now(),
  locked_until    timestamptz,                  -- NULL when not locked
  updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS auth_lockouts_locked_until_idx ON auth_lockouts (locked_until);

-- Least-privilege grants (explicit; default privileges also cover this).
GRANT SELECT, INSERT, UPDATE, DELETE ON auth_lockouts TO capybara_app;
