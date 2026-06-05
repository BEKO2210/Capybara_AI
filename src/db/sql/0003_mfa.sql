-- 0003_mfa.sql — TOTP multi-factor authentication. Idempotent.

ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled   boolean NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret    text;       -- AES-256-GCM encrypted
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_last_step bigint;     -- replay guard (last used TOTP step)

CREATE TABLE IF NOT EXISTS mfa_backup_codes (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash   text NOT NULL,        -- Argon2id hash of a single-use code
  used_at     timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS mfa_backup_codes_user_id_idx ON mfa_backup_codes (user_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON mfa_backup_codes TO capybara_app;
