-- 0004_documents.sql — Document Intelligence (RAG). Idempotent.
-- Requires the pgvector extension (image: pgvector/pgvector:pg16).

CREATE EXTENSION IF NOT EXISTS vector;

-- Numeric clearance rank for a classification label (single source of truth,
-- used by RLS). IMMUTABLE so it can be used in policies efficiently.
CREATE OR REPLACE FUNCTION classification_rank(c text) RETURNS int
  IMMUTABLE LANGUAGE sql AS $$
  SELECT CASE c
    WHEN 'PUBLIC' THEN 0
    WHEN 'INTERNAL' THEN 1
    WHEN 'CONFIDENTIAL' THEN 2
    WHEN 'SECRET' THEN 3
    ELSE 99 END
$$;

-- Reads the caller's clearance GUC, defaulting to -1 (deny) when unset.
CREATE OR REPLACE FUNCTION current_clearance() RETURNS int
  STABLE LANGUAGE sql AS $$
  SELECT COALESCE(NULLIF(current_setting('app.current_clearance', true), '')::int, -1)
$$;

CREATE TABLE IF NOT EXISTS documents (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id          uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  uploaded_by     uuid REFERENCES users(id) ON DELETE SET NULL,
  title           text NOT NULL,
  mime_type       text NOT NULL,
  storage_path    text NOT NULL,
  size_bytes      bigint NOT NULL,
  classification  text NOT NULL DEFAULT 'INTERNAL'
                    CHECK (classification IN ('PUBLIC','INTERNAL','CONFIDENTIAL','SECRET')),
  version         integer NOT NULL DEFAULT 1,
  parent_id       uuid REFERENCES documents(id) ON DELETE SET NULL,
  retention_date  timestamptz,
  legal_hold      boolean NOT NULL DEFAULT false,
  deleted_at      timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS documents_org_id_idx ON documents (org_id);

CREATE TABLE IF NOT EXISTS document_chunks (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id            uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  document_id       uuid NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  chunk_index       integer NOT NULL,
  content_encrypted text NOT NULL,
  embedding         vector(768) NOT NULL,
  classification    text NOT NULL,
  token_count       integer NOT NULL,
  created_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS document_chunks_document_id_idx ON document_chunks (document_id);
CREATE INDEX IF NOT EXISTS document_chunks_embedding_idx
  ON document_chunks USING hnsw (embedding vector_cosine_ops);

CREATE TABLE IF NOT EXISTS document_access_log (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id          uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  document_id     uuid,
  user_id         uuid,
  action          text NOT NULL
                    CHECK (action IN ('UPLOAD','VIEW','DOWNLOAD','DELETE','QUERY')),
  query_text_hash text,
  ip_address      text,
  created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS document_access_log_org_id_idx ON document_access_log (org_id);

CREATE TABLE IF NOT EXISTS conversations (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id     uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS messages (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  conversation_id   uuid NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
  org_id            uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id           uuid,
  role              text NOT NULL,
  content_encrypted text NOT NULL,
  sources_json      jsonb,
  model_used        text,
  created_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS messages_conversation_id_idx ON messages (conversation_id);

-- ── Row-Level Security ──────────────────────────────────────────────────────
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE documents FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS documents_isolation ON documents;
CREATE POLICY documents_isolation ON documents
  USING (
    org_id = current_setting('app.current_org', true)::uuid
    AND classification_rank(classification) <= current_clearance()
  )
  WITH CHECK (org_id = current_setting('app.current_org', true)::uuid);

ALTER TABLE document_chunks ENABLE ROW LEVEL SECURITY;
ALTER TABLE document_chunks FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS document_chunks_isolation ON document_chunks;
CREATE POLICY document_chunks_isolation ON document_chunks
  USING (
    org_id = current_setting('app.current_org', true)::uuid
    AND classification_rank(classification) <= current_clearance()
  )
  WITH CHECK (org_id = current_setting('app.current_org', true)::uuid);

ALTER TABLE document_access_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE document_access_log FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS document_access_log_isolation ON document_access_log;
CREATE POLICY document_access_log_isolation ON document_access_log
  USING (org_id = current_setting('app.current_org', true)::uuid)
  WITH CHECK (org_id = current_setting('app.current_org', true)::uuid);

ALTER TABLE conversations ENABLE ROW LEVEL SECURITY;
ALTER TABLE conversations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS conversations_isolation ON conversations;
CREATE POLICY conversations_isolation ON conversations
  USING (org_id = current_setting('app.current_org', true)::uuid)
  WITH CHECK (org_id = current_setting('app.current_org', true)::uuid);

ALTER TABLE messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE messages FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS messages_isolation ON messages;
CREATE POLICY messages_isolation ON messages
  USING (org_id = current_setting('app.current_org', true)::uuid)
  WITH CHECK (org_id = current_setting('app.current_org', true)::uuid);

-- ── Grants (least privilege) ────────────────────────────────────────────────
GRANT SELECT, INSERT, UPDATE, DELETE ON documents, document_chunks, conversations, messages TO capybara_app;
-- Access log is append-only for the app role.
GRANT SELECT, INSERT ON document_access_log TO capybara_app;
REVOKE UPDATE, DELETE ON document_access_log FROM capybara_app;

-- GDPR anonymization of the (otherwise immutable) access log runs through a
-- vetted SECURITY DEFINER function rather than granting the app role UPDATE.
CREATE OR REPLACE FUNCTION gdpr_anonymize_access_log(target_user uuid) RETURNS integer
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE n integer;
BEGIN
  UPDATE document_access_log SET user_id = NULL WHERE user_id = target_user;
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN n;
END;
$$;
REVOKE ALL ON FUNCTION gdpr_anonymize_access_log(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION gdpr_anonymize_access_log(uuid) TO capybara_app;
