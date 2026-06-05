import { sql } from 'drizzle-orm';
import type { AppDatabase } from '../db/client.js';
import { withTenantContext } from '../tenancy/scope.js';
import { decryptSecret, deriveTenantKey } from '../lib/crypto.js';
import type { Embedder } from '../ai/embeddings/embedder.js';
import { logAccess } from './accessLog.js';

export interface SearchResult {
  chunkId: string;
  documentId: string;
  documentTitle: string;
  chunkIndex: number;
  content: string;
  similarity: number;
  classification: string;
}

export interface SearchDeps {
  db: AppDatabase;
  embedder: Embedder;
  masterKey: Buffer;
}

export interface SearchParams {
  query: string;
  orgId: string;
  userId: string;
  clearance: number;
  limit?: number;
  ip?: string | undefined;
}

interface RawRow {
  chunk_id: string;
  document_id: string;
  document_title: string;
  chunk_index: number;
  content_encrypted: string;
  classification: string;
  similarity: string | number;
}

/**
 * Cosine-similarity vector search over the caller's tenant, gated by
 * classification clearance at TWO independent layers:
 *   - Application: the explicit `classification_rank(...) <= clearance` predicate.
 *   - Database: Postgres RLS on document_chunks AND documents (FORCE RLS, the
 *     app role cannot bypass) keyed on app.current_org + app.current_clearance.
 * Both must fail simultaneously to leak across a tenant/clearance boundary.
 * The QUERY action is logged with only a SHA-256 hash of the query text.
 */
export async function searchDocuments(deps: SearchDeps, params: SearchParams): Promise<SearchResult[]> {
  const limit = params.limit ?? 10;
  const [queryVec] = await deps.embedder.embed([params.query]);
  if (!queryVec) return [];
  const vecLiteral = `[${queryVec.join(',')}]`;

  return withTenantContext(
    deps.db,
    { orgId: params.orgId, userId: params.userId, clearance: params.clearance },
    async (tx) => {
      const result = await tx.execute(sql`
        SELECT c.id AS chunk_id,
               c.document_id,
               d.title AS document_title,
               c.chunk_index,
               c.content_encrypted,
               c.classification,
               1 - (c.embedding <=> ${vecLiteral}::vector) AS similarity
        FROM document_chunks c
        JOIN documents d ON d.id = c.document_id AND d.deleted_at IS NULL
        WHERE classification_rank(c.classification) <= ${params.clearance}
        ORDER BY c.embedding <=> ${vecLiteral}::vector
        LIMIT ${limit}
      `);
      const rows = result as unknown as RawRow[];

      const tenantKey = deriveTenantKey(deps.masterKey, params.orgId);
      const results: SearchResult[] = rows.map((r) => ({
        chunkId: r.chunk_id,
        documentId: r.document_id,
        documentTitle: r.document_title,
        chunkIndex: r.chunk_index,
        content: decryptSecret(r.content_encrypted, tenantKey),
        similarity: Number(r.similarity),
        classification: r.classification,
      }));

      await logAccess(tx, {
        orgId: params.orgId,
        action: 'QUERY',
        userId: params.userId,
        queryText: params.query,
        ...(params.ip ? { ip: params.ip } : {}),
      });

      return results;
    },
  );
}
