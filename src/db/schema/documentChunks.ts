import { pgTable, uuid, text, integer, timestamp, vector, index } from 'drizzle-orm/pg-core';
import { organizations } from './organizations.js';
import { documents } from './documents.js';

/**
 * A chunk of a document with its embedding. `content_encrypted` is AES-256-GCM
 * ciphertext under the per-tenant key (never plaintext at rest). `classification`
 * is denormalized from the parent so RLS can gate retrieval by clearance without
 * a cross-table subquery. Embeddings are 768-dim (nomic-embed-text).
 */
export const documentChunks = pgTable(
  'document_chunks',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    orgId: uuid('org_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    documentId: uuid('document_id')
      .notNull()
      .references(() => documents.id, { onDelete: 'cascade' }),
    chunkIndex: integer('chunk_index').notNull(),
    contentEncrypted: text('content_encrypted').notNull(),
    embedding: vector('embedding', { dimensions: 768 }).notNull(),
    classification: text('classification').notNull(),
    tokenCount: integer('token_count').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index('document_chunks_document_id_idx').on(t.documentId)],
);

export type DocumentChunk = typeof documentChunks.$inferSelect;
export type NewDocumentChunk = typeof documentChunks.$inferInsert;
