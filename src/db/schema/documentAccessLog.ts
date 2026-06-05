import { pgTable, uuid, text, timestamp } from 'drizzle-orm/pg-core';
import { organizations } from './organizations.js';

export const DOCUMENT_ACTIONS = ['UPLOAD', 'VIEW', 'DOWNLOAD', 'DELETE', 'QUERY'] as const;
export type DocumentAction = (typeof DOCUMENT_ACTIONS)[number];

/**
 * Append-only access trail for documents. The app role may INSERT and SELECT
 * only (UPDATE/DELETE revoked at the DB layer). Query text is never stored in
 * plaintext — only a SHA-256 hash.
 */
export const documentAccessLog = pgTable('document_access_log', {
  id: uuid('id').primaryKey().defaultRandom(),
  orgId: uuid('org_id')
    .notNull()
    .references(() => organizations.id, { onDelete: 'cascade' }),
  documentId: uuid('document_id'),
  userId: uuid('user_id'),
  action: text('action').notNull(),
  queryTextHash: text('query_text_hash'),
  ipAddress: text('ip_address'),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

export type DocumentAccessEntry = typeof documentAccessLog.$inferSelect;
export type NewDocumentAccessEntry = typeof documentAccessLog.$inferInsert;
