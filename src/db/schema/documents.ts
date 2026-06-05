import { pgTable, uuid, text, integer, bigint, boolean, timestamp } from 'drizzle-orm/pg-core';
import { organizations } from './organizations.js';
import { users } from './users.js';

export const CLASSIFICATIONS = ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'SECRET'] as const;
export type Classification = (typeof CLASSIFICATIONS)[number];

/** Numeric clearance rank for a classification (0=PUBLIC … 3=SECRET). */
export const CLASSIFICATION_RANK: Readonly<Record<Classification, number>> = {
  PUBLIC: 0,
  INTERNAL: 1,
  CONFIDENTIAL: 2,
  SECRET: 3,
};

/**
 * A stored, encrypted document. File contents live encrypted on disk under a
 * UUID filename (never the original name); only metadata is in the DB. RLS keys
 * off org_id AND the caller's classification clearance.
 */
export const documents = pgTable('documents', {
  id: uuid('id').primaryKey().defaultRandom(),
  orgId: uuid('org_id')
    .notNull()
    .references(() => organizations.id, { onDelete: 'cascade' }),
  uploadedBy: uuid('uploaded_by').references(() => users.id, { onDelete: 'set null' }),
  title: text('title').notNull(),
  mimeType: text('mime_type').notNull(),
  storagePath: text('storage_path').notNull(),
  sizeBytes: bigint('size_bytes', { mode: 'number' }).notNull(),
  classification: text('classification').notNull().default('INTERNAL'),
  version: integer('version').notNull().default(1),
  parentId: uuid('parent_id'),
  retentionDate: timestamp('retention_date', { withTimezone: true }),
  legalHold: boolean('legal_hold').notNull().default(false),
  deletedAt: timestamp('deleted_at', { withTimezone: true }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
});

export type Document = typeof documents.$inferSelect;
export type NewDocument = typeof documents.$inferInsert;
