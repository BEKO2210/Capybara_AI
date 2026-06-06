import { pgTable, bigserial, bigint, text, timestamp } from 'drizzle-orm/pg-core';

/**
 * Signed off-box checkpoints over the security_events hash chain. Append-only
 * (SELECT/INSERT granted, UPDATE/DELETE revoked). Each anchor binds a chain head
 * (event id + hash + count) with an Ed25519 signature verifiable using a public
 * key held outside the database.
 */
export const auditAnchors = pgTable('audit_anchors', {
  id: bigserial('id', { mode: 'number' }).primaryKey(),
  checkpointSeq: bigint('checkpoint_seq', { mode: 'number' }).notNull(),
  eventId: bigint('event_id', { mode: 'number' }).notNull(),
  eventCount: bigint('event_count', { mode: 'number' }).notNull(),
  chainHash: text('chain_hash').notNull(),
  algorithm: text('algorithm').notNull(),
  signature: text('signature').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull(),
});

export type AuditAnchor = typeof auditAnchors.$inferSelect;
export type NewAuditAnchor = typeof auditAnchors.$inferInsert;
