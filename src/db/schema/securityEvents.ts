import { pgTable, uuid, text, timestamp, jsonb, bigserial } from 'drizzle-orm/pg-core';

/**
 * Tamper-evident, append-only security event log. Each row is hash-chained to
 * its predecessor: hash = sha256(prev_hash || canonical(content)). Any later
 * mutation or deletion breaks the chain and is detectable by verifyChain().
 *
 * The app role is granted SELECT/INSERT only; UPDATE/DELETE are revoked at the
 * DB layer, so even a compromised application cannot silently rewrite history.
 */
export const securityEvents = pgTable('security_events', {
  id: bigserial('id', { mode: 'number' }).primaryKey(),
  orgId: uuid('org_id'),
  eventType: text('event_type').notNull(),
  severity: text('severity').notNull(),
  payload: jsonb('payload').notNull(),
  prevHash: text('prev_hash').notNull(),
  hash: text('hash').notNull(),
  // Set explicitly by the writer (not DB default) so it is part of the hash.
  createdAt: timestamp('created_at', { withTimezone: true }).notNull(),
});

export type SecurityEvent = typeof securityEvents.$inferSelect;
export type NewSecurityEvent = typeof securityEvents.$inferInsert;
