import { pgTable, uuid, text, timestamp, jsonb } from 'drizzle-orm/pg-core';

/**
 * Business/sensitive-action audit trail (login, role change, membership change,
 * approval decisions, etc.). Append-only by convention; the app role is granted
 * SELECT/INSERT only (UPDATE/DELETE revoked at the DB layer).
 *
 * Callers MUST NOT place secrets or raw PII in `metadata` — it is stored in
 * plaintext for queryability.
 */
export const auditLog = pgTable('audit_log', {
  id: uuid('id').primaryKey().defaultRandom(),
  orgId: uuid('org_id'),
  actorUserId: uuid('actor_user_id'),
  action: text('action').notNull(),
  targetType: text('target_type'),
  targetId: text('target_id'),
  metadata: jsonb('metadata'),
  ip: text('ip'),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

export type AuditEntry = typeof auditLog.$inferSelect;
export type NewAuditEntry = typeof auditLog.$inferInsert;
