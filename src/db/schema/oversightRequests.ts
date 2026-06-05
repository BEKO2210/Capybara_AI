import { pgTable, uuid, text, timestamp } from 'drizzle-orm/pg-core';
import { organizations } from './organizations.js';
import { users } from './users.js';

export const RISK_LEVELS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;
export type RiskLevel = (typeof RISK_LEVELS)[number];

export const OVERSIGHT_STATUSES = ['PENDING', 'APPROVED', 'REJECTED', 'EXPIRED'] as const;
export type OversightStatus = (typeof OVERSIGHT_STATUSES)[number];

/** Numeric ordering for risk levels (for the HIGH-threshold check). */
export const RISK_LEVEL_RANK: Readonly<Record<RiskLevel, number>> = {
  LOW: 0,
  MEDIUM: 1,
  HIGH: 2,
  CRITICAL: 3,
};

/**
 * Human-oversight request (EU AI Act Art. 14). Status is forward-only
 * (PENDING → APPROVED/REJECTED/EXPIRED), enforced by a DB trigger; sensitive
 * columns are immutable after creation. RLS: org-scoped. Args stored encrypted
 * (AES-256-GCM) with a SHA-256 hash for lookup.
 */
export const oversightRequests = pgTable('oversight_requests', {
  id: uuid('id').primaryKey().defaultRandom(),
  orgId: uuid('org_id')
    .notNull()
    .references(() => organizations.id, { onDelete: 'cascade' }),
  requestedBy: uuid('requested_by').references(() => users.id, { onDelete: 'set null' }),
  toolName: text('tool_name').notNull(),
  toolArgsHash: text('tool_args_hash').notNull(),
  toolArgsEncrypted: text('tool_args_encrypted').notNull(),
  riskLevel: text('risk_level').notNull(),
  status: text('status').notNull().default('PENDING'),
  decidedBy: uuid('decided_by').references(() => users.id, { onDelete: 'set null' }),
  decidedAt: timestamp('decided_at', { withTimezone: true }),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  outcomeSummary: text('outcome_summary'),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

export type OversightRequest = typeof oversightRequests.$inferSelect;
export type NewOversightRequest = typeof oversightRequests.$inferInsert;
