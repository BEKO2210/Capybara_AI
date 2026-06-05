import { pgTable, uuid, text, timestamp } from 'drizzle-orm/pg-core';
import { organizations } from './organizations.js';
import { users } from './users.js';

/**
 * Server-side opaque sessions. We store only the SHA-256 hash of the session
 * token (never the raw token), enabling instant revocation and avoiding a
 * JWT-secret-leak blast radius. `org_id` records the active tenant context.
 */
export const sessions = pgTable('sessions', {
  id: uuid('id').primaryKey().defaultRandom(),
  tokenHash: text('token_hash').notNull().unique(),
  userId: uuid('user_id')
    .notNull()
    .references(() => users.id, { onDelete: 'cascade' }),
  orgId: uuid('org_id').references(() => organizations.id, { onDelete: 'cascade' }),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  revokedAt: timestamp('revoked_at', { withTimezone: true }),
});

export type Session = typeof sessions.$inferSelect;
export type NewSession = typeof sessions.$inferInsert;
