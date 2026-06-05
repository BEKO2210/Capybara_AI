import { pgTable, uuid, text, integer, boolean, timestamp, unique } from 'drizzle-orm/pg-core';
import { organizations } from './organizations.js';

export const scimConfigs = pgTable('scim_configs', {
  id: uuid('id').primaryKey().defaultRandom(),
  orgId: uuid('org_id').notNull().unique().references(() => organizations.id, { onDelete: 'cascade' }),
  bearerTokenHash: text('bearer_token_hash').notNull(),
  tokenPrefix: text('token_prefix').notNull(),
  active: boolean('active').notNull().default(true),
  lastSyncAt: timestamp('last_sync_at', { withTimezone: true }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
});

export const encryptionKeyVersions = pgTable('encryption_key_versions', {
  id: uuid('id').primaryKey().defaultRandom(),
  orgId: uuid('org_id').notNull().references(() => organizations.id, { onDelete: 'cascade' }),
  keyVersion: integer('key_version').notNull(),
  keyEncrypted: text('key_encrypted').notNull(),
  algorithm: text('algorithm').notNull().default('AES-256-GCM'),
  active: boolean('active').notNull().default(true),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  retiredAt: timestamp('retired_at', { withTimezone: true }),
}, (t) => [unique('encryption_key_org_version_unique').on(t.orgId, t.keyVersion)]);

/**
 * Brute-force lockout state, keyed by normalized login identifier (email).
 * Global (pre-tenant) like `users`/`sessions`; no RLS. The application enforces
 * a sliding failure window and exponential-backoff lock.
 */
export const authLockouts = pgTable('auth_lockouts', {
  identifier: text('identifier').primaryKey(),
  failedCount: integer('failed_count').notNull().default(0),
  lockoutCount: integer('lockout_count').notNull().default(0),
  firstFailedAt: timestamp('first_failed_at', { withTimezone: true }).notNull().defaultNow(),
  lastFailedAt: timestamp('last_failed_at', { withTimezone: true }).notNull().defaultNow(),
  lockedUntil: timestamp('locked_until', { withTimezone: true }),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
});

export type ScimConfig = typeof scimConfigs.$inferSelect;
export type EncryptionKeyVersion = typeof encryptionKeyVersions.$inferSelect;
export type AuthLockout = typeof authLockouts.$inferSelect;
