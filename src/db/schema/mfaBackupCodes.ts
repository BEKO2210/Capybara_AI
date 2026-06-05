import { pgTable, uuid, text, timestamp } from 'drizzle-orm/pg-core';
import { users } from './users.js';

/**
 * Single-use MFA backup codes. Only Argon2id hashes are stored; a code is
 * consumed by stamping `used_at` and can never be reused.
 */
export const mfaBackupCodes = pgTable('mfa_backup_codes', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id')
    .notNull()
    .references(() => users.id, { onDelete: 'cascade' }),
  codeHash: text('code_hash').notNull(),
  usedAt: timestamp('used_at', { withTimezone: true }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

export type MfaBackupCode = typeof mfaBackupCodes.$inferSelect;
export type NewMfaBackupCode = typeof mfaBackupCodes.$inferInsert;
