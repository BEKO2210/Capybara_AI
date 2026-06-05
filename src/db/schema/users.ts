import { pgTable, uuid, text, timestamp } from 'drizzle-orm/pg-core';

/**
 * Global identity. Users are NOT tenant-scoped: a single human identity may
 * belong to multiple organizations via `memberships`. Authorization within a
 * tenant is granted by membership, never by the user row alone.
 *
 * `email` is stored normalized (lowercased) by the application layer and is
 * globally unique. Passwords are stored only as Argon2id hashes.
 */
export const users = pgTable('users', {
  id: uuid('id').primaryKey().defaultRandom(),
  email: text('email').notNull().unique(),
  passwordHash: text('password_hash').notNull(),
  status: text('status').notNull().default('active'),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;
