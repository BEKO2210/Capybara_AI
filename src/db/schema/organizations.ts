import { pgTable, uuid, text, timestamp } from 'drizzle-orm/pg-core';

/**
 * Tenant root. Every tenant-scoped row references an organization. RLS policies
 * key off `id` (for this table) and `org_id` (for child tables).
 */
export const organizations = pgTable('organizations', {
  id: uuid('id').primaryKey().defaultRandom(),
  slug: text('slug').notNull().unique(),
  name: text('name').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  deletedAt: timestamp('deleted_at', { withTimezone: true }),
});

export type Organization = typeof organizations.$inferSelect;
export type NewOrganization = typeof organizations.$inferInsert;
