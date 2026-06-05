import { pgTable, uuid, text, timestamp, unique } from 'drizzle-orm/pg-core';
import { organizations } from './organizations.js';
import { users } from './users.js';

/** RBAC roles, least-privileged first. Enforced by application + DB CHECK. */
export const ROLES = ['owner', 'admin', 'member', 'viewer'] as const;
export type Role = (typeof ROLES)[number];

/**
 * Join of a user into an organization with a role. This is the tenant-scoped
 * authorization record. RLS keys off `org_id`.
 */
export const memberships = pgTable(
  'memberships',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    orgId: uuid('org_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    role: text('role').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [unique('memberships_org_user_unique').on(t.orgId, t.userId)],
);

export type Membership = typeof memberships.$inferSelect;
export type NewMembership = typeof memberships.$inferInsert;
