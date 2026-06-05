import { pgTable, uuid, text, boolean, date, timestamp, unique } from 'drizzle-orm/pg-core';
import { organizations } from './organizations.js';
import { users } from './users.js';

export const RISK_CLASSES = ['MINIMAL', 'LIMITED', 'HIGH', 'UNACCEPTABLE'] as const;
export type RiskClass = (typeof RISK_CLASSES)[number];

/** KI-Inventar entry (EU AI Act Art. 4 AI-usage registry). RLS: org-scoped. */
export const aiInventoryEntries = pgTable(
  'ai_inventory_entries',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    orgId: uuid('org_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    modelId: text('model_id'),
    modelName: text('model_name').notNull(),
    provider: text('provider').notNull(),
    purpose: text('purpose').notNull().default(''),
    riskClass: text('risk_class').notNull().default('LIMITED'),
    inUseSince: date('in_use_since').notNull().defaultNow(),
    humanOversightRequired: boolean('human_oversight_required').notNull().default(true),
    dataCategoriesProcessed: text('data_categories_processed').array().notNull().default([]),
    legalBasis: text('legal_basis').notNull().default(''),
    notes: text('notes').notNull().default(''),
    createdBy: uuid('created_by').references(() => users.id, { onDelete: 'set null' }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [unique('ai_inventory_org_model_unique').on(t.orgId, t.modelName, t.provider)],
);

export type AiInventoryEntry = typeof aiInventoryEntries.$inferSelect;
export type NewAiInventoryEntry = typeof aiInventoryEntries.$inferInsert;
