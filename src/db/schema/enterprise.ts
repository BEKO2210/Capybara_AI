import { pgTable, uuid, text, integer, numeric, boolean, jsonb, timestamp } from 'drizzle-orm/pg-core';
import { organizations } from './organizations.js';
import { users } from './users.js';

export const METERING_EVENT_TYPES = ['LLM_CALL', 'DOCUMENT_UPLOAD', 'QUERY', 'STORAGE_GB_DAY'] as const;
export type MeteringEventType = (typeof METERING_EVENT_TYPES)[number];

/** Append-only billing meter (app role: SELECT/INSERT only). */
export const meteringEvents = pgTable('metering_events', {
  id: uuid('id').primaryKey().defaultRandom(),
  orgId: uuid('org_id').notNull().references(() => organizations.id, { onDelete: 'cascade' }),
  eventType: text('event_type').notNull(),
  quantity: numeric('quantity').notNull().default('1'),
  unit: text('unit').notNull().default('count'),
  model: text('model'),
  provider: text('provider'),
  metadataJson: jsonb('metadata_json'),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

export const exportJobs = pgTable('export_jobs', {
  id: uuid('id').primaryKey().defaultRandom(),
  orgId: uuid('org_id').notNull().references(() => organizations.id, { onDelete: 'cascade' }),
  requestedBy: uuid('requested_by').references(() => users.id, { onDelete: 'set null' }),
  status: text('status').notNull().default('PENDING'),
  filePath: text('file_path'),
  downloadTokenHash: text('download_token_hash'),
  expiresAt: timestamp('expires_at', { withTimezone: true }),
  error: text('error'),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  completedAt: timestamp('completed_at', { withTimezone: true }),
});

export const oidcConfigs = pgTable('oidc_configs', {
  id: uuid('id').primaryKey().defaultRandom(),
  orgId: uuid('org_id').notNull().unique().references(() => organizations.id, { onDelete: 'cascade' }),
  issuer: text('issuer').notNull(),
  clientId: text('client_id').notNull(),
  clientSecretEncrypted: text('client_secret_encrypted').notNull(),
  redirectUri: text('redirect_uri').notNull(),
  autoProvision: boolean('auto_provision').notNull().default(true),
  defaultRole: text('default_role').notNull().default('member'),
  domainHint: text('domain_hint'),
  active: boolean('active').notNull().default(true),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
});

export const API_KEY_SCOPES = ['chat:read', 'chat:write', 'documents:read', 'documents:write', 'admin:read'] as const;
export type ApiKeyScope = (typeof API_KEY_SCOPES)[number];

export const apiKeys = pgTable('api_keys', {
  id: uuid('id').primaryKey().defaultRandom(),
  orgId: uuid('org_id').notNull().references(() => organizations.id, { onDelete: 'cascade' }),
  createdBy: uuid('created_by').references(() => users.id, { onDelete: 'set null' }),
  name: text('name').notNull(),
  keyHash: text('key_hash').notNull().unique(),
  keyPrefix: text('key_prefix').notNull(),
  scopes: text('scopes').array().notNull().default([]),
  lastUsedAt: timestamp('last_used_at', { withTimezone: true }),
  expiresAt: timestamp('expires_at', { withTimezone: true }),
  active: boolean('active').notNull().default(true),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

export const webhookConfigs = pgTable('webhook_configs', {
  id: uuid('id').primaryKey().defaultRandom(),
  orgId: uuid('org_id').notNull().references(() => organizations.id, { onDelete: 'cascade' }),
  url: text('url').notNull(),
  secretEncrypted: text('secret_encrypted').notNull(),
  events: text('events').array().notNull().default([]),
  active: boolean('active').notNull().default(true),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
});

export const webhookDeliveries = pgTable('webhook_deliveries', {
  id: uuid('id').primaryKey().defaultRandom(),
  orgId: uuid('org_id').notNull().references(() => organizations.id, { onDelete: 'cascade' }),
  webhookId: uuid('webhook_id').notNull().references(() => webhookConfigs.id, { onDelete: 'cascade' }),
  eventType: text('event_type').notNull(),
  status: text('status').notNull().default('pending'),
  statusCode: integer('status_code'),
  attempt: integer('attempt').notNull().default(0),
  deliveredAt: timestamp('delivered_at', { withTimezone: true }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

export type MeteringEvent = typeof meteringEvents.$inferSelect;
export type ExportJob = typeof exportJobs.$inferSelect;
export type OidcConfig = typeof oidcConfigs.$inferSelect;
export type ApiKey = typeof apiKeys.$inferSelect;
export type WebhookConfig = typeof webhookConfigs.$inferSelect;
export type WebhookDelivery = typeof webhookDeliveries.$inferSelect;
