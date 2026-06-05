import { createHmac } from 'node:crypto';
import { and, eq, desc, sql } from 'drizzle-orm';
import type { AppDatabase } from '../db/client.js';
import { webhookConfigs, webhookDeliveries, type WebhookConfig, type WebhookDelivery } from '../db/schema/index.js';
import { withTenantContext, type TenantContext } from '../tenancy/scope.js';
import { encryptSecret, decryptSecret, deriveTenantKey } from '../lib/crypto.js';

export const WEBHOOK_EVENTS = [
  'document.uploaded', 'document.deleted', 'chat.completed', 'oversight.requested',
  'oversight.decided', 'user.invited', 'user.deactivated', 'gdpr.erasure_completed',
] as const;
export type WebhookEvent = (typeof WEBHOOK_EVENTS)[number];

export function signPayload(secret: string, body: string): string {
  return 'sha256=' + createHmac('sha256', secret).update(body).digest('hex');
}

export async function createWebhook(
  db: AppDatabase, ctx: TenantContext, input: { url: string; secret: string; events: string[] }, masterKey: Buffer,
): Promise<WebhookConfig> {
  const enc = encryptSecret(input.secret, deriveTenantKey(masterKey, ctx.orgId));
  return withTenantContext(db, ctx, async (tx) => {
    const [row] = await tx.insert(webhookConfigs).values({ orgId: ctx.orgId, url: input.url, secretEncrypted: enc, events: input.events }).returning();
    return row!;
  });
}

export function listWebhooks(db: AppDatabase, ctx: TenantContext): Promise<Omit<WebhookConfig, 'secretEncrypted'>[]> {
  return withTenantContext(db, ctx, async (tx) => {
    const rows = await tx.select().from(webhookConfigs).orderBy(desc(webhookConfigs.createdAt));
    return rows.map(({ secretEncrypted, ...rest }) => rest);
  });
}

export function updateWebhook(
  db: AppDatabase, ctx: TenantContext, id: string, input: { url?: string; events?: string[]; active?: boolean },
): Promise<boolean> {
  return withTenantContext(db, ctx, async (tx) => {
    const rows = await tx.update(webhookConfigs).set({
      ...(input.url !== undefined ? { url: input.url } : {}),
      ...(input.events !== undefined ? { events: input.events } : {}),
      ...(input.active !== undefined ? { active: input.active } : {}),
      updatedAt: new Date(),
    }).where(eq(webhookConfigs.id, id)).returning({ id: webhookConfigs.id });
    return rows.length > 0;
  });
}

export function deleteWebhook(db: AppDatabase, ctx: TenantContext, id: string): Promise<boolean> {
  return withTenantContext(db, ctx, async (tx) => {
    const rows = await tx.delete(webhookConfigs).where(eq(webhookConfigs.id, id)).returning({ id: webhookConfigs.id });
    return rows.length > 0;
  });
}

export function listDeliveries(db: AppDatabase, ctx: TenantContext, webhookId: string): Promise<WebhookDelivery[]> {
  return withTenantContext(db, ctx, async (tx) =>
    tx.select().from(webhookDeliveries).where(eq(webhookDeliveries.webhookId, webhookId)).orderBy(desc(webhookDeliveries.createdAt)),
  );
}

export interface EmitDeps {
  masterKey: Buffer;
  timeoutMs?: number;
  maxRetries?: number;
  backoffMs?: number[]; // overrides default [1000, 5000, 30000]
  fetchImpl?: typeof fetch;
}

const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * Deliver `eventType` to every active subscribed webhook. Signs the JSON body
 * with HMAC-SHA256, retries up to maxRetries with backoff, logs every attempt,
 * and dead-letters (status=failed) after the final failure.
 */
export async function emitEvent(
  db: AppDatabase, ctx: TenantContext, eventType: WebhookEvent, payload: unknown, deps: EmitDeps,
): Promise<void> {
  const configs = await withTenantContext(db, ctx, async (tx) =>
    tx.select().from(webhookConfigs).where(and(eq(webhookConfigs.active, true), sql`${eventType} = ANY(${webhookConfigs.events})`)),
  );
  if (configs.length === 0) return;

  const body = JSON.stringify({ event: eventType, data: payload, timestamp: new Date().toISOString() });
  const fetchImpl = deps.fetchImpl ?? fetch;
  const backoff = deps.backoffMs ?? [1000, 5000, 30000];
  const maxRetries = deps.maxRetries ?? 3;
  const tenantKey = deriveTenantKey(deps.masterKey, ctx.orgId);

  for (const cfg of configs) {
    const secret = decryptSecret(cfg.secretEncrypted, tenantKey);
    const signature = signPayload(secret, body);
    let delivered = false;
    for (let attempt = 1; attempt <= maxRetries && !delivered; attempt++) {
      let statusCode: number | null = null;
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), deps.timeoutMs ?? 5000);
        try {
          const res = await fetchImpl(cfg.url, {
            method: 'POST',
            headers: { 'content-type': 'application/json', 'x-capybara-signature': signature, 'x-capybara-event': eventType },
            body, signal: controller.signal,
          });
          statusCode = res.status;
          delivered = res.ok;
        } finally {
          clearTimeout(timer);
        }
      } catch {
        statusCode = null;
      }
      // Log this attempt.
      await withTenantContext(db, ctx, async (tx) => {
        await tx.insert(webhookDeliveries).values({
          orgId: ctx.orgId, webhookId: cfg.id, eventType, attempt,
          status: delivered ? 'delivered' : 'failed',
          statusCode: statusCode ?? null,
          deliveredAt: delivered ? new Date() : null,
        });
      });
      if (!delivered && attempt < maxRetries) await delay(backoff[attempt - 1] ?? 1000);
    }
  }
}
