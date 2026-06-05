import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import type { AppDatabase } from '../../db/client.js';
import { API_KEY_SCOPES, type Role } from '../../db/schema/index.js';
import { clearanceForRole } from '../../rbac/roles.js';
import { requireRole } from '../../rbac/guard.js';
import { createApiKey, listApiKeys, revokeApiKey } from '../../integrations/apiKeys.js';
import { createWebhook, listWebhooks, updateWebhook, deleteWebhook, listDeliveries, WEBHOOK_EVENTS } from '../../integrations/webhooks.js';
import { apiKeyAuth, requireScope } from '../apiKeyAuth.js';

export interface IntegrationRoutesDeps {
  db: AppDatabase;
  masterKey: Buffer;
}

function ctxOf(req: FastifyRequest) {
  const a = req.authContext!;
  return { orgId: a.orgId, userId: a.userId, clearance: clearanceForRole(a.role as Role) };
}

export function registerIntegrationRoutes(app: FastifyInstance, deps: IntegrationRoutesDeps): void {
  const adminOnly = { preHandler: requireRole('admin') };

  // ── API keys ──
  app.get('/api/admin/api-keys', adminOnly, (req) => listApiKeys(deps.db, ctxOf(req)));

  app.post('/api/admin/api-keys', adminOnly, async (req, reply) => {
    const body = z.object({
      name: z.string().min(1),
      scopes: z.array(z.enum(API_KEY_SCOPES)).min(1),
      expiresAt: z.string().datetime().optional(),
    }).safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: 'invalid request' });
    const created = await createApiKey(deps.db, ctxOf(req), {
      name: body.data.name, scopes: body.data.scopes,
      ...(body.data.expiresAt ? { expiresAt: new Date(body.data.expiresAt) } : {}),
    });
    return reply.code(201).send(created); // full key returned ONCE
  });

  app.delete<{ Params: { id: string } }>('/api/admin/api-keys/:id', adminOnly, async (req, reply) => {
    const ok = await revokeApiKey(deps.db, ctxOf(req), req.params.id);
    if (!ok) return reply.code(404).send({ error: 'not found' });
    return { revoked: true };
  });

  // ── Webhooks ──
  app.get('/api/admin/webhooks', adminOnly, (req) => listWebhooks(deps.db, ctxOf(req)));

  app.post('/api/admin/webhooks', adminOnly, async (req, reply) => {
    const body = z.object({
      url: z.string().url(),
      secret: z.string().min(8),
      events: z.array(z.enum(WEBHOOK_EVENTS)).min(1),
    }).safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: 'invalid request' });
    const wh = await createWebhook(deps.db, ctxOf(req), body.data, deps.masterKey);
    const { secretEncrypted, ...rest } = wh;
    return reply.code(201).send(rest);
  });

  app.put<{ Params: { id: string } }>('/api/admin/webhooks/:id', adminOnly, async (req, reply) => {
    const body = z.object({ url: z.string().url().optional(), events: z.array(z.enum(WEBHOOK_EVENTS)).optional(), active: z.boolean().optional() }).safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: 'invalid request' });
    const ok = await updateWebhook(deps.db, ctxOf(req), req.params.id, body.data as { url?: string; events?: string[]; active?: boolean });
    if (!ok) return reply.code(404).send({ error: 'not found' });
    return { updated: true };
  });

  app.delete<{ Params: { id: string } }>('/api/admin/webhooks/:id', adminOnly, async (req, reply) => {
    const ok = await deleteWebhook(deps.db, ctxOf(req), req.params.id);
    if (!ok) return reply.code(404).send({ error: 'not found' });
    return { deleted: true };
  });

  app.get<{ Params: { id: string } }>('/api/admin/webhooks/:id/deliveries', adminOnly, (req) =>
    listDeliveries(deps.db, ctxOf(req), req.params.id),
  );
}

/**
 * Example external REST surface authenticated by API key (Bearer capy_<key>).
 * Demonstrates scope enforcement + per-key rate limiting.
 */
export function registerApiV1Routes(app: FastifyInstance, deps: IntegrationRoutesDeps, rateLimit?: { max: number; timeWindow: number }): void {
  app.get('/api/v1/me', {
    preHandler: [apiKeyAuth(deps.db), requireScope('chat:read')],
    ...(rateLimit ? { config: { rateLimit } } : {}),
  }, async (req) => ({ orgId: req.apiKey!.orgId, scopes: req.apiKey!.scopes }));
}
