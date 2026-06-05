import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createServer, type Server, type IncomingMessage } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createHmac } from 'node:crypto';
import { and, eq } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import { loadConfig } from '../../src/config/index.js';
import { buildServer } from '../../src/server.js';
import { registerIntegrationRoutes, registerApiV1Routes } from '../../src/http/routes/integrations.js';
import { apiKeys, auditLog } from '../../src/db/schema/index.js';
import { createWebhook, emitEvent, listDeliveries, signPayload } from '../../src/integrations/webhooks.js';
import type { Role } from '../../src/db/schema/index.js';
import { startTestDb, type TestDb } from '../setup/testDb.js';
import { seedOrgUser, MASTER_KEY, type SeededPrincipal } from '../documents/helpers.js';

let t: TestDb;
let app: FastifyInstance;
let url: string;
let owner: SeededPrincipal;
let receiver: Server;
let receiverUrl: string;
const received: Array<{ path: string; body: string; sig: string | undefined }> = [];

const auth = (p: SeededPrincipal, role: Role = p.role) => ({ 'x-test-org': p.orgId, 'x-test-user': p.userId, 'x-test-role': role });
const j = (p: SeededPrincipal) => ({ ...auth(p), 'content-type': 'application/json' });
const ctx = (p: SeededPrincipal) => ({ orgId: p.orgId, userId: p.userId, clearance: p.clearance });

async function makeKey(scopes: string[], expiresAt?: string): Promise<string> {
  const res = await fetch(`${url}/api/admin/api-keys`, { method: 'POST', headers: j(owner), body: JSON.stringify({ name: 'k', scopes, ...(expiresAt ? { expiresAt } : {}) }) });
  return ((await res.json()) as { key: string }).key;
}
const bearer = (key: string) => ({ authorization: `Bearer ${key}` });

beforeAll(async () => {
  t = await startTestDb();
  owner = await seedOrgUser(t.admin.db, { slug: 'int-org', email: 'int-owner@example.com', role: 'owner' });

  receiver = createServer((req: IncomingMessage, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      received.push({ path: req.url ?? '', body, sig: req.headers['x-capybara-signature'] as string | undefined });
      if ((req.url ?? '').includes('/fail')) { res.writeHead(500); res.end('nope'); }
      else { res.writeHead(200); res.end('ok'); }
    });
  });
  await new Promise<void>((r) => receiver.listen(0, '127.0.0.1', r));
  receiverUrl = `http://127.0.0.1:${(receiver.address() as AddressInfo).port}`;

  const config = loadConfig({ APP_ENV: 'test', CORS_ALLOWED_ORIGINS: 'http://localhost', LOG_LEVEL: 'fatal' });
  app = await buildServer({
    config,
    routes: (instance) => {
      instance.addHook('preHandler', async (req) => {
        const role = req.headers['x-test-role'] as Role | undefined;
        if (role) req.authContext = { userId: String(req.headers['x-test-user'] ?? ''), email: 't@e.com', orgId: String(req.headers['x-test-org'] ?? ''), role, sessionId: 's' };
      });
      registerIntegrationRoutes(instance, { db: t.app.db, masterKey: MASTER_KEY });
      registerApiV1Routes(instance, { db: t.app.db, masterKey: MASTER_KEY }, { max: 3, timeWindow: 60_000 });
    },
  });
  url = await app.listen({ host: '127.0.0.1', port: 0 });
}, 180_000);

afterAll(async () => {
  await app?.close();
  await new Promise<void>((r) => receiver.close(() => r()));
  await t?.stop();
});

describe('integrations — API keys', () => {
  it('returns the key once and stores only a hash', async () => {
    const res = await fetch(`${url}/api/admin/api-keys`, { method: 'POST', headers: j(owner), body: JSON.stringify({ name: 'main', scopes: ['chat:read'] }) });
    expect(res.status).toBe(201);
    const body = (await res.json()) as { id: string; key: string };
    expect(body.key.startsWith('capy_')).toBe(true);
    const row = (await t.admin.db.select().from(apiKeys).where(eq(apiKeys.id, body.id)))[0];
    expect(row?.keyHash).not.toContain(body.key);
    const list = (await (await fetch(`${url}/api/admin/api-keys`, { headers: auth(owner) })).json()) as Array<Record<string, unknown>>;
    expect(JSON.stringify(list)).not.toContain('keyHash');
  });

  it('allows a request with the correct scope and audits it', async () => {
    const key = await makeKey(['chat:read']);
    const res = await fetch(`${url}/api/v1/me`, { headers: bearer(key) });
    expect(res.status).toBe(200);
    const audit = await t.admin.db.select().from(auditLog).where(and(eq(auditLog.orgId, owner.orgId), eq(auditLog.action, 'api.request')));
    expect(audit.length).toBeGreaterThan(0);
  });

  it('returns 403 when the scope is missing', async () => {
    const key = await makeKey(['documents:read']);
    const res = await fetch(`${url}/api/v1/me`, { headers: bearer(key) });
    expect(res.status).toBe(403);
  });

  it('returns 401 for an expired key', async () => {
    const key = await makeKey(['chat:read'], new Date(Date.now() - 1000).toISOString());
    const res = await fetch(`${url}/api/v1/me`, { headers: bearer(key) });
    expect(res.status).toBe(401);
  });

  it('returns 401 for a revoked key', async () => {
    const create = await (await fetch(`${url}/api/admin/api-keys`, { method: 'POST', headers: j(owner), body: JSON.stringify({ name: 'rev', scopes: ['chat:read'] }) })).json() as { id: string; key: string };
    await fetch(`${url}/api/admin/api-keys/${create.id}`, { method: 'DELETE', headers: auth(owner) });
    const res = await fetch(`${url}/api/v1/me`, { headers: bearer(create.key) });
    expect(res.status).toBe(401);
  });

  it('enforces the rate limit per API key', async () => {
    const key = await makeKey(['chat:read']);
    const codes: number[] = [];
    for (let i = 0; i < 4; i++) codes.push((await fetch(`${url}/api/v1/me`, { headers: bearer(key) })).status);
    expect(codes.filter((c) => c === 200).length).toBe(3);
    expect(codes[3]).toBe(429);
  });
});

describe('integrations — webhooks', () => {
  it('fires on document.uploaded with a verifiable HMAC signature', async () => {
    received.length = 0;
    await createWebhook(t.app.db, ctx(owner), { url: `${receiverUrl}/hook`, secret: 'whsecret12345', events: ['document.uploaded'] }, MASTER_KEY);
    await emitEvent(t.app.db, ctx(owner), 'document.uploaded', { documentId: 'doc-1' }, { masterKey: MASTER_KEY, backoffMs: [0, 0, 0] });

    const hit = received.find((r) => r.path === '/hook');
    expect(hit).toBeTruthy();
    // Recipient can verify the signature with the shared secret.
    expect(hit!.sig).toBe(signPayload('whsecret12345', hit!.body));
    expect(createHmac('sha256', 'whsecret12345').update(hit!.body).digest('hex')).toBe(hit!.sig!.slice('sha256='.length));
  });

  it('retries a failing delivery 3 times then dead-letters, logging every attempt', async () => {
    const wh = await createWebhook(t.app.db, ctx(owner), { url: `${receiverUrl}/fail`, secret: 'failsecret123', events: ['chat.completed'] }, MASTER_KEY);
    await emitEvent(t.app.db, ctx(owner), 'chat.completed', { x: 1 }, { masterKey: MASTER_KEY, backoffMs: [0, 0, 0], maxRetries: 3 });

    const deliveries = await listDeliveries(t.app.db, ctx(owner), wh.id);
    expect(deliveries.length).toBe(3); // all attempts logged
    expect(deliveries.every((d) => d.status === 'failed')).toBe(true);
    expect(deliveries.map((d) => d.attempt).sort()).toEqual([1, 2, 3]);
  });
});
