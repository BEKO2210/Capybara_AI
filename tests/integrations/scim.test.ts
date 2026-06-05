import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { eq, isNull, and } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import { loadConfig } from '../../src/config/index.js';
import { buildServer } from '../../src/server.js';
import { registerScimRoutes } from '../../src/http/routes/scim.js';
import { users, memberships, sessions } from '../../src/db/schema/index.js';
import type { Role } from '../../src/db/schema/index.js';
import { startTestDb, type TestDb } from '../setup/testDb.js';
import { seedOrgUser, type SeededPrincipal } from '../documents/helpers.js';

let t: TestDb;
let app: FastifyInstance;
let url: string;
let orgA: SeededPrincipal;
let orgB: SeededPrincipal;
let tokenA: string;
let tokenB: string;

const auth = (p: SeededPrincipal, role: Role = p.role) => ({ 'x-test-org': p.orgId, 'x-test-user': p.userId, 'x-test-role': role });
const scim = (token: string) => ({ authorization: `Bearer ${token}`, 'content-type': 'application/json' });

beforeAll(async () => {
  t = await startTestDb();
  orgA = await seedOrgUser(t.admin.db, { slug: 'scim-a', email: 'scim-a@example.com', role: 'owner' });
  orgB = await seedOrgUser(t.admin.db, { slug: 'scim-b', email: 'scim-b@example.com', role: 'owner' });

  const config = loadConfig({ APP_ENV: 'test', CORS_ALLOWED_ORIGINS: 'http://localhost', LOG_LEVEL: 'fatal' });
  app = await buildServer({
    config,
    routes: (instance) => {
      instance.addHook('preHandler', async (req) => {
        const role = req.headers['x-test-role'] as Role | undefined;
        if (role) req.authContext = { userId: String(req.headers['x-test-user'] ?? ''), email: 't@e.com', orgId: String(req.headers['x-test-org'] ?? ''), role, sessionId: 's' };
      });
      registerScimRoutes(instance, { db: t.app.db });
    },
  });
  url = await app.listen({ host: '127.0.0.1', port: 0 });

  tokenA = ((await (await fetch(`${url}/api/admin/scim/token`, { method: 'POST', headers: auth(orgA) })).json()) as { token: string }).token;
  tokenB = ((await (await fetch(`${url}/api/admin/scim/token`, { method: 'POST', headers: auth(orgB) })).json()) as { token: string }).token;
}, 180_000);

afterAll(async () => { await app?.close(); await t?.stop(); });

async function createScimUser(token: string, userName: string): Promise<string> {
  const res = await fetch(`${url}/scim/v2/Users`, { method: 'POST', headers: scim(token), body: JSON.stringify({ schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'], userName, active: true }) });
  return ((await res.json()) as { id: string }).id;
}

describe('scim — provisioning', () => {
  it('creates a user that appears in the org', async () => {
    const id = await createScimUser(tokenA, 'alice@scim-a.com');
    const list = (await (await fetch(`${url}/scim/v2/Users?filter=userName eq "alice@scim-a.com"`, { headers: scim(tokenA) })).json()) as { Resources: Array<{ id: string }> };
    expect(list.Resources.some((r) => r.id === id)).toBe(true);
    const m = (await t.admin.db.select().from(memberships).where(eq(memberships.userId, id)))[0];
    expect(m?.orgId).toBe(orgA.orgId);
  });

  it('PATCH active=false deactivates the user and revokes sessions', async () => {
    const id = await createScimUser(tokenA, 'bob@scim-a.com');
    await t.admin.db.insert(sessions).values({ userId: id, tokenHash: 'h-' + id, expiresAt: new Date(Date.now() + 3600_000) });
    const res = await fetch(`${url}/scim/v2/Users/${id}`, { method: 'PATCH', headers: scim(tokenA), body: JSON.stringify({ schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'], Operations: [{ op: 'replace', path: 'active', value: false }] }) });
    expect(res.status).toBe(200);
    expect((await t.admin.db.select().from(users).where(eq(users.id, id)))[0]?.status).toBe('inactive');
    const live = await t.admin.db.select().from(sessions).where(and(eq(sessions.userId, id), isNull(sessions.revokedAt)));
    expect(live).toHaveLength(0);
  });

  it('DELETE soft-deactivates (does not hard-delete)', async () => {
    const id = await createScimUser(tokenA, 'carol@scim-a.com');
    const res = await fetch(`${url}/scim/v2/Users/${id}`, { method: 'DELETE', headers: { authorization: `Bearer ${tokenA}` } });
    expect(res.status).toBe(204);
    const row = (await t.admin.db.select().from(users).where(eq(users.id, id)))[0];
    expect(row).toBeTruthy(); // still present
    expect(row?.status).toBe('inactive');
  });

  it('Group PATCH adds a member with the correct role', async () => {
    const id = await createScimUser(tokenA, 'dave@scim-a.com');
    const res = await fetch(`${url}/scim/v2/Groups/admin`, { method: 'PATCH', headers: scim(tokenA), body: JSON.stringify({ Operations: [{ op: 'add', path: 'members', value: [{ value: id }] }] }) });
    expect(res.status).toBe(200);
    expect((await t.admin.db.select().from(memberships).where(eq(memberships.userId, id)))[0]?.role).toBe('admin');
  });
});

describe('scim — auth & isolation', () => {
  it('rejects a wrong bearer token (401)', async () => {
    const res = await fetch(`${url}/scim/v2/Users`, { headers: scim('scim_totally-wrong-token') });
    expect(res.status).toBe(401);
  });

  it('isolates tenants by token (org B cannot see org A users)', async () => {
    const list = (await (await fetch(`${url}/scim/v2/Users`, { headers: scim(tokenB) })).json()) as { Resources: Array<{ userName: string }> };
    expect(list.Resources.every((r) => !r.userName.endsWith('@scim-a.com'))).toBe(true);
  });

  it('returns a valid ServiceProviderConfig', async () => {
    const res = await fetch(`${url}/scim/v2/ServiceProviderConfig`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { schemas: string[]; patch: { supported: boolean }; filter: { supported: boolean } };
    expect(body.schemas).toContain('urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig');
    expect(body.patch.supported).toBe(true);
    expect(body.filter.supported).toBe(true);
  });
});
