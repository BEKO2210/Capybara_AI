import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { FastifyInstance } from 'fastify';
import { eq } from 'drizzle-orm';
import { loadConfig } from '../../src/config/index.js';
import { buildServer } from '../../src/server.js';
import { registerSsoRoutes } from '../../src/http/routes/sso.js';
import { oidcConfigs, users, memberships } from '../../src/db/schema/index.js';
import { lookupOrgByDomain, autoProvisionUser } from '../../src/admin/sso.js';
import type { Role } from '../../src/db/schema/index.js';
import { startTestDb, type TestDb } from '../setup/testDb.js';
import { seedOrgUser, MASTER_KEY, type SeededPrincipal } from '../documents/helpers.js';

let t: TestDb;
let app: FastifyInstance;
let url: string;
let idp: Server;
let issuer: string;
let orgA: SeededPrincipal;
let orgB: SeededPrincipal;

const auth = (p: SeededPrincipal, role: Role = p.role) => ({ 'x-test-org': p.orgId, 'x-test-user': p.userId, 'x-test-role': role });
const j = (p: SeededPrincipal, role?: Role) => ({ ...auth(p, role), 'content-type': 'application/json' });

beforeAll(async () => {
  t = await startTestDb();
  orgA = await seedOrgUser(t.admin.db, { slug: 'sso-a', email: 'sso-a@example.com', role: 'owner' });
  orgB = await seedOrgUser(t.admin.db, { slug: 'sso-b', email: 'sso-b@example.com', role: 'owner' });

  idp = createServer((req, res) => {
    if ((req.url ?? '').startsWith('/.well-known/openid-configuration')) {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({
        issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`,
        jwks_uri: `${issuer}/jwks`, response_types_supported: ['code'], subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
      }));
      return;
    }
    if ((req.url ?? '').startsWith('/jwks')) { res.writeHead(200, { 'content-type': 'application/json' }); res.end('{"keys":[]}'); return; }
    res.writeHead(404); res.end();
  });
  await new Promise<void>((r) => idp.listen(0, '127.0.0.1', r));
  issuer = `http://127.0.0.1:${(idp.address() as AddressInfo).port}`;

  const config = loadConfig({ APP_ENV: 'test', CORS_ALLOWED_ORIGINS: 'http://localhost', LOG_LEVEL: 'fatal' });
  app = await buildServer({
    config,
    routes: (instance) => {
      instance.addHook('preHandler', async (req) => {
        const role = req.headers['x-test-role'] as Role | undefined;
        if (role) req.authContext = { userId: String(req.headers['x-test-user'] ?? ''), email: 't@e.com', orgId: String(req.headers['x-test-org'] ?? ''), role, sessionId: 's' };
      });
      registerSsoRoutes(instance, { db: t.app.db, masterKey: MASTER_KEY });
    },
  });
  url = await app.listen({ host: '127.0.0.1', port: 0 });
}, 180_000);

afterAll(async () => {
  await app?.close();
  await new Promise<void>((r) => idp.close(() => r()));
  await t?.stop();
});

function configBody(extra: Record<string, unknown> = {}) {
  return JSON.stringify({ issuer, clientId: 'client-a', clientSecret: 'super-secret-value', redirectUri: 'https://app.example/cb', domainHint: 'acme.com', ...extra });
}

describe('sso — config management', () => {
  it('stores the client secret encrypted (never plaintext), GET hides it', async () => {
    const res = await fetch(`${url}/api/admin/sso/config`, { method: 'POST', headers: j(orgA), body: configBody() });
    expect(res.status).toBe(200);
    const row = (await t.admin.db.select().from(oidcConfigs).where(eq(oidcConfigs.orgId, orgA.orgId)))[0];
    expect(row?.clientSecretEncrypted).toBeTruthy();
    expect(row?.clientSecretEncrypted).not.toContain('super-secret-value');

    const got = (await (await fetch(`${url}/api/admin/sso/config`, { headers: auth(orgA) })).json()) as Record<string, unknown>;
    expect(JSON.stringify(got)).not.toContain('super-secret-value');
    expect(JSON.stringify(got)).not.toContain('clientSecretEncrypted');
  });

  it('is not accessible across tenants', async () => {
    const res = await fetch(`${url}/api/admin/sso/config`, { headers: auth(orgB) });
    expect(res.status).toBe(404); // org B has no config and cannot see org A's
  });

  it('validates issuer discovery via the test endpoint', async () => {
    const res = await fetch(`${url}/api/admin/sso/config/test`, {
      method: 'POST', headers: j(orgA),
      body: JSON.stringify({ issuer, clientId: 'client-a', clientSecret: 'x', allowInsecure: true }),
    });
    const body = (await res.json()) as { ok: boolean; issuer: string; endpoints: { token_endpoint?: string } };
    expect(body.ok).toBe(true);
    expect(body.issuer).toBe(issuer);
    expect(body.endpoints.token_endpoint).toBe(`${issuer}/token`);
  });
});

describe('sso — domain routing, provisioning, disabled', () => {
  it('looks up the correct org by domain hint', async () => {
    const routing = await lookupOrgByDomain(t.app.db, 'acme.com');
    expect(routing?.orgId).toBe(orgA.orgId);
  });

  it('auto-provisions a new user with the default role', async () => {
    const routing = (await lookupOrgByDomain(t.app.db, 'acme.com'))!;
    const r1 = await autoProvisionUser(t.app.db, routing, { email: 'newhire@acme.com', subject: 'sub-1' });
    expect(r1.created).toBe(true);
    const u = (await t.admin.db.select().from(users).where(eq(users.id, r1.userId)))[0];
    expect(u?.status).toBe('active');
    const m = (await t.admin.db.select().from(memberships).where(eq(memberships.userId, r1.userId)))[0];
    expect(m?.role).toBe('member');
    // Idempotent.
    const r2 = await autoProvisionUser(t.app.db, routing, { email: 'newhire@acme.com', subject: 'sub-1' });
    expect(r2.created).toBe(false);
  });

  it('blocks SSO login when the config is disabled', async () => {
    await fetch(`${url}/api/admin/sso/config`, { method: 'POST', headers: j(orgA), body: configBody({ active: false }) });
    const res = await fetch(`${url}/api/auth/sso/login?domain=acme.com`, { redirect: 'manual' });
    expect(res.status).toBe(403);
  });
});
