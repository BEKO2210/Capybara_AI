import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { readFile } from 'node:fs/promises';
import { eq, and } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import { loadConfig } from '../../src/config/index.js';
import { buildServer } from '../../src/server.js';
import { registerAiEnvelope } from '../../src/http/aiResponseEnvelope.js';
import { registerAdminRoutes } from '../../src/http/routes/admin.js';
import { registerCompletionsRoute } from '../../src/http/routes/completions.js';
import { users, auditLog, meteringEvents, exportJobs } from '../../src/db/schema/index.js';
import { createExportJob, runExportJob, getJob, takeDownloadToken, consumeDownload } from '../../src/admin/export.js';
import type { LlmProvider } from '../../src/ai/providers/provider.interface.js';
import type { Role } from '../../src/db/schema/index.js';
import { startTestDb, type TestDb } from '../setup/testDb.js';
import { seedOrgUser, seedMember, tmpStorageDir, MASTER_KEY, type SeededPrincipal } from '../documents/helpers.js';

const fakeProvider: LlmProvider = {
  id: 'test-llm', model: 'test-llm',
  chat: async () => ({ content: 'Antwort', model: 'test-llm' }),
  async *chatStream() { yield { delta: 'Antwort', done: true }; },
};

let t: TestDb;
let app: FastifyInstance;
let url: string;
let owner: SeededPrincipal;
let admin2: SeededPrincipal;
let orgB: SeededPrincipal;
let exportDeps: { storageDir: string; documentStorageDir: string; masterKey: Buffer };

const auth = (p: SeededPrincipal, role: Role = p.role) => ({ 'x-test-org': p.orgId, 'x-test-user': p.userId, 'x-test-role': role });
const j = (p: SeededPrincipal, role?: Role) => ({ ...auth(p, role), 'content-type': 'application/json' });
const ctx = (p: SeededPrincipal) => ({ orgId: p.orgId, userId: p.userId, clearance: p.clearance });

beforeAll(async () => {
  t = await startTestDb();
  owner = await seedOrgUser(t.admin.db, { slug: 'ad-org', email: 'ad-owner@example.com', role: 'owner' });
  admin2 = await seedMember(t.admin.db, owner.orgId, { email: 'ad-admin@example.com', role: 'admin' });
  orgB = await seedOrgUser(t.admin.db, { slug: 'ad-org-b', email: 'ad-b@example.com', role: 'owner' });
  exportDeps = { storageDir: await tmpStorageDir(), documentStorageDir: await tmpStorageDir(), masterKey: MASTER_KEY };

  const config = loadConfig({ APP_ENV: 'test', CORS_ALLOWED_ORIGINS: 'http://localhost', LOG_LEVEL: 'fatal' });
  app = await buildServer({
    config,
    routes: (instance) => {
      instance.addHook('preHandler', async (req) => {
        const role = req.headers['x-test-role'] as Role | undefined;
        if (role) req.authContext = { userId: String(req.headers['x-test-user'] ?? ''), email: 't@e.com', orgId: String(req.headers['x-test-org'] ?? ''), role, sessionId: 's' };
      });
      registerAiEnvelope(instance, { db: t.app.db });
      registerAdminRoutes(instance, { db: t.app.db, export: exportDeps });
      registerCompletionsRoute(instance, { db: t.app.db, resolveProvider: (id) => { if (id === 'test-llm') return fakeProvider; throw new Error('x'); }, providerId: 'test-llm' });
    },
  });
  url = await app.listen({ host: '127.0.0.1', port: 0 });
}, 180_000);

afterAll(async () => { await app?.close(); await t?.stop(); });

describe('admin — user management', () => {
  it('lists only the org members', async () => {
    const rows = (await (await fetch(`${url}/api/admin/users`, { headers: auth(owner) })).json()) as Array<{ email: string }>;
    expect(rows.some((r) => r.email === 'ad-owner@example.com')).toBe(true);
    expect(rows.some((r) => r.email === 'ad-b@example.com')).toBe(false);
  });

  it('invites a user (pending) and writes an audit entry', async () => {
    const res = await fetch(`${url}/api/admin/users/invite`, { method: 'POST', headers: j(owner), body: JSON.stringify({ email: 'newbie@example.com', role: 'member' }) });
    expect(res.status).toBe(201);
    const body = (await res.json()) as { userId: string; inviteToken: string };
    expect(body.inviteToken).toBeTruthy();
    const u = await t.admin.db.select().from(users).where(eq(users.id, body.userId));
    expect(u[0]?.status).toBe('invited');
    const audit = await t.admin.db.select().from(auditLog).where(and(eq(auditLog.action, 'user.invited'), eq(auditLog.targetId, body.userId)));
    expect(audit.length).toBe(1);
  });

  it('blocks a non-owner from demoting an owner (403)', async () => {
    const res = await fetch(`${url}/api/admin/users/${owner.userId}/role`, { method: 'PUT', headers: j(owner, 'admin'), body: JSON.stringify({ role: 'member' }) });
    expect(res.status).toBe(403);
  });

  it('refuses to deactivate your own account (400)', async () => {
    const res = await fetch(`${url}/api/admin/users/${owner.userId}/deactivate`, { method: 'POST', headers: auth(owner) });
    expect(res.status).toBe(400);
  });

  it('unlocks a brute-force-locked member and audits it', async () => {
    // Lock the admin member by recording failures against their email.
    const { recordFailure } = await import('../../src/auth/abuseGuard.js');
    const policy = { maxFailures: 1, windowMs: 60_000, lockBaseMs: 10_000, lockMaxMs: 100_000 };
    await recordFailure(t.app.db, 'ad-admin@example.com', policy);

    const res = await fetch(`${url}/api/admin/users/${admin2.userId}/unlock`, { method: 'POST', headers: auth(owner) });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { cleared: boolean; email: string };
    expect(body.cleared).toBe(true);
    const audit = await t.admin.db.select().from(auditLog).where(and(eq(auditLog.action, 'user.unlocked'), eq(auditLog.targetId, admin2.userId)));
    expect(audit.length).toBe(1);
  });

  it('refuses to unlock a non-member (404)', async () => {
    const res = await fetch(`${url}/api/admin/users/${orgB.userId}/unlock`, { method: 'POST', headers: auth(owner) });
    expect(res.status).toBe(404);
  });
});

describe('admin — stats', () => {
  it('returns only this org\'s data', async () => {
    const a = (await (await fetch(`${url}/api/admin/stats`, { headers: auth(owner) })).json()) as { users: { total: number } };
    const b = (await (await fetch(`${url}/api/admin/stats`, { headers: auth(orgB) })).json()) as { users: { total: number } };
    expect(a.users.total).toBeGreaterThanOrEqual(2); // owner + admin + invited
    expect(b.users.total).toBe(1); // org B only
  });
});

describe('admin — metering', () => {
  it('writes a metering event on every LLM call', async () => {
    await fetch(`${url}/api/chat/completions`, { method: 'POST', headers: j(owner), body: JSON.stringify({ message: 'Hallo Welt' }) });
    const rows = await t.admin.db.select().from(meteringEvents).where(and(eq(meteringEvents.orgId, owner.orgId), eq(meteringEvents.eventType, 'LLM_CALL')));
    expect(rows.length).toBeGreaterThan(0);
    expect(rows[0]?.provider).toBe('test-llm');
  });

  it('metering events are INSERT-only for the app role', async () => {
    const privs = await t.app.sql<{ privilege_type: string }[]>`
      SELECT privilege_type FROM information_schema.role_table_grants
      WHERE table_name = 'metering_events' AND grantee = 'capybara_app'`;
    const set = new Set(privs.map((p) => p.privilege_type));
    expect(set.has('INSERT')).toBe(true);
    expect(set.has('UPDATE')).toBe(false);
    expect(set.has('DELETE')).toBe(false);
  });
});

describe('admin — GDPR data export', () => {
  it('creates an encrypted ZIP and serves it via a 1-hour token', async () => {
    const { jobId } = await createExportJob(t.app.db, ctx(owner));
    await runExportJob(t.app.db, ctx(owner), jobId, exportDeps);
    const job = await getJob(t.app.db, ctx(owner), jobId);
    expect(job?.status).toBe('DONE');
    expect(job?.filePath).toBeTruthy();

    // The artifact at rest is encrypted (not a raw ZIP).
    const atRest = await readFile(job!.filePath!, 'utf8');
    expect(atRest.startsWith('PK')).toBe(false);

    const token = takeDownloadToken(jobId)!;
    expect(token).toBeTruthy();

    // Expired token → no download.
    await t.admin.db.update(exportJobs).set({ expiresAt: new Date(Date.now() - 1000) }).where(eq(exportJobs.id, jobId));
    expect(await consumeDownload(t.app.db, ctx(owner), jobId, token, exportDeps)).toBeNull();

    // Within the hour → a valid ZIP (starts with PK), then deleted.
    await t.admin.db.update(exportJobs).set({ expiresAt: new Date(Date.now() + 3600_000) }).where(eq(exportJobs.id, jobId));
    const zip = await consumeDownload(t.app.db, ctx(owner), jobId, token, exportDeps);
    expect(zip).not.toBeNull();
    expect(zip!.subarray(0, 2).toString()).toBe('PK');
  });
});
