import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { loadConfig } from '../../src/config/index.js';
import { buildServer } from '../../src/server.js';
import { registerAdminUi } from '../../src/http/admin-ui.js';
import type { Role } from '../../src/db/schema/index.js';
import { startTestDb, type TestDb } from '../setup/testDb.js';
import { seedOrgUser, type SeededPrincipal } from '../documents/helpers.js';

let t: TestDb;
let app: FastifyInstance;
let url: string;
let owner: SeededPrincipal;

const auth = (p: SeededPrincipal, role: Role = p.role) => ({ 'x-test-org': p.orgId, 'x-test-user': p.userId, 'x-test-role': role });

beforeAll(async () => {
  t = await startTestDb();
  owner = await seedOrgUser(t.admin.db, { slug: 'ui-org', email: 'ui-owner@example.com', role: 'owner' });

  const config = loadConfig({ APP_ENV: 'test', CORS_ALLOWED_ORIGINS: 'http://localhost', LOG_LEVEL: 'fatal' });
  app = await buildServer({
    config,
    routes: async (instance) => {
      instance.addHook('preHandler', async (req) => {
        const role = req.headers['x-test-role'] as Role | undefined;
        if (role) req.authContext = { userId: String(req.headers['x-test-user'] ?? ''), email: 't@e.com', orgId: String(req.headers['x-test-org'] ?? ''), role, sessionId: 's' };
      });
      await registerAdminUi(instance, { db: t.app.db });
    },
  });
  url = await app.listen({ host: '127.0.0.1', port: 0 });
}, 180_000);

afterAll(async () => { await app?.close(); await t?.stop(); });

describe('admin UI', () => {
  it('serves the dashboard to an admin (200)', async () => {
    const res = await fetch(`${url}/admin/dashboard`, { headers: auth(owner, 'admin') });
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('text/html');
    const body = await res.text();
    expect(body).toContain('Dashboard');
    expect(body).toContain('Capybara_AI');
  });

  it('forbids a member (403)', async () => {
    const res = await fetch(`${url}/admin/dashboard`, { headers: auth(owner, 'member') });
    expect(res.status).toBe(403);
  });

  it('includes a CSRF token in forms', async () => {
    const body = await (await fetch(`${url}/admin/users`, { headers: auth(owner, 'admin') })).text();
    expect(body).toContain('<form');
    expect(body).toContain('name="_csrf"');
  });

  it('references no external CDN (htmx is served locally)', async () => {
    const pages = ['/admin/dashboard', '/admin/users', '/admin/compliance', '/admin/sso', '/admin/api-keys', '/admin/webhooks'];
    for (const p of pages) {
      const body = await (await fetch(`${url}${p}`, { headers: auth(owner, 'admin') })).text();
      expect(body, `${p} CDN`).not.toMatch(/cdn\.|unpkg\.com|jsdelivr|cdnjs/i);
      expect(body, `${p} htmx`).toContain('/admin/static/htmx.min.js');
    }
  });

  it('serves the vendored htmx asset locally (no CDN)', async () => {
    const res = await fetch(`${url}/admin/static/htmx.min.js`, { headers: auth(owner, 'admin') });
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toMatch(/javascript/);
  });

  it('serves the local stylesheet and script (no CDN), with theme toggle + toasts', async () => {
    const css = await fetch(`${url}/admin/static/app.css`, { headers: auth(owner, 'admin') });
    expect(css.status).toBe(200);
    expect(css.headers.get('content-type')).toMatch(/css/);
    const js = await fetch(`${url}/admin/static/app.js`, { headers: auth(owner, 'admin') });
    expect(js.status).toBe(200);
    expect(js.headers.get('content-type')).toMatch(/javascript/);

    const body = await (await fetch(`${url}/admin/dashboard`, { headers: auth(owner, 'admin') })).text();
    expect(body).toContain('/admin/static/app.css');
    expect(body).toContain('/admin/static/app.js');
    expect(body).toContain('data-action="theme"'); // dark/light toggle
    expect(body).toContain('id="toasts"'); // toast container
    expect(body).toContain('class="sidebar"'); // sidebar nav
  });

  it('renders the human-oversight approval queue and protects decisions with CSRF', async () => {
    const { oversightRequests } = await import('../../src/db/schema/index.js');
    const [req] = await t.admin.db.insert(oversightRequests).values({
      orgId: owner.orgId, requestedBy: owner.userId, toolName: 'delete_database',
      toolArgsHash: 'h', toolArgsEncrypted: 'x', riskLevel: 'CRITICAL', status: 'PENDING',
      expiresAt: new Date(Date.now() + 3_600_000),
    }).returning({ id: oversightRequests.id });

    const page = await (await fetch(`${url}/admin/oversight`, { headers: auth(owner, 'admin') })).text();
    expect(page).toContain('delete_database');
    expect(page).toContain('/admin/oversight/' + req!.id + '/approve');

    // A decision without a CSRF token is rejected (protection wired).
    const res = await fetch(`${url}/admin/oversight/${req!.id}/approve`, { method: 'POST', headers: auth(owner, 'admin') });
    expect(res.status).toBe(403);
  });

  it('emits NO inline style attributes (keeps the strict CSP intact)', async () => {
    const pages = ['/admin/dashboard', '/admin/users', '/admin/compliance', '/admin/oversight', '/admin/sso', '/admin/api-keys', '/admin/webhooks', '/admin/documents'];
    for (const p of pages) {
      const body = await (await fetch(`${url}${p}`, { headers: auth(owner, 'admin') })).text();
      expect(body, `${p} has inline style=`).not.toMatch(/\sstyle=/);
      // No <style> blocks either — all CSS is in the external stylesheet.
      expect(body, `${p} has <style>`).not.toMatch(/<style/i);
    }
  });
});
