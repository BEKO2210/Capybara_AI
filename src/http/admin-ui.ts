import { fileURLToPath } from 'node:url';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { Eta } from 'eta';
import fastifyStatic from '@fastify/static';
import { z } from 'zod';
import type { AppDatabase } from '../db/client.js';
import { ROLES, type Role } from '../db/schema/index.js';
import { clearanceForRole } from '../rbac/roles.js';
import { requireRole } from '../rbac/guard.js';
import { listUsers, userActivity, inviteUser } from '../admin/users.js';
import { orgStats } from '../admin/stats.js';
import { listInventory } from '../compliance/inventory.js';

export interface AdminUiDeps {
  db: AppDatabase;
}

const viewsDir = fileURLToPath(new URL('../admin/views', import.meta.url));
const staticDir = fileURLToPath(new URL('../admin/static', import.meta.url));
const eta = new Eta({ views: viewsDir, cache: true });

function ctxOf(req: FastifyRequest) {
  const a = req.authContext!;
  return { orgId: a.orgId, userId: a.userId, clearance: clearanceForRole(a.role as Role) };
}

function html(reply: FastifyReply, template: string, data: Record<string, unknown>): FastifyReply {
  return reply.type('text/html; charset=utf-8').send(eta.render(template, data));
}

/**
 * Minimal server-rendered admin console (htmx + eta, no build step, no CDN).
 * All routes require an admin+ session.
 */
export async function registerAdminUi(app: FastifyInstance, deps: AdminUiDeps): Promise<void> {
  // Local htmx + assets (never a CDN).
  await app.register(fastifyStatic, { root: staticDir, prefix: '/admin/static/' });

  const adminOnly = { preHandler: requireRole('admin') };

  app.get('/admin', adminOnly, (_req, reply) => reply.redirect('/admin/dashboard'));

  app.get('/admin/dashboard', adminOnly, async (req, reply) => {
    const stats = await orgStats(deps.db, ctxOf(req));
    return html(reply, 'dashboard', { title: 'Dashboard', stats });
  });

  app.get('/admin/users', adminOnly, async (req, reply) => {
    const users = await listUsers(deps.db, ctxOf(req));
    return html(reply, 'users', { title: 'Benutzer', users, csrf: reply.generateCsrf() });
  });

  app.get<{ Params: { id: string } }>('/admin/users/:id', adminOnly, async (req, reply) => {
    const activity = await userActivity(deps.db, ctxOf(req), req.params.id);
    const body = `<p>Aktivität (30 Tage):</p><ul>
      <li>Abfragen: ${activity.queries}</li><li>Uploads: ${activity.uploads}</li>
      <li>Logins: ${activity.logins}</li><li>Audit-Ereignisse: ${activity.auditEvents}</li></ul>`;
    return html(reply, 'page', { title: 'Benutzerdetails', body });
  });

  app.get('/admin/documents', adminOnly, (_req, reply) =>
    html(reply, 'page', { title: 'Dokumente', body: '<p>Dokumentenverwaltung — siehe <code>/api/documents</code>. Filter nach Klassifizierung über die API.</p>' }),
  );

  app.get('/admin/compliance', adminOnly, async (req, reply) => {
    const inventory = await listInventory(deps.db, ctxOf(req));
    return html(reply, 'compliance', { title: 'Compliance', inventory });
  });

  app.get('/admin/sso', adminOnly, (_req, reply) => {
    const csrf = reply.generateCsrf();
    const body = `<form hx-post="/api/admin/sso/config" hx-ext="json-enc">
      <input type="hidden" name="_csrf" value="${csrf}">
      <label>Issuer</label><input name="issuer" placeholder="https://login.microsoftonline.com/&lt;tenant&gt;/v2.0" required>
      <label>Client ID</label><input name="clientId" required>
      <label>Client Secret</label><input name="clientSecret" type="password" required>
      <label>Redirect URI</label><input name="redirectUri" required>
      <p><button type="submit">Speichern</button></p></form>`;
    return html(reply, 'page', { title: 'SSO-Konfiguration', body });
  });

  app.get('/admin/api-keys', adminOnly, (_req, reply) => {
    const csrf = reply.generateCsrf();
    const body = `<form hx-post="/api/admin/api-keys">
      <input type="hidden" name="_csrf" value="${csrf}">
      <label>Name</label><input name="name" required>
      <p><button type="submit">API-Key erstellen</button></p></form>
      <p><small>Der vollständige Schlüssel wird nur einmal angezeigt.</small></p>`;
    return html(reply, 'page', { title: 'API-Keys', body });
  });

  app.get('/admin/webhooks', adminOnly, (_req, reply) => {
    const csrf = reply.generateCsrf();
    const body = `<form hx-post="/api/admin/webhooks">
      <input type="hidden" name="_csrf" value="${csrf}">
      <label>Ziel-URL</label><input name="url" required>
      <label>Secret (HMAC)</label><input name="secret" type="password" required>
      <p><button type="submit">Webhook anlegen</button></p></form>`;
    return html(reply, 'page', { title: 'Webhooks', body });
  });

  // htmx invite (CSRF-protected, returns a small fragment).
  app.post('/admin/users/invite', { preHandler: [requireRole('admin'), app.csrfProtection] }, async (req, reply) => {
    const body = z.object({ email: z.string().email(), role: z.enum(ROLES) }).safeParse(req.body);
    if (!body.success) return reply.code(400).type('text/html').send('<p>Ungültige Eingabe.</p>');
    await inviteUser(deps.db, ctxOf(req), body.data);
    return reply.type('text/html').send(`<p>Einladung an ${body.data.email} gesendet.</p>`);
  });
}
