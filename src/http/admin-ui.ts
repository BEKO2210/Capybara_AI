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
import { listOversight, approveRequest, rejectRequest } from '../compliance/oversight.js';

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
    const a = await userActivity(deps.db, ctxOf(req), req.params.id);
    const metric = (label: string, value: number) =>
      `<div class="card stat"><div class="card-title">${label}</div><div class="value">${value}</div></div>`;
    const body = `<div class="card-title">Aktivität (letzte 30 Tage)</div>
      <div class="grid stats">
        ${metric('Abfragen', a.queries)}${metric('Uploads', a.uploads)}
        ${metric('Logins', a.logins)}${metric('Audit-Ereignisse', a.auditEvents)}
      </div>
      <p class="mt-16"><a class="btn ghost sm" href="/admin/users">← Zurück zu Benutzern</a></p>`;
    return html(reply, 'page', { title: 'Benutzerdetails', active: 'users', body });
  });

  app.get('/admin/documents', adminOnly, (_req, reply) =>
    html(reply, 'page', {
      title: 'Dokumente',
      active: 'documents',
      body: `<div class="card-title">Dokumentenverwaltung</div>
        <p>Verschlüsselte Dokumente werden über die API verwaltet. Upload, Versionierung,
        Legal Hold und klassifizierungsbasierte Zugriffe laufen über
        <code>/api/documents</code>.</p>
        <p class="mt-12"><span class="pill ok">AES-256-GCM</span> <span class="pill">RLS-isoliert</span> <span class="pill">ClamAV optional</span></p>`,
    }),
  );

  app.get('/admin/compliance', adminOnly, async (req, reply) => {
    const inventory = await listInventory(deps.db, ctxOf(req));
    return html(reply, 'compliance', { title: 'Compliance', active: 'compliance', inventory });
  });

  // ── Human-oversight approvals (EU AI Act Art. 14) ──
  app.get('/admin/oversight', adminOnly, async (req, reply) => {
    const requests = await listOversight(deps.db, ctxOf(req), { pendingOnly: true });
    return html(reply, 'oversight', { title: 'Aufsicht', active: 'oversight', requests, csrf: reply.generateCsrf() });
  });

  const decide = (action: 'approve' | 'reject') =>
    async (req: FastifyRequest<{ Params: { id: string } }>, reply: FastifyReply) => {
      const ctx = ctxOf(req);
      const fn = action === 'approve' ? approveRequest : rejectRequest;
      const ok = await fn(deps.db, ctx, req.params.id, ctx.userId);
      if (!ok) return reply.code(409).type('text/html').send('<tr><td colspan="5">Bereits entschieden.</td></tr>');
      // Row removed from the pending list on success (htmx outerHTML swap).
      return reply.type('text/html').send('');
    };

  app.post<{ Params: { id: string } }>('/admin/oversight/:id/approve', { preHandler: [requireRole('admin'), app.csrfProtection] }, decide('approve'));
  app.post<{ Params: { id: string } }>('/admin/oversight/:id/reject', { preHandler: [requireRole('admin'), app.csrfProtection] }, decide('reject'));

  app.get('/admin/sso', adminOnly, (_req, reply) => {
    const csrf = reply.generateCsrf();
    const body = `<div class="card-title">SSO-Konfiguration (OIDC)</div>
      <form hx-post="/api/admin/sso/config" hx-ext="json-enc" hx-swap="none"
            data-toast-success="SSO gespeichert." data-toast-error="Speichern fehlgeschlagen.">
      <input type="hidden" name="_csrf" value="${csrf}">
      <label>Issuer</label><input name="issuer" placeholder="https://login.microsoftonline.com/&lt;tenant&gt;/v2.0" required>
      <label>Client ID</label><input name="clientId" required>
      <label>Client Secret</label><input name="clientSecret" type="password" required>
      <label>Redirect URI</label><input name="redirectUri" placeholder="https://app.example.com/auth/oidc/callback" required>
      <p class="mt-14"><button type="submit"><span class="htmx-indicator spinner"></span> Speichern</button></p></form>`;
    return html(reply, 'page', { title: 'SSO-Konfiguration', active: 'sso', body });
  });

  app.get('/admin/api-keys', adminOnly, (_req, reply) => {
    const csrf = reply.generateCsrf();
    const body = `<div class="card-title">API-Keys</div>
      <form hx-post="/api/admin/api-keys" hx-swap="none"
            data-toast-success="API-Key erstellt — Schlüssel wird einmalig angezeigt." data-toast-error="Erstellen fehlgeschlagen.">
      <input type="hidden" name="_csrf" value="${csrf}">
      <label>Name</label><input name="name" placeholder="z. B. CI-Pipeline" required>
      <p class="mt-14"><button type="submit"><span class="htmx-indicator spinner"></span> API-Key erstellen</button></p></form>
      <p class="muted mt-8">Der vollständige Schlüssel wird aus Sicherheitsgründen nur einmal angezeigt.</p>`;
    return html(reply, 'page', { title: 'API-Keys', active: 'api-keys', body });
  });

  app.get('/admin/webhooks', adminOnly, (_req, reply) => {
    const csrf = reply.generateCsrf();
    const body = `<div class="card-title">Webhooks</div>
      <form hx-post="/api/admin/webhooks" hx-swap="none"
            data-toast-success="Webhook angelegt." data-toast-error="Anlegen fehlgeschlagen.">
      <input type="hidden" name="_csrf" value="${csrf}">
      <label>Ziel-URL</label><input name="url" placeholder="https://hooks.example.com/capybara" required>
      <label>Secret (HMAC-Signierung)</label><input name="secret" type="password" required>
      <p class="mt-14"><button type="submit"><span class="htmx-indicator spinner"></span> Webhook anlegen</button></p></form>`;
    return html(reply, 'page', { title: 'Webhooks', active: 'webhooks', body });
  });

  // htmx invite (CSRF-protected, returns a small fragment).
  app.post('/admin/users/invite', { preHandler: [requireRole('admin'), app.csrfProtection] }, async (req, reply) => {
    const body = z.object({ email: z.string().email(), role: z.enum(ROLES) }).safeParse(req.body);
    if (!body.success) return reply.code(400).type('text/html').send('<p>Ungültige Eingabe.</p>');
    await inviteUser(deps.db, ctxOf(req), body.data);
    return reply.type('text/html').send(`<p>Einladung an ${body.data.email} gesendet.</p>`);
  });
}
