import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import type { AppDatabase } from '../../db/client.js';
import { ROLES, type Role } from '../../db/schema/index.js';
import { clearanceForRole } from '../../rbac/roles.js';
import { requirePermission, requireRole } from '../../rbac/guard.js';
import { listUsers, inviteUser, changeRole, deactivateUser, userActivity, AdminError } from '../../admin/users.js';
import { orgStats } from '../../admin/stats.js';
import { createExportJob, runExportJob, getJob, takeDownloadToken, consumeDownload, type ExportDeps } from '../../admin/export.js';

export interface AdminRoutesDeps {
  db: AppDatabase;
  export: ExportDeps;
}

function ctxOf(req: FastifyRequest) {
  const a = req.authContext!;
  return { orgId: a.orgId, userId: a.userId, clearance: clearanceForRole(a.role as Role), role: a.role as Role };
}

export function registerAdminRoutes(app: FastifyInstance, deps: AdminRoutesDeps): void {
  const adminOnly = { preHandler: requireRole('admin') };

  app.get('/api/admin/users', adminOnly, (req) => listUsers(deps.db, ctxOf(req)));

  app.post('/api/admin/users/invite', adminOnly, async (req, reply) => {
    const body = z.object({ email: z.string().email(), role: z.enum(ROLES) }).safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: 'invalid request' });
    try {
      return reply.code(201).send(await inviteUser(deps.db, ctxOf(req), body.data));
    } catch (e) {
      if (e instanceof AdminError) return reply.code(409).send({ error: e.code });
      throw e;
    }
  });

  app.put<{ Params: { id: string } }>('/api/admin/users/:id/role', adminOnly, async (req, reply) => {
    const body = z.object({ role: z.enum(ROLES) }).safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: 'invalid request' });
    const ctx = ctxOf(req);
    try {
      await changeRole(deps.db, ctx, ctx.role, req.params.id, body.data.role);
      return { role: body.data.role };
    } catch (e) {
      if (e instanceof AdminError) return reply.code(e.code === 'owner_demotion' ? 403 : 409).send({ error: e.code });
      throw e;
    }
  });

  app.post<{ Params: { id: string } }>('/api/admin/users/:id/deactivate', adminOnly, async (req, reply) => {
    try {
      await deactivateUser(deps.db, ctxOf(req), req.params.id);
      return { deactivated: true };
    } catch (e) {
      if (e instanceof AdminError) return reply.code(e.code === 'self_deactivate' ? 400 : 409).send({ error: e.code });
      throw e;
    }
  });

  app.get<{ Params: { id: string } }>('/api/admin/users/:id/activity', adminOnly, (req) =>
    userActivity(deps.db, ctxOf(req), req.params.id),
  );

  app.get('/api/admin/stats', adminOnly, (req) => {
    const days = Number((req.query as { days?: string }).days) || 30;
    return orgStats(deps.db, ctxOf(req), days);
  });

  // ── Data export (owner only) ──
  app.post('/api/admin/export', { preHandler: requirePermission('gdpr:erase') }, async (req, reply) => {
    const ctx = ctxOf(req);
    const { jobId } = await createExportJob(deps.db, ctx);
    void runExportJob(deps.db, ctx, jobId, deps.export); // async
    return reply.code(202).send({ jobId });
  });

  app.get<{ Params: { jobId: string } }>('/api/admin/export/:jobId', { preHandler: requirePermission('gdpr:erase') }, async (req, reply) => {
    const job = await getJob(deps.db, ctxOf(req), req.params.jobId);
    if (!job) return reply.code(404).send({ error: 'not found' });
    const body: Record<string, unknown> = { status: job.status, expiresAt: job.expiresAt };
    if (job.status === 'DONE') {
      const token = takeDownloadToken(job.id);
      if (token) body['downloadUrl'] = `/api/admin/export/${job.id}/download?token=${token}`;
    }
    return body;
  });

  app.get<{ Params: { jobId: string }; Querystring: { token?: string } }>(
    '/api/admin/export/:jobId/download',
    { preHandler: requirePermission('gdpr:erase') },
    async (req, reply) => {
      const token = req.query.token ?? '';
      const zip = await consumeDownload(deps.db, ctxOf(req), req.params.jobId, token, deps.export);
      if (!zip) return reply.code(410).send({ error: 'expired or invalid download' });
      return reply.header('content-type', 'application/zip').header('content-disposition', 'attachment; filename="org-export.zip"').send(zip);
    },
  );
}
