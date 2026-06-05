import type { FastifyInstance, FastifyRequest } from 'fastify';
import { eq } from 'drizzle-orm';
import { z } from 'zod';
import type { AppDatabase } from '../../db/client.js';
import { organizations, RISK_CLASSES } from '../../db/schema/index.js';
import { clearanceForRole } from '../../rbac/roles.js';
import { requirePermission } from '../../rbac/guard.js';
import type { Role } from '../../db/schema/index.js';
import {
  listInventory,
  createInventory,
  updateInventory,
  deleteInventory,
  type InventoryInput,
} from '../../compliance/inventory.js';
import { listOversight, approveRequest, rejectRequest } from '../../compliance/oversight.js';
import { renderInventoryPdf, renderCompliancePdf } from '../../compliance/pdf.js';
import { gatherReportData } from '../../compliance/report.js';

export interface ComplianceRoutesDeps {
  db: AppDatabase;
}

const inventoryCreateSchema = z.object({
  modelId: z.string().optional(),
  modelName: z.string().min(1),
  provider: z.string().min(1),
  purpose: z.string().optional(),
  riskClass: z.enum(RISK_CLASSES).optional(),
  humanOversightRequired: z.boolean().optional(),
  dataCategoriesProcessed: z.array(z.string()).optional(),
  legalBasis: z.string().optional(),
  notes: z.string().optional(),
});
const inventoryUpdateSchema = inventoryCreateSchema.partial();

function ctxOf(req: FastifyRequest): { orgId: string; userId: string; clearance: number } {
  const a = req.authContext!;
  return { orgId: a.orgId, userId: a.userId, clearance: clearanceForRole(a.role as Role) };
}

async function orgName(db: AppDatabase, orgId: string): Promise<string> {
  const rows = await db.select({ name: organizations.name }).from(organizations).where(eq(organizations.id, orgId)).limit(1);
  return rows[0]?.name ?? orgId;
}

export function registerComplianceRoutes(app: FastifyInstance, deps: ComplianceRoutesDeps): void {
  // ── KI-Inventar ──
  app.get('/api/compliance/inventory', { preHandler: requirePermission('compliance:read') }, (req) =>
    listInventory(deps.db, ctxOf(req)),
  );

  app.post('/api/compliance/inventory', { preHandler: requirePermission('compliance:write') }, async (req, reply) => {
    const parsed = inventoryCreateSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: 'invalid request' });
    return reply.code(201).send(await createInventory(deps.db, ctxOf(req), parsed.data as InventoryInput));
  });

  app.put<{ Params: { id: string } }>(
    '/api/compliance/inventory/:id',
    { preHandler: requirePermission('compliance:write') },
    async (req, reply) => {
      const parsed = inventoryUpdateSchema.safeParse(req.body);
      if (!parsed.success) return reply.code(400).send({ error: 'invalid request' });
      const row = await updateInventory(deps.db, ctxOf(req), req.params.id, parsed.data as Partial<InventoryInput>);
      if (!row) return reply.code(404).send({ error: 'not found' });
      return row;
    },
  );

  app.delete<{ Params: { id: string } }>(
    '/api/compliance/inventory/:id',
    { preHandler: requirePermission('compliance:delete') },
    async (req, reply) => {
      const ok = await deleteInventory(deps.db, ctxOf(req), req.params.id);
      if (!ok) return reply.code(404).send({ error: 'not found' });
      return { deleted: true };
    },
  );

  app.get('/api/compliance/inventory/export.pdf', { preHandler: requirePermission('compliance:report') }, async (req, reply) => {
    const ctx = ctxOf(req);
    const [entries, name] = await Promise.all([listInventory(deps.db, ctx), orgName(deps.db, ctx.orgId)]);
    const pdf = await renderInventoryPdf({ orgName: name, generatedBy: req.authContext!.email, entries });
    return reply.header('content-type', 'application/pdf').header('content-disposition', 'attachment; filename="ki-inventar.pdf"').send(pdf);
  });

  // ── Human oversight ──
  app.get('/api/compliance/oversight', { preHandler: requirePermission('oversight:read') }, (req) =>
    listOversight(deps.db, ctxOf(req)),
  );
  app.get('/api/compliance/oversight/pending', { preHandler: requirePermission('oversight:read') }, (req) =>
    listOversight(deps.db, ctxOf(req), { pendingOnly: true }),
  );
  app.post<{ Params: { id: string } }>(
    '/api/compliance/oversight/:id/approve',
    { preHandler: requirePermission('oversight:decide') },
    async (req, reply) => {
      const ctx = ctxOf(req);
      const ok = await approveRequest(deps.db, ctx, req.params.id, ctx.userId);
      if (!ok) return reply.code(409).send({ error: 'not pending or not found' });
      return { status: 'APPROVED' };
    },
  );
  app.post<{ Params: { id: string } }>(
    '/api/compliance/oversight/:id/reject',
    { preHandler: requirePermission('oversight:decide') },
    async (req, reply) => {
      const ctx = ctxOf(req);
      const ok = await rejectRequest(deps.db, ctx, req.params.id, ctx.userId);
      if (!ok) return reply.code(409).send({ error: 'not pending or not found' });
      return { status: 'REJECTED' };
    },
  );

  // ── Compliance report ──
  app.get('/api/compliance/report.pdf', { preHandler: requirePermission('compliance:report') }, async (req, reply) => {
    const ctx = ctxOf(req);
    const data = await gatherReportData(deps.db, ctx, await orgName(deps.db, ctx.orgId), req.authContext!.email);
    const pdf = await renderCompliancePdf(data);
    return reply.header('content-type', 'application/pdf').header('content-disposition', 'attachment; filename="ki-compliance-bericht.pdf"').send(pdf);
  });
}
