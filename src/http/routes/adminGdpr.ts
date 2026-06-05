import type { FastifyInstance } from 'fastify';
import { clearanceForRole } from '../../rbac/roles.js';
import { requirePermission } from '../../rbac/guard.js';
import { eraseUser } from '../../documents/erasure.js';
import type { AppDatabase } from '../../db/client.js';

export interface GdprRoutesDeps {
  db: AppDatabase;
}

/**
 * GDPR erasure endpoint. Irreversible, so it requires an explicit confirmation
 * header AND the owner-only `gdpr:erase` permission.
 */
export function registerGdprRoutes(app: FastifyInstance, deps: GdprRoutesDeps): void {
  app.delete<{ Params: { id: string } }>(
    '/api/admin/users/:id/gdpr-erasure',
    { preHandler: requirePermission('gdpr:erase') },
    async (req, reply) => {
      if (req.headers['x-confirm-erasure'] !== 'permanent') {
        return reply.code(400).send({ error: 'missing confirmation', hint: 'X-Confirm-Erasure: permanent' });
      }
      const a = req.authContext!;
      const result = await eraseUser(
        deps.db,
        { orgId: a.orgId, userId: a.userId, clearance: clearanceForRole(a.role) },
        req.params.id,
      );
      return reply.code(200).send(result);
    },
  );
}
