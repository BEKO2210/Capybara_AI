import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { AppDatabase } from '../../db/client.js';
import type { Role } from '../../db/schema/index.js';
import { clearanceForRole } from '../../rbac/roles.js';
import { requireRole } from '../../rbac/guard.js';
import { deriveTenantKey } from '../../lib/crypto.js';
import { ensureKeyVersion, rotateKey } from '../../admin/encryption.js';

export interface EncryptionRoutesDeps {
  db: AppDatabase;
  masterKek: Buffer;
  documentEncryptionKey: Buffer;
}

function ctxOf(req: FastifyRequest) {
  const a = req.authContext!;
  return { orgId: a.orgId, userId: a.userId, clearance: clearanceForRole(a.role as Role) };
}

export function registerEncryptionRoutes(app: FastifyInstance, deps: EncryptionRoutesDeps): void {
  // Key rotation — owner only.
  app.post('/api/admin/encryption/rotate', { preHandler: requireRole('owner') }, async (req) => {
    const ctx = ctxOf(req);
    // Ensure a versioned key exists (idempotent migration), then rotate.
    await ensureKeyVersion(deps.db, ctx, deps.masterKek, deriveTenantKey(deps.documentEncryptionKey, ctx.orgId));
    return rotateKey(deps.db, ctx, deps.masterKek);
  });
}
