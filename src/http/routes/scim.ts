import type { FastifyInstance, FastifyReply, FastifyRequest, preHandlerHookHandler } from 'fastify';
import type { AppDatabase } from '../../db/client.js';
import { clearanceForRole } from '../../rbac/roles.js';
import { requireRole } from '../../rbac/guard.js';
import type { Role } from '../../db/schema/index.js';
import {
  authenticateScim, generateScimToken, revokeScimToken,
  scimListUsers, scimGetUser, scimCreateUser, scimReplaceUser, scimPatchUser, scimDeleteUser,
  scimListGroups, scimGetGroup, scimPatchGroup, scimServiceProviderConfig,
} from '../../integrations/scim.js';
import './../types.js';

export interface ScimRoutesDeps {
  db: AppDatabase;
}

function scimError(status: number, detail: string): Record<string, unknown> {
  return { schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'], status: String(status), detail };
}

export function registerScimRoutes(app: FastifyInstance, deps: ScimRoutesDeps): void {
  // SCIM bearer auth → resolves org from the token.
  const scimAuth: preHandlerHookHandler = async (req: FastifyRequest, reply: FastifyReply) => {
    const h = req.headers['authorization'];
    if (!h || !h.startsWith('Bearer ')) return reply.code(401).send(scimError(401, 'missing bearer token'));
    const orgId = await authenticateScim(deps.db, h.slice('Bearer '.length));
    if (!orgId) return reply.code(401).send(scimError(401, 'invalid token'));
    req.scimOrgId = orgId;
  };
  const auth = { preHandler: scimAuth };
  const scimType = (reply: FastifyReply) => reply.type('application/scim+json');

  // Capability declaration (public).
  app.get('/scim/v2/ServiceProviderConfig', (_req, reply) => scimType(reply).send(scimServiceProviderConfig()));

  app.get<{ Querystring: { filter?: string } }>('/scim/v2/Users', auth, async (req, reply) =>
    scimType(reply).send(await scimListUsers(deps.db, req.scimOrgId!, req.query.filter)),
  );
  app.get<{ Params: { id: string } }>('/scim/v2/Users/:id', auth, async (req, reply) => {
    const u = await scimGetUser(deps.db, req.scimOrgId!, req.params.id);
    return u ? scimType(reply).send(u) : reply.code(404).send(scimError(404, 'not found'));
  });
  app.post('/scim/v2/Users', auth, async (req, reply) =>
    scimType(reply.code(201)).send(await scimCreateUser(deps.db, req.scimOrgId!, req.body as { userName?: string; active?: boolean })),
  );
  app.put<{ Params: { id: string } }>('/scim/v2/Users/:id', auth, async (req, reply) => {
    const u = await scimReplaceUser(deps.db, req.scimOrgId!, req.params.id, req.body as { active?: boolean });
    return u ? scimType(reply).send(u) : reply.code(404).send(scimError(404, 'not found'));
  });
  app.patch<{ Params: { id: string } }>('/scim/v2/Users/:id', auth, async (req, reply) => {
    const ops = ((req.body as { Operations?: Array<{ op: string; path?: string; value?: unknown }> }).Operations) ?? [];
    const u = await scimPatchUser(deps.db, req.scimOrgId!, req.params.id, ops);
    return u ? scimType(reply).send(u) : reply.code(404).send(scimError(404, 'not found'));
  });
  app.delete<{ Params: { id: string } }>('/scim/v2/Users/:id', auth, async (req, reply) => {
    const ok = await scimDeleteUser(deps.db, req.scimOrgId!, req.params.id);
    return ok ? reply.code(204).send() : reply.code(404).send(scimError(404, 'not found'));
  });

  app.get('/scim/v2/Groups', auth, (_req, reply) => scimType(reply).send(scimListGroups()));
  app.get<{ Params: { id: string } }>('/scim/v2/Groups/:id', auth, (req, reply) => {
    const g = scimGetGroup(req.params.id);
    return g ? scimType(reply).send(g) : reply.code(404).send(scimError(404, 'not found'));
  });
  app.patch<{ Params: { id: string } }>('/scim/v2/Groups/:id', auth, async (req, reply) => {
    const ops = ((req.body as { Operations?: Array<{ op: string; path?: string; value?: unknown }> }).Operations) ?? [];
    const ok = await scimPatchGroup(deps.db, req.scimOrgId!, req.params.id, ops);
    return ok ? scimType(reply).send(scimGetGroup(req.params.id)) : reply.code(404).send(scimError(404, 'not found'));
  });

  // ── Admin: SCIM token management ──
  const adminOnly = { preHandler: requireRole('admin') };
  const ctxOf = (req: FastifyRequest) => {
    const a = req.authContext!;
    return { orgId: a.orgId, userId: a.userId, clearance: clearanceForRole(a.role as Role) };
  };
  app.post('/api/admin/scim/token', adminOnly, async (req, reply) =>
    reply.code(201).send(await generateScimToken(deps.db, ctxOf(req))),
  );
  app.delete('/api/admin/scim/token', adminOnly, async (req) => ({ revoked: await revokeScimToken(deps.db, ctxOf(req)) }));
}
