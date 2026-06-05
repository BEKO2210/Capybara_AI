import type { FastifyReply, FastifyRequest, preHandlerHookHandler } from 'fastify';
import type { Role } from '../db/schema/index.js';
import { can, hasAtLeastRole } from './permissions.js';
import type { Permission } from './roles.js';

/**
 * Fastify authorization guards (preHandlers). All guards FAIL CLOSED: a request
 * without an established auth context is rejected 401; an authenticated request
 * lacking the capability is rejected 403. Authorization reads only
 * `request.authContext`, which is derived server-side from the session.
 */

function unauthorized(reply: FastifyReply): void {
  reply.code(401).send({ error: 'authentication required' });
}

function forbidden(reply: FastifyReply): void {
  reply.code(403).send({ error: 'forbidden' });
}

/** Require any authenticated principal. */
export const requireAuth: preHandlerHookHandler = async (req: FastifyRequest, reply) => {
  if (!req.authContext) {
    unauthorized(reply);
  }
};

/** Require that the principal holds a specific permission. */
export function requirePermission(permission: Permission): preHandlerHookHandler {
  return async (req: FastifyRequest, reply) => {
    const ctx = req.authContext;
    if (!ctx) return unauthorized(reply);
    if (!can(ctx.role, permission)) return forbidden(reply);
  };
}

/** Require that the principal's role is at least `minimum`. */
export function requireRole(minimum: Role): preHandlerHookHandler {
  return async (req: FastifyRequest, reply) => {
    const ctx = req.authContext;
    if (!ctx) return unauthorized(reply);
    if (!hasAtLeastRole(ctx.role, minimum)) return forbidden(reply);
  };
}
