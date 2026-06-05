import type { FastifyRequest, FastifyReply, preHandlerHookHandler } from 'fastify';
import type { AppDatabase } from '../db/client.js';
import { auditLog, type ApiKeyScope } from '../db/schema/index.js';
import { withTenantContext } from '../tenancy/scope.js';
import { authenticateApiKey } from '../integrations/apiKeys.js';
import './types.js';

const BEARER = 'Bearer ';

/**
 * Authenticate an API key from `Authorization: Bearer capy_<key>`. On success
 * sets `req.apiKey` and audit-logs the request. Fails closed (401).
 */
export function apiKeyAuth(db: AppDatabase): preHandlerHookHandler {
  return async (req: FastifyRequest, reply: FastifyReply) => {
    const authz = req.headers['authorization'];
    if (!authz || !authz.startsWith(BEARER)) {
      return reply.code(401).send({ error: 'api key required' });
    }
    const auth = await authenticateApiKey(db, authz.slice(BEARER.length));
    if (!auth) return reply.code(401).send({ error: 'invalid or expired api key' });
    req.apiKey = auth;

    // Every API-key request is audited.
    await withTenantContext(db, { orgId: auth.orgId, userId: auth.orgId, clearance: 0 }, async (tx) => {
      await tx.insert(auditLog).values({
        orgId: auth.orgId,
        action: 'api.request',
        targetType: 'api_key',
        targetId: auth.keyId,
        metadata: { method: req.method, path: req.url },
      });
    }).catch(() => {});
  };
}

/** Require that the authenticated API key carries `scope`. */
export function requireScope(scope: ApiKeyScope): preHandlerHookHandler {
  return async (req: FastifyRequest, reply: FastifyReply) => {
    if (!req.apiKey || !req.apiKey.scopes.includes(scope)) {
      return reply.code(403).send({ error: 'insufficient_scope', required: scope });
    }
  };
}
