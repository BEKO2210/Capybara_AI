import type { FastifyInstance, FastifyError, FastifyReply, FastifyRequest } from 'fastify';
import { ForbiddenError } from '../rbac/permissions.js';

/**
 * Centralized, fail-closed error handler. In production the client receives a
 * generic message with the appropriate status code and NEVER a stack trace,
 * internal message, or other detail that could aid an attacker. Full details
 * are always logged server-side.
 */
export function registerErrorHandler(app: FastifyInstance, isProduction: boolean): void {
  app.setErrorHandler((error: FastifyError, req: FastifyRequest, reply: FastifyReply) => {
    // Authorization failures from RBAC guards.
    if (error instanceof ForbiddenError) {
      return reply.code(403).send({ error: 'forbidden' });
    }

    const status = error.statusCode ?? 500;

    // Log the full error server-side regardless of environment.
    req.log.error({ err: error, statusCode: status }, 'request failed');

    // Client-facing body: never leak internals on 5xx, and in production keep
    // 4xx messages generic too (except validation, which is safe and useful).
    if (status >= 500) {
      return reply.code(status).send({ error: 'internal server error' });
    }

    if (error.validation) {
      return reply.code(400).send({ error: 'invalid request' });
    }

    const message = isProduction ? 'request error' : error.message;
    return reply.code(status).send({ error: message });
  });

  // Fail-closed 404 without revealing routing internals.
  app.setNotFoundHandler((_req, reply) => {
    reply.code(404).send({ error: 'not found' });
  });
}
