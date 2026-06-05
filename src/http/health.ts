import type { FastifyInstance } from 'fastify';

/**
 * Liveness/readiness endpoints. These intentionally expose NO version, build,
 * dependency, or configuration detail — only a coarse status — so they are safe
 * to leave unauthenticated.
 */
export function registerHealthRoutes(app: FastifyInstance): void {
  app.get('/healthz', async () => ({ status: 'ok' }));
  app.get('/readyz', async () => ({ status: 'ready' }));
}
