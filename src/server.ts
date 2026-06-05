import Fastify, { type FastifyInstance } from 'fastify';
import type { Config } from './config/index.js';
import { registerSecurity } from './http/security.js';
import { registerErrorHandler } from './http/errors.js';
import { registerHealthRoutes } from './http/health.js';
import './http/types.js';

export interface BuildServerOptions {
  config: Config;
  /**
   * Optional application routes. Registered AFTER the security plugins have
   * loaded, so they may use decorators such as `app.csrfProtection`.
   */
  routes?: (app: FastifyInstance) => Promise<void> | void;
}

/**
 * Assemble the Fastify server: structured logging with secret/PII redaction,
 * baseline security middleware, fail-closed error handling, and health routes.
 * Returns a ready instance.
 */
export async function buildServer(opts: BuildServerOptions): Promise<FastifyInstance> {
  const { config } = opts;

  const app = Fastify({
    logger: {
      level: config.logLevel,
      redact: {
        paths: [
          'req.headers.authorization',
          'req.headers.cookie',
          'req.headers["x-csrf-token"]',
          'res.headers["set-cookie"]',
        ],
        censor: '[redacted]',
      },
    },
    // Do not advertise the framework.
    disableRequestLogging: false,
    trustProxy: config.isProduction,
  });

  registerErrorHandler(app, config.isProduction);
  await registerSecurity(app, config);
  registerHealthRoutes(app);

  if (opts.routes) {
    const routes = opts.routes;
    await app.register(async (instance) => {
      await routes(instance);
    });
  }

  await app.ready();
  return app;
}
