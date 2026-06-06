import { createHash } from 'node:crypto';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import helmet from '@fastify/helmet';
import cors from '@fastify/cors';
import cookie from '@fastify/cookie';
import csrf from '@fastify/csrf-protection';
import rateLimit from '@fastify/rate-limit';
import type { Config } from '../config/index.js';

/**
 * Registers the baseline HTTP security middleware. All defaults are
 * secure-by-default and, where relevant, stricter in production:
 *   - helmet: CSP (no inline/eval), frame-ancestors none, nosniff, HSTS (prod).
 *   - CORS: strict allowlist from config; NO wildcard; credentials enabled.
 *   - CSRF: double-submit token required on state-changing routes.
 *   - rate-limit: global per-IP budget (stricter per-route where needed).
 *
 * These plugins use fastify-plugin internally, so their decorators
 * (e.g. app.csrfProtection) propagate to routes registered on `app`.
 */
export interface SecurityOptions {
  /**
   * Optional shared store for rate limiting (an ioredis-compatible client).
   * In-memory limits are per-instance; inject a shared store so a horizontally
   * scaled deployment enforces ONE global budget. We don't bundle a Redis client
   * — operators pass their own, keeping the dependency surface minimal.
   */
  rateLimitRedis?: unknown;
}

export async function registerSecurity(app: FastifyInstance, config: Config, opts: SecurityOptions = {}): Promise<void> {
  await app.register(cookie, { secret: config.cookieSecret });

  await app.register(helmet, {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        frameAncestors: ["'none'"],
        formAction: ["'self'"],
      },
    },
    // HSTS only makes sense over TLS; enable in production (TLS terminated at
    // the proxy). Disabled in dev to avoid pinning localhost to HTTPS.
    hsts: config.isProduction
      ? { maxAge: 15_552_000, includeSubDomains: true, preload: true }
      : false,
    crossOriginOpenerPolicy: { policy: 'same-origin' },
    referrerPolicy: { policy: 'no-referrer' },
  });

  await app.register(cors, {
    origin: config.corsAllowedOrigins as string[],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
  });

  await app.register(rateLimit, {
    max: config.rateLimit.max,
    timeWindow: config.rateLimit.windowMs,
    // Shared store for multi-instance deployments (per-instance in-memory if absent).
    ...(opts.rateLimitRedis ? { redis: opts.rateLimitRedis } : {}),
    // Per-API-key buckets when an API key is presented; per-IP otherwise.
    keyGenerator: (req: FastifyRequest) => {
      const authz = req.headers['authorization'];
      if (authz && authz.startsWith('Bearer capy_')) {
        return 'apikey:' + createHash('sha256').update(authz).digest('hex');
      }
      return req.ip;
    },
  });

  await app.register(csrf, {
    cookieOpts: {
      path: '/',
      sameSite: 'lax',
      httpOnly: true,
      secure: config.secureCookies,
    },
  });
}
