import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { loadConfig } from '../../src/config/index.js';
import { buildServer } from '../../src/server.js';

const ALLOWED_ORIGIN = 'https://app.allowed.example';

describe('http — baseline security middleware', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    const config = loadConfig({
      APP_ENV: 'test',
      CORS_ALLOWED_ORIGINS: ALLOWED_ORIGIN,
      LOG_LEVEL: 'fatal',
    });
    app = await buildServer({
      config,
      routes: (instance) => {
        instance.get('/csrf', async (_req, reply) => ({ token: reply.generateCsrf() }));
        instance.post(
          '/echo',
          { preHandler: instance.csrfProtection },
          async (req) => ({ body: req.body }),
        );
        instance.get(
          '/limited',
          { config: { rateLimit: { max: 2, timeWindow: 60_000 } } },
          async () => ({ ok: true }),
        );
        instance.get('/boom', async () => {
          throw new Error('super secret internal failure detail');
        });
      },
    });
  });

  afterAll(async () => {
    await app?.close();
  });

  it('sets hardened security headers (CSP frame-ancestors none, nosniff)', async () => {
    const res = await app.inject({ method: 'GET', url: '/healthz' });
    expect(res.statusCode).toBe(200);
    const csp = res.headers['content-security-policy'];
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['cross-origin-opener-policy']).toBe('same-origin');
  });

  it('reflects an allowed CORS origin and withholds it from a disallowed one', async () => {
    const allowed = await app.inject({
      method: 'GET',
      url: '/healthz',
      headers: { origin: ALLOWED_ORIGIN },
    });
    expect(allowed.headers['access-control-allow-origin']).toBe(ALLOWED_ORIGIN);

    const denied = await app.inject({
      method: 'GET',
      url: '/healthz',
      headers: { origin: 'https://evil.example' },
    });
    expect(denied.headers['access-control-allow-origin']).toBeUndefined();
  });

  it('rejects a state-changing request without a CSRF token (403)', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/echo',
      payload: { hello: 'world' },
    });
    expect(res.statusCode).toBe(403);
  });

  it('accepts a state-changing request WITH a valid CSRF token', async () => {
    const csrfRes = await app.inject({ method: 'GET', url: '/csrf' });
    const token = csrfRes.json<{ token: string }>().token;
    const cookie = csrfRes.cookies.map((c) => `${c.name}=${c.value}`).join('; ');

    const res = await app.inject({
      method: 'POST',
      url: '/echo',
      headers: { 'csrf-token': token, cookie },
      payload: { hello: 'world' },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json<{ body: { hello: string } }>().body.hello).toBe('world');
  });

  it('enforces the per-route rate limit (429 past the budget)', async () => {
    const first = await app.inject({ method: 'GET', url: '/limited' });
    const second = await app.inject({ method: 'GET', url: '/limited' });
    const third = await app.inject({ method: 'GET', url: '/limited' });
    expect(first.statusCode).toBe(200);
    expect(second.statusCode).toBe(200);
    expect(third.statusCode).toBe(429);
  });

  it('never leaks internal error detail on 500 (fail-closed)', async () => {
    const res = await app.inject({ method: 'GET', url: '/boom' });
    expect(res.statusCode).toBe(500);
    expect(res.json()).toEqual({ error: 'internal server error' });
    expect(res.payload).not.toContain('super secret');
  });
});
