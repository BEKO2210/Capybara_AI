import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { loadConfig } from '../../src/config/index.js';
import { buildServer } from '../../src/server.js';
import { requirePermission } from '../../src/rbac/guard.js';
import { can, hasAtLeastRole } from '../../src/rbac/permissions.js';
import type { Role } from '../../src/db/schema/index.js';

describe('rbac — least-privilege capability matrix', () => {
  it('grants only the expected capabilities per role (happy path)', () => {
    expect(can('viewer', 'content:read')).toBe(true);
    expect(can('member', 'content:create')).toBe(true);
    expect(can('admin', 'member:invite')).toBe(true);
    expect(can('owner', 'org:delete')).toBe(true);
  });

  it('denies capabilities above a role (boundary cases)', () => {
    expect(can('viewer', 'content:create')).toBe(false);
    expect(can('member', 'member:invite')).toBe(false);
    expect(can('admin', 'org:delete')).toBe(false);
    // Unknown/garbage role fails closed.
    expect(can('nonsense' as Role, 'content:read')).toBe(false);
  });

  it('orders roles by privilege', () => {
    expect(hasAtLeastRole('owner', 'admin')).toBe(true);
    expect(hasAtLeastRole('admin', 'owner')).toBe(false);
    expect(hasAtLeastRole('member', 'member')).toBe(true);
  });
});

describe('rbac — guard enforcement over HTTP (fail-closed)', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    const config = loadConfig({
      APP_ENV: 'test',
      CORS_ALLOWED_ORIGINS: 'http://localhost',
      LOG_LEVEL: 'fatal',
    });
    app = await buildServer({
      config,
      routes: (instance) => {
        // TEST-ONLY auth shim: establish authContext from a header so the guard
        // can be exercised per role. This lives in the test, never in src/.
        instance.addHook('preHandler', async (req) => {
          const role = req.headers['x-test-role'] as Role | undefined;
          if (role) {
            req.authContext = {
              userId: '00000000-0000-0000-0000-000000000000',
              email: 'test@example.com',
              orgId: '00000000-0000-0000-0000-000000000001',
              role,
              sessionId: 's',
            };
          }
        });
        instance.get(
          '/content',
          { preHandler: requirePermission('content:delete') },
          async () => ({ ok: true }),
        );
      },
    });
  });

  afterAll(async () => {
    await app?.close();
  });

  it('rejects unauthenticated requests with 401', async () => {
    const res = await app.inject({ method: 'GET', url: '/content' });
    expect(res.statusCode).toBe(401);
  });

  it('forbids a viewer/member from a delete-gated route (403)', async () => {
    for (const role of ['viewer', 'member'] as Role[]) {
      const res = await app.inject({ method: 'GET', url: '/content', headers: { 'x-test-role': role } });
      expect(res.statusCode, role).toBe(403);
    }
  });

  it('allows admin and owner through the delete-gated route (200)', async () => {
    for (const role of ['admin', 'owner'] as Role[]) {
      const res = await app.inject({ method: 'GET', url: '/content', headers: { 'x-test-role': role } });
      expect(res.statusCode, role).toBe(200);
    }
  });
});
