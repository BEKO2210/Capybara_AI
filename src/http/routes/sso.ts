import type { FastifyInstance, FastifyRequest } from 'fastify';
import { eq } from 'drizzle-orm';
import { z } from 'zod';
import type { AppDatabase } from '../../db/client.js';
import { oidcConfigs, ROLES, type Role } from '../../db/schema/index.js';
import { clearanceForRole } from '../../rbac/roles.js';
import { requireRole } from '../../rbac/guard.js';
import { withTenantContext } from '../../tenancy/scope.js';
import { deriveTenantKey, decryptSecret } from '../../lib/crypto.js';
import {
  upsertSsoConfig, getSsoConfig, deleteSsoConfig, testSsoConfig, lookupOrgByDomain,
  type SsoConfigInput,
} from '../../admin/sso.js';
import { OidcAuthProvider } from '../../auth/oidc.provider.js';

export interface SsoRoutesDeps {
  db: AppDatabase;
  masterKey: Buffer;
}

function ctxOf(req: FastifyRequest) {
  const a = req.authContext!;
  return { orgId: a.orgId, userId: a.userId, clearance: clearanceForRole(a.role as Role) };
}

const configSchema = z.object({
  issuer: z.string().url(),
  clientId: z.string().min(1),
  clientSecret: z.string().min(1),
  redirectUri: z.string().url(),
  autoProvision: z.boolean().optional(),
  defaultRole: z.enum(ROLES).optional(),
  domainHint: z.string().optional(),
  active: z.boolean().optional(),
  allowInsecure: z.boolean().optional(),
});

export function registerSsoRoutes(app: FastifyInstance, deps: SsoRoutesDeps): void {
  const adminOnly = { preHandler: requireRole('admin') };

  app.get('/api/admin/sso/config', adminOnly, async (req, reply) => {
    const cfg = await getSsoConfig(deps.db, ctxOf(req));
    if (!cfg) return reply.code(404).send({ error: 'not configured' });
    return cfg;
  });

  app.post('/api/admin/sso/config', adminOnly, async (req, reply) => {
    const body = configSchema.safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: 'invalid request' });
    return upsertSsoConfig(deps.db, ctxOf(req), body.data as SsoConfigInput, deps.masterKey);
  });

  app.post('/api/admin/sso/config/test', adminOnly, async (req, reply) => {
    const body = configSchema.partial({ redirectUri: true }).safeParse(req.body);
    if (!body.success) return reply.code(400).send({ error: 'invalid request' });
    return testSsoConfig(
      { issuer: body.data.issuer!, clientId: body.data.clientId!, clientSecret: body.data.clientSecret! },
      { ...(body.data.allowInsecure ? { allowInsecure: true } : {}) },
    );
  });

  app.delete('/api/admin/sso/config', adminOnly, async (req) => ({ deleted: await deleteSsoConfig(deps.db, ctxOf(req)) }));

  // ── SSO login (public) ──
  app.get<{ Querystring: { domain?: string } }>('/api/auth/sso/login', async (req, reply) => {
    const domain = req.query.domain;
    if (!domain) return reply.code(400).send({ error: 'domain required' });
    const routing = await lookupOrgByDomain(deps.db, domain);
    if (!routing) return reply.code(403).send({ error: 'sso_not_configured' });

    // Fetch the decrypted secret for this org to build the provider.
    const full = await withTenantContext(
      deps.db, { orgId: routing.orgId, userId: routing.orgId, clearance: 0 },
      async (tx) => (await tx.select().from(oidcConfigs).where(eq(oidcConfigs.orgId, routing.orgId)).limit(1))[0],
    );
    if (!full) return reply.code(403).send({ error: 'sso_not_configured' });

    const provider = new OidcAuthProvider({
      issuer: routing.issuer,
      clientId: routing.clientId,
      clientSecret: decryptSecret(full.clientSecretEncrypted, deriveTenantKey(deps.masterKey, routing.orgId)),
      redirectUri: routing.redirectUri,
      ...(routing.issuer.startsWith('http://') ? { allowInsecure: true } : {}),
    });
    try {
      const start = await provider.start();
      reply.setCookie('sso_flow', JSON.stringify({ s: start.state, n: start.nonce, v: start.codeVerifier, o: routing.orgId }), {
        httpOnly: true, sameSite: 'lax', secure: false, path: '/', signed: true, maxAge: 600,
      });
      return reply.redirect(start.authorizationUrl);
    } catch (e) {
      return reply.code(502).send({ error: 'oidc_discovery_failed', detail: e instanceof Error ? e.message : String(e) });
    }
  });
}
