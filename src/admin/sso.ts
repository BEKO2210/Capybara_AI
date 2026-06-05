import { eq, sql, and } from 'drizzle-orm';
import * as client from 'openid-client';
import type { AppDatabase } from '../db/client.js';
import { oidcConfigs, users, memberships, auditLog, type Role, type OidcConfig } from '../db/schema/index.js';
import { withTenantContext, type TenantContext } from '../tenancy/scope.js';
import { encryptSecret, decryptSecret, deriveTenantKey } from '../lib/crypto.js';

export interface SsoConfigInput {
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  autoProvision?: boolean;
  defaultRole?: Role;
  domainHint?: string;
  active?: boolean;
}

/** Public (secret-free) view of an SSO config. */
export type SsoConfigView = Omit<OidcConfig, 'clientSecretEncrypted'> & { clientSecretSet: boolean };

function view(c: OidcConfig): SsoConfigView {
  const { clientSecretEncrypted, ...rest } = c;
  return { ...rest, clientSecretSet: clientSecretEncrypted.length > 0 };
}

export async function upsertSsoConfig(
  db: AppDatabase,
  ctx: TenantContext,
  input: SsoConfigInput,
  masterKey: Buffer,
): Promise<SsoConfigView> {
  const secretEnc = encryptSecret(input.clientSecret, deriveTenantKey(masterKey, ctx.orgId));
  return withTenantContext(db, ctx, async (tx) => {
    const [row] = await tx
      .insert(oidcConfigs)
      .values({
        orgId: ctx.orgId,
        issuer: input.issuer,
        clientId: input.clientId,
        clientSecretEncrypted: secretEnc,
        redirectUri: input.redirectUri,
        autoProvision: input.autoProvision ?? true,
        defaultRole: input.defaultRole ?? 'member',
        domainHint: input.domainHint ?? null,
        active: input.active ?? true,
      })
      .onConflictDoUpdate({
        target: oidcConfigs.orgId,
        set: {
          issuer: input.issuer,
          clientId: input.clientId,
          clientSecretEncrypted: secretEnc,
          redirectUri: input.redirectUri,
          autoProvision: input.autoProvision ?? true,
          defaultRole: input.defaultRole ?? 'member',
          domainHint: input.domainHint ?? null,
          active: input.active ?? true,
          updatedAt: new Date(),
        },
      })
      .returning();
    return view(row!);
  });
}

export function getSsoConfig(db: AppDatabase, ctx: TenantContext): Promise<SsoConfigView | null> {
  return withTenantContext(db, ctx, async (tx) => {
    const rows = await tx.select().from(oidcConfigs).where(eq(oidcConfigs.orgId, ctx.orgId)).limit(1);
    return rows[0] ? view(rows[0]) : null;
  });
}

export function deleteSsoConfig(db: AppDatabase, ctx: TenantContext): Promise<boolean> {
  return withTenantContext(db, ctx, async (tx) => {
    const rows = await tx.delete(oidcConfigs).where(eq(oidcConfigs.orgId, ctx.orgId)).returning({ id: oidcConfigs.id });
    return rows.length > 0;
  });
}

export interface SsoTestResult {
  ok: boolean;
  issuer?: string;
  endpoints?: { authorization_endpoint?: string; token_endpoint?: string; jwks_uri?: string };
  error?: string;
}

/** Validate issuer discovery (used by the admin "test connection" button). */
export async function testSsoConfig(
  input: { issuer: string; clientId: string; clientSecret: string },
  opts: { allowInsecure?: boolean } = {},
): Promise<SsoTestResult> {
  try {
    const config = await client.discovery(
      new URL(input.issuer),
      input.clientId,
      input.clientSecret,
      undefined,
      opts.allowInsecure ? { execute: [client.allowInsecureRequests] } : undefined,
    );
    const meta = config.serverMetadata();
    return {
      ok: true,
      issuer: meta.issuer,
      endpoints: {
        ...(meta.authorization_endpoint ? { authorization_endpoint: meta.authorization_endpoint } : {}),
        ...(meta.token_endpoint ? { token_endpoint: meta.token_endpoint } : {}),
        ...(meta.jwks_uri ? { jwks_uri: meta.jwks_uri } : {}),
      },
    };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}

export interface DomainRouting {
  orgId: string;
  issuer: string;
  clientId: string;
  redirectUri: string;
  autoProvision: boolean;
  defaultRole: Role;
}

/** Resolve an active SSO config by email domain (no tenant context needed). */
export async function lookupOrgByDomain(db: AppDatabase, domain: string): Promise<DomainRouting | null> {
  const rows = (await db.execute(sql`SELECT * FROM oidc_config_by_domain(${domain})`)) as unknown as Array<{
    org_id: string; issuer: string; client_id: string; redirect_uri: string; auto_provision: boolean; default_role: string;
  }>;
  const r = rows[0];
  if (!r) return null;
  return {
    orgId: r.org_id, issuer: r.issuer, clientId: r.client_id, redirectUri: r.redirect_uri,
    autoProvision: r.auto_provision, defaultRole: r.default_role as Role,
  };
}

/**
 * Auto-provision a user from a verified SSO identity. Creates the account (role
 * = config default) and org membership if absent; idempotent on re-login.
 */
export async function autoProvisionUser(
  db: AppDatabase,
  routing: DomainRouting,
  identity: { email: string; subject: string },
): Promise<{ userId: string; created: boolean }> {
  const email = identity.email.trim().toLowerCase();
  const existing = await db.select({ id: users.id }).from(users).where(eq(users.email, email)).limit(1);
  let userId = existing[0]?.id;
  let created = false;
  if (!userId) {
    const [u] = await db
      .insert(users)
      .values({ email, passwordHash: '!sso', status: 'active' })
      .returning({ id: users.id });
    userId = u!.id;
    created = true;
  }

  const ctx: TenantContext = { orgId: routing.orgId, userId, clearance: 0 };
  await withTenantContext(db, ctx, async (tx) => {
    const m = await tx
      .select({ id: memberships.id })
      .from(memberships)
      .where(and(eq(memberships.userId, userId!), eq(memberships.orgId, routing.orgId)))
      .limit(1);
    if (!m[0]) {
      await tx.insert(memberships).values({ orgId: routing.orgId, userId: userId!, role: routing.defaultRole });
      await tx.insert(auditLog).values({
        orgId: routing.orgId, actorUserId: userId!, action: 'user.provisioned_sso',
        targetType: 'user', targetId: userId!, metadata: { email, role: routing.defaultRole },
      });
    }
  });
  return { userId: userId!, created };
}

export { decryptSecret, deriveTenantKey };
