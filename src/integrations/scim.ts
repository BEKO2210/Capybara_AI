import { randomBytes, createHash } from 'node:crypto';
import { and, eq, sql } from 'drizzle-orm';
import type { AppDatabase } from '../db/client.js';
import { scimConfigs, users, memberships, sessions, auditLog, type Role } from '../db/schema/index.js';
import { withTenantContext, type TenantContext } from '../tenancy/scope.js';

const PREFIX = 'scim_';
function hashToken(raw: string): string {
  return createHash('sha256').update(raw).digest('hex');
}

/** Generate (or rotate) a SCIM bearer token; returned ONCE. */
export async function generateScimToken(db: AppDatabase, ctx: TenantContext): Promise<{ token: string; prefix: string }> {
  const token = PREFIX + randomBytes(24).toString('base64url');
  const prefix = token.slice(0, 8);
  await withTenantContext(db, ctx, async (tx) => {
    await tx.insert(scimConfigs).values({ orgId: ctx.orgId, bearerTokenHash: hashToken(token), tokenPrefix: prefix, active: true })
      .onConflictDoUpdate({ target: scimConfigs.orgId, set: { bearerTokenHash: hashToken(token), tokenPrefix: prefix, active: true, updatedAt: new Date() } });
  });
  return { token, prefix };
}

export function revokeScimToken(db: AppDatabase, ctx: TenantContext): Promise<boolean> {
  return withTenantContext(db, ctx, async (tx) => {
    const rows = await tx.update(scimConfigs).set({ active: false, updatedAt: new Date() }).where(eq(scimConfigs.orgId, ctx.orgId)).returning({ id: scimConfigs.id });
    return rows.length > 0;
  });
}

/** Resolve org id from a SCIM bearer token. Null = unauthorized. */
export async function authenticateScim(db: AppDatabase, raw: string): Promise<string | null> {
  if (!raw || !raw.startsWith(PREFIX)) return null;
  const rows = (await db.execute(sql`SELECT scim_org_by_token(${hashToken(raw)}) AS org_id`)) as unknown as Array<{ org_id: string | null }>;
  return rows[0]?.org_id ?? null;
}

// ── SCIM resource mapping ────────────────────────────────────────────────────
const USER_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:User';
const GROUP_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:Group';

export function toScimUser(u: { id: string; email: string; status: string }, role?: string): Record<string, unknown> {
  return {
    schemas: [USER_SCHEMA], id: u.id, userName: u.email, displayName: u.email.split('@')[0],
    active: u.status === 'active',
    emails: [{ value: u.email, primary: true }],
    ...(role ? { roles: [{ value: role }] } : {}),
    meta: { resourceType: 'User' },
  };
}

function listResponse(resources: unknown[]): Record<string, unknown> {
  return { schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'], totalResults: resources.length, startIndex: 1, itemsPerPage: resources.length, Resources: resources };
}

function parseFilter(filter: string | undefined): string | null {
  if (!filter) return null;
  const m = filter.match(/(userName|emails(?:\.value)?)\s+eq\s+"([^"]+)"/i);
  return m ? m[2]!.toLowerCase() : null;
}

export async function scimListUsers(db: AppDatabase, orgId: string, filter?: string): Promise<Record<string, unknown>> {
  const email = parseFilter(filter);
  return withTenantContext(db, { orgId, userId: orgId, clearance: 0 }, async (tx) => {
    const rows = await tx
      .select({ id: users.id, email: users.email, status: users.status, role: memberships.role })
      .from(memberships).innerJoin(users, eq(users.id, memberships.userId));
    const filtered = email ? rows.filter((r) => r.email.toLowerCase() === email) : rows;
    return listResponse(filtered.map((r) => toScimUser(r, r.role)));
  });
}

export async function scimGetUser(db: AppDatabase, orgId: string, id: string): Promise<Record<string, unknown> | null> {
  return withTenantContext(db, { orgId, userId: orgId, clearance: 0 }, async (tx) => {
    const rows = await tx.select({ id: users.id, email: users.email, status: users.status, role: memberships.role })
      .from(memberships).innerJoin(users, eq(users.id, memberships.userId)).where(eq(memberships.userId, id)).limit(1);
    return rows[0] ? toScimUser(rows[0], rows[0].role) : null;
  });
}

export async function scimCreateUser(db: AppDatabase, orgId: string, payload: { userName?: string; active?: boolean }): Promise<Record<string, unknown>> {
  const email = (payload.userName ?? '').trim().toLowerCase();
  const status = payload.active === false ? 'inactive' : 'active';
  const existing = await db.select({ id: users.id }).from(users).where(eq(users.email, email)).limit(1);
  let userId = existing[0]?.id;
  if (!userId) {
    const [u] = await db.insert(users).values({ email, passwordHash: '!scim', status }).returning({ id: users.id });
    userId = u!.id;
  }
  await withTenantContext(db, { orgId, userId, clearance: 0 }, async (tx) => {
    const m = await tx.select({ id: memberships.id }).from(memberships).where(and(eq(memberships.userId, userId!), eq(memberships.orgId, orgId))).limit(1);
    if (!m[0]) await tx.insert(memberships).values({ orgId, userId: userId!, role: 'member' });
    await tx.insert(auditLog).values({ orgId, actorUserId: null, action: 'scim.user.created', targetType: 'user', targetId: userId!, metadata: { email } });
  });
  return (await scimGetUser(db, orgId, userId))!;
}

async function setActive(db: AppDatabase, orgId: string, userId: string, active: boolean): Promise<void> {
  await db.update(users).set({ status: active ? 'active' : 'inactive' }).where(eq(users.id, userId));
  if (!active) await db.update(sessions).set({ revokedAt: new Date() }).where(eq(sessions.userId, userId));
  await withTenantContext(db, { orgId, userId, clearance: 0 }, async (tx) => {
    await tx.insert(auditLog).values({ orgId, action: active ? 'scim.user.activated' : 'scim.user.deactivated', targetType: 'user', targetId: userId });
  });
}

export async function scimReplaceUser(db: AppDatabase, orgId: string, id: string, payload: { active?: boolean }): Promise<Record<string, unknown> | null> {
  if (payload.active !== undefined) await setActive(db, orgId, id, payload.active);
  return scimGetUser(db, orgId, id);
}

/** Apply RFC 7644 PATCH operations (active toggle supported). */
export async function scimPatchUser(db: AppDatabase, orgId: string, id: string, ops: Array<{ op: string; path?: string; value?: unknown }>): Promise<Record<string, unknown> | null> {
  for (const op of ops) {
    const path = (op.path ?? '').toLowerCase();
    if (path === 'active' || (op.value && typeof op.value === 'object' && 'active' in (op.value as object))) {
      const active = path === 'active' ? Boolean(op.value) : Boolean((op.value as { active?: boolean }).active);
      await setActive(db, orgId, id, active);
    }
  }
  return scimGetUser(db, orgId, id);
}

/** DELETE = soft deactivate (never hard delete; GDPR erasure is separate). */
export async function scimDeleteUser(db: AppDatabase, orgId: string, id: string): Promise<boolean> {
  const exists = await scimGetUser(db, orgId, id);
  if (!exists) return false;
  await setActive(db, orgId, id, false);
  return true;
}

// ── Groups (org roles) ───────────────────────────────────────────────────────
const ROLE_GROUPS: Role[] = ['owner', 'admin', 'member', 'viewer'];

export function scimListGroups(): Record<string, unknown> {
  return listResponse(ROLE_GROUPS.map((r) => ({ schemas: [GROUP_SCHEMA], id: r, displayName: r, meta: { resourceType: 'Group' } })));
}

export function scimGetGroup(id: string): Record<string, unknown> | null {
  return ROLE_GROUPS.includes(id as Role) ? { schemas: [GROUP_SCHEMA], id, displayName: id, meta: { resourceType: 'Group' } } : null;
}

/** PATCH group: add/remove members → set their RBAC role to the group role. */
export async function scimPatchGroup(db: AppDatabase, orgId: string, role: string, ops: Array<{ op: string; path?: string; value?: unknown }>): Promise<boolean> {
  if (!ROLE_GROUPS.includes(role as Role)) return false;
  await withTenantContext(db, { orgId, userId: orgId, clearance: 0 }, async (tx) => {
    for (const op of ops) {
      if (op.op.toLowerCase() === 'add' && Array.isArray(op.value)) {
        for (const m of op.value as Array<{ value: string }>) {
          await tx.update(memberships).set({ role: role as Role }).where(and(eq(memberships.userId, m.value), eq(memberships.orgId, orgId)));
        }
      }
    }
  });
  return true;
}

export function scimServiceProviderConfig(): Record<string, unknown> {
  return {
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],
    documentationUri: 'https://github.com/BEKO2210/Capybara_AI',
    patch: { supported: true },
    bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
    filter: { supported: true, maxResults: 200 },
    changePassword: { supported: false },
    sort: { supported: false },
    etag: { supported: false },
    authenticationSchemes: [{ type: 'oauthbearertoken', name: 'OAuth Bearer Token', description: 'Authentication via SCIM bearer token' }],
    meta: { resourceType: 'ServiceProviderConfig' },
  };
}
