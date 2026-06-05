import { randomBytes, createHash } from 'node:crypto';
import { and, eq, desc, sql } from 'drizzle-orm';
import type { AppDatabase } from '../db/client.js';
import { users, memberships, sessions, auditLog, type Role } from '../db/schema/index.js';
import { withTenantContext, type TenantContext } from '../tenancy/scope.js';

export class AdminError extends Error {
  constructor(message: string, readonly code: 'self_deactivate' | 'owner_demotion' | 'email_exists' | 'not_found') {
    super(message);
    this.name = 'AdminError';
  }
}

export interface AdminUserRow {
  id: string;
  name: string;
  email: string;
  role: string;
  mfaEnrolled: boolean;
  status: string;
  lastActive: Date | null;
  createdAt: Date;
}

export function listUsers(
  db: AppDatabase,
  ctx: TenantContext,
  page: { limit?: number; offset?: number } = {},
): Promise<AdminUserRow[]> {
  const limit = Math.min(page.limit ?? 50, 200);
  const offset = page.offset ?? 0;
  return withTenantContext(db, ctx, async (tx) => {
    const rows = await tx
      .select({
        id: users.id,
        email: users.email,
        role: memberships.role,
        mfaEnrolled: users.mfaEnabled,
        status: users.status,
        lastActive: users.lastActiveAt,
        createdAt: users.createdAt,
      })
      .from(memberships)
      .innerJoin(users, eq(users.id, memberships.userId))
      .orderBy(desc(users.createdAt))
      .limit(limit)
      .offset(offset);
    return rows.map((r) => ({ ...r, name: r.email.split('@')[0] ?? r.email }));
  });
}

export interface InviteResult {
  userId: string;
  inviteToken: string; // returned once
}

export async function inviteUser(
  db: AppDatabase,
  ctx: TenantContext,
  input: { email: string; role: Role },
): Promise<InviteResult> {
  const email = input.email.trim().toLowerCase();
  const existing = await db.select({ id: users.id }).from(users).where(eq(users.email, email)).limit(1);
  if (existing[0]) throw new AdminError('email already registered', 'email_exists');

  const inviteToken = randomBytes(32).toString('base64url');
  const inviteTokenHash = createHash('sha256').update(inviteToken).digest('hex');

  const [user] = await db
    .insert(users)
    .values({ email, passwordHash: '!invited', status: 'invited', inviteTokenHash })
    .returning({ id: users.id });

  await withTenantContext(db, ctx, async (tx) => {
    await tx.insert(memberships).values({ orgId: ctx.orgId, userId: user!.id, role: input.role });
    await tx.insert(auditLog).values({
      orgId: ctx.orgId,
      actorUserId: ctx.userId,
      action: 'user.invited',
      targetType: 'user',
      targetId: user!.id,
      metadata: { email, role: input.role },
    });
  });

  return { userId: user!.id, inviteToken };
}

export async function changeRole(
  db: AppDatabase,
  ctx: TenantContext,
  actorRole: Role,
  targetUserId: string,
  newRole: Role,
): Promise<void> {
  await withTenantContext(db, ctx, async (tx) => {
    const rows = await tx
      .select({ role: memberships.role })
      .from(memberships)
      .where(eq(memberships.userId, targetUserId))
      .limit(1);
    const current = rows[0];
    if (!current) throw new AdminError('membership not found', 'not_found');
    // An owner may only be demoted by another owner.
    if (current.role === 'owner' && newRole !== 'owner' && actorRole !== 'owner') {
      throw new AdminError('only an owner may demote an owner', 'owner_demotion');
    }
    await tx.update(memberships).set({ role: newRole }).where(eq(memberships.userId, targetUserId));
    await tx.insert(auditLog).values({
      orgId: ctx.orgId,
      actorUserId: ctx.userId,
      action: 'user.role_changed',
      targetType: 'user',
      targetId: targetUserId,
      metadata: { from: current.role, to: newRole },
    });
  });
}

export async function deactivateUser(
  db: AppDatabase,
  ctx: TenantContext,
  targetUserId: string,
): Promise<void> {
  if (targetUserId === ctx.userId) throw new AdminError('cannot deactivate your own account', 'self_deactivate');
  await db.update(users).set({ status: 'inactive' }).where(eq(users.id, targetUserId));
  // Revoke all sessions for the user (sessions are not RLS-scoped).
  await db.update(sessions).set({ revokedAt: new Date() }).where(eq(sessions.userId, targetUserId));
  await withTenantContext(db, ctx, async (tx) => {
    await tx.insert(auditLog).values({
      orgId: ctx.orgId,
      actorUserId: ctx.userId,
      action: 'user.deactivated',
      targetType: 'user',
      targetId: targetUserId,
    });
  });
}

export interface UserActivity {
  queries: number;
  uploads: number;
  logins: number;
  auditEvents: number;
}

export function userActivity(db: AppDatabase, ctx: TenantContext, targetUserId: string): Promise<UserActivity> {
  const sinceIso = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
  return withTenantContext(db, ctx, async (tx) => {
    const rows = (await tx.execute(sql`
      SELECT
        (SELECT count(*) FROM document_access_log WHERE user_id = ${targetUserId}::uuid AND action = 'QUERY' AND created_at >= ${sinceIso}) AS queries,
        (SELECT count(*) FROM document_access_log WHERE user_id = ${targetUserId}::uuid AND action = 'UPLOAD' AND created_at >= ${sinceIso}) AS uploads,
        (SELECT count(*) FROM sessions WHERE user_id = ${targetUserId}::uuid AND created_at >= ${sinceIso}) AS logins,
        (SELECT count(*) FROM audit_log WHERE actor_user_id = ${targetUserId}::uuid AND org_id = ${ctx.orgId}::uuid AND created_at >= ${sinceIso}) AS audit_events
    `)) as unknown as { queries: number; uploads: number; logins: number; audit_events: number }[];
    const r = rows[0] ?? { queries: 0, uploads: 0, logins: 0, audit_events: 0 };
    return { queries: Number(r.queries), uploads: Number(r.uploads), logins: Number(r.logins), auditEvents: Number(r.audit_events) };
  });
}
