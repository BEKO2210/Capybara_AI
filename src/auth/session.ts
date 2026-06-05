import { randomBytes, createHash } from 'node:crypto';
import { and, eq, gt, isNull } from 'drizzle-orm';
import type { AppDatabase } from '../db/client.js';
import { sessions, users } from '../db/schema/index.js';

/**
 * Opaque, server-side sessions. The raw token is returned to the caller ONCE
 * (to set in a cookie); only its SHA-256 hash is persisted, so a database leak
 * does not expose usable tokens. Validation re-checks the user still exists
 * (orphan-session defense) and that the session is neither expired nor revoked.
 */

const DEFAULT_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

export function generateSessionToken(): string {
  return randomBytes(32).toString('base64url');
}

export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

export interface CreatedSession {
  readonly token: string; // raw token — return to client once, never stored
  readonly sessionId: string;
  readonly expiresAt: Date;
}

export async function createSession(
  db: AppDatabase,
  params: { userId: string; orgId?: string | undefined; ttlMs?: number | undefined },
): Promise<CreatedSession> {
  const token = generateSessionToken();
  const expiresAt = new Date(Date.now() + (params.ttlMs ?? DEFAULT_TTL_MS));
  const [row] = await db
    .insert(sessions)
    .values({
      tokenHash: hashToken(token),
      userId: params.userId,
      orgId: params.orgId ?? null,
      expiresAt,
    })
    .returning({ id: sessions.id });
  if (!row) throw new Error('failed to create session');
  return { token, sessionId: row.id, expiresAt };
}

export interface ValidatedSession {
  readonly sessionId: string;
  readonly userId: string;
  readonly email: string;
  readonly orgId: string | null;
}

/** Validate a raw session token. Returns null on any failure (fail-closed). */
export async function validateSession(
  db: AppDatabase,
  token: string,
): Promise<ValidatedSession | null> {
  if (!token) return null;
  const tokenHash = hashToken(token);
  const rows = await db
    .select({
      sessionId: sessions.id,
      userId: sessions.userId,
      orgId: sessions.orgId,
      email: users.email,
    })
    .from(sessions)
    .innerJoin(users, eq(users.id, sessions.userId))
    .where(
      and(
        eq(sessions.tokenHash, tokenHash),
        isNull(sessions.revokedAt),
        gt(sessions.expiresAt, new Date()),
      ),
    )
    .limit(1);

  const row = rows[0];
  if (!row) return null;
  return {
    sessionId: row.sessionId,
    userId: row.userId,
    email: row.email,
    orgId: row.orgId,
  };
}

/** Revoke a session by raw token (idempotent). */
export async function revokeSession(db: AppDatabase, token: string): Promise<void> {
  await db
    .update(sessions)
    .set({ revokedAt: new Date() })
    .where(eq(sessions.tokenHash, hashToken(token)));
}
