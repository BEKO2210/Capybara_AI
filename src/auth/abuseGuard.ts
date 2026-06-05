import { eq } from 'drizzle-orm';
import type { AppDatabase } from '../db/client.js';
import { authLockouts } from '../db/schema/index.js';
import { appendSecurityEvent } from '../audit/securityLog.js';

/**
 * Brute-force / credential-stuffing defense for login.
 *
 * Strategy: a sliding failure window per identifier (normalized email). Once
 * `maxFailures` accrue inside `windowMs`, the account is locked for an
 * exponentially-growing duration (`lockBaseMs * 2^n`, capped at `lockMaxMs`),
 * where `n` is the number of prior locks. Successful auth clears all state.
 *
 * Login is pre-tenant, so lock state is GLOBAL (keyed by email) and lock events
 * are recorded in the tamper-evident security log with a null org.
 */

export interface LockoutPolicy {
  /** Failures within the window before the account locks. */
  readonly maxFailures: number;
  /** Sliding window (ms) over which failures are counted. */
  readonly windowMs: number;
  /** Base lock duration (ms) for the first lock. */
  readonly lockBaseMs: number;
  /** Maximum lock duration (ms); the exponential backoff is capped here. */
  readonly lockMaxMs: number;
}

export const DEFAULT_LOCKOUT_POLICY: LockoutPolicy = {
  maxFailures: 10,
  windowMs: 15 * 60_000,
  lockBaseMs: 15 * 60_000,
  lockMaxMs: 24 * 60 * 60_000,
};

export interface LockoutStatus {
  /** True if the account is currently locked. */
  readonly locked: boolean;
  /** Milliseconds until the lock lifts (0 when not locked). */
  readonly retryAfterMs: number;
}

const UNLOCKED: LockoutStatus = { locked: false, retryAfterMs: 0 };

function normalize(identifier: string): string {
  return identifier.trim().toLowerCase();
}

/**
 * Non-mutating check used as a pre-auth gate. Returns the current lock status
 * for an identifier without recording anything.
 */
export async function checkLockout(
  db: AppDatabase,
  identifierRaw: string,
): Promise<LockoutStatus> {
  const identifier = normalize(identifierRaw);
  const rows = await db
    .select({ lockedUntil: authLockouts.lockedUntil })
    .from(authLockouts)
    .where(eq(authLockouts.identifier, identifier))
    .limit(1);
  const lockedUntil = rows[0]?.lockedUntil;
  if (!lockedUntil) return UNLOCKED;
  const remaining = lockedUntil.getTime() - Date.now();
  return remaining > 0 ? { locked: true, retryAfterMs: remaining } : UNLOCKED;
}

/**
 * Record a failed authentication attempt. Returns the resulting lock status —
 * `locked: true` means this failure tripped (or extended) a lock. Emits a
 * `auth.account_locked` security event when a new lock is applied.
 */
export async function recordFailure(
  db: AppDatabase,
  identifierRaw: string,
  policy: LockoutPolicy = DEFAULT_LOCKOUT_POLICY,
): Promise<LockoutStatus> {
  const identifier = normalize(identifierRaw);
  const now = Date.now();
  const nowDate = new Date(now);

  const rows = await db.select().from(authLockouts).where(eq(authLockouts.identifier, identifier)).limit(1);
  const existing = rows[0];

  if (!existing) {
    await db.insert(authLockouts).values({ identifier, failedCount: 1, firstFailedAt: nowDate, lastFailedAt: nowDate });
    return UNLOCKED;
  }

  // Already locked and the lock is still in force: keep it, just note the hit.
  if (existing.lockedUntil && existing.lockedUntil.getTime() > now) {
    await db.update(authLockouts).set({ lastFailedAt: nowDate, updatedAt: nowDate }).where(eq(authLockouts.identifier, identifier));
    return { locked: true, retryAfterMs: existing.lockedUntil.getTime() - now };
  }

  // Reset the counter if the sliding window has elapsed since the first failure.
  const windowElapsed = now - existing.firstFailedAt.getTime() > policy.windowMs;
  let failedCount = windowElapsed ? 1 : existing.failedCount + 1;
  let firstFailedAt = windowElapsed ? nowDate : existing.firstFailedAt;
  let lockoutCount = existing.lockoutCount;
  let lockedUntil: Date | null = null;

  if (failedCount >= policy.maxFailures) {
    const lockMs = Math.min(policy.lockBaseMs * 2 ** lockoutCount, policy.lockMaxMs);
    lockedUntil = new Date(now + lockMs);
    lockoutCount += 1;
    // Start a fresh window after the lock so backoff applies to the next burst.
    failedCount = 0;
    firstFailedAt = nowDate;
  }

  await db
    .update(authLockouts)
    .set({ failedCount, lockoutCount, firstFailedAt, lastFailedAt: nowDate, lockedUntil, updatedAt: nowDate })
    .where(eq(authLockouts.identifier, identifier));

  if (lockedUntil) {
    await appendSecurityEvent(db, {
      orgId: null,
      eventType: 'auth.account_locked',
      severity: 'warning',
      payload: { identifier, lockoutCount, lockedUntilMs: lockedUntil.getTime() },
    });
    return { locked: true, retryAfterMs: lockedUntil.getTime() - now };
  }
  return UNLOCKED;
}

/** Clear all lockout state after a successful authentication. */
export async function recordSuccess(db: AppDatabase, identifierRaw: string): Promise<void> {
  await db.delete(authLockouts).where(eq(authLockouts.identifier, normalize(identifierRaw)));
}

/**
 * Administratively clear a lockout. Returns true if a lock row was removed.
 * Caller is responsible for authorization + business-level audit.
 */
export async function clearLockout(db: AppDatabase, identifierRaw: string): Promise<boolean> {
  const identifier = normalize(identifierRaw);
  const deleted = await db
    .delete(authLockouts)
    .where(eq(authLockouts.identifier, identifier))
    .returning({ identifier: authLockouts.identifier });
  return deleted.length > 0;
}
