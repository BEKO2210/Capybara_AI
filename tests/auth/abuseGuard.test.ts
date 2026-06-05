import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { sql } from 'drizzle-orm';
import { startTestDb, type TestDb } from '../setup/testDb.js';
import { authLockouts } from '../../src/db/schema/index.js';
import {
  checkLockout,
  recordFailure,
  recordSuccess,
  clearLockout,
  type LockoutPolicy,
} from '../../src/auth/abuseGuard.js';
import { verifyChain } from '../../src/audit/verifyChain.js';

// Short, deterministic policy: lock after 3 failures, large window, 10s base lock.
const POLICY: LockoutPolicy = { maxFailures: 3, windowMs: 60_000, lockBaseMs: 10_000, lockMaxMs: 100_000 };

let t: TestDb;
afterAll(async () => { await t?.stop(); });
beforeAll(async () => { t = await startTestDb(); }, 120_000);

async function failN(id: string, n: number) {
  let last = await recordFailure(t.app.db, id, POLICY);
  for (let i = 1; i < n; i++) last = await recordFailure(t.app.db, id, POLICY);
  return last;
}

describe('auth — abuse lockout (brute-force defense)', () => {
  it('does not lock below the failure threshold', async () => {
    const id = 'a@example.com';
    await failN(id, 2);
    expect((await checkLockout(t.app.db, id)).locked).toBe(false);
  });

  it('locks at the threshold and reports retryAfter', async () => {
    const id = 'b@example.com';
    const status = await failN(id, 3);
    expect(status.locked).toBe(true);
    expect(status.retryAfterMs).toBeGreaterThan(0);
    expect(status.retryAfterMs).toBeLessThanOrEqual(POLICY.lockBaseMs);
    const check = await checkLockout(t.app.db, id);
    expect(check.locked).toBe(true);
  });

  it('normalizes the identifier (case/whitespace insensitive)', async () => {
    await failN('Case@Example.com', 3);
    expect((await checkLockout(t.app.db, '  case@example.com ')).locked).toBe(true);
  });

  it('records a tamper-evident security event on lock', async () => {
    const events = await t.app.sql<{ n: number }[]>`
      SELECT count(*)::int AS n FROM security_events WHERE event_type = 'auth.account_locked'`;
    expect(Number(events[0]?.n)).toBeGreaterThan(0);
    expect((await verifyChain(t.app.db)).ok).toBe(true);
  });

  it('clears all state on a successful authentication', async () => {
    const id = 'c@example.com';
    await failN(id, 2);
    await recordSuccess(t.app.db, id);
    const rows = await t.app.db.select().from(authLockouts);
    expect(rows.find((r) => r.identifier === id)).toBeUndefined();
  });

  it('applies exponential backoff to successive locks', async () => {
    const id = 'd@example.com';
    const first = await failN(id, 3);
    expect(first.locked).toBe(true);
    // Force the first lock to expire so the next burst can trigger a second lock.
    await t.app.db
      .update(authLockouts)
      .set({ lockedUntil: new Date(Date.now() - 1000) })
      .where(sql`identifier = ${id}`);
    const second = await failN(id, 3);
    expect(second.locked).toBe(true);
    // Second lock duration ~= 2x the first (base * 2^1).
    expect(second.retryAfterMs).toBeGreaterThan(first.retryAfterMs * 1.5);
  });

  it('admin clearLockout removes the lock', async () => {
    const id = 'e@example.com';
    await failN(id, 3);
    expect((await checkLockout(t.app.db, id)).locked).toBe(true);
    expect(await clearLockout(t.app.db, id)).toBe(true);
    expect((await checkLockout(t.app.db, id)).locked).toBe(false);
    // Clearing an unknown identifier is a no-op returning false.
    expect(await clearLockout(t.app.db, 'nobody@example.com')).toBe(false);
  });
});
