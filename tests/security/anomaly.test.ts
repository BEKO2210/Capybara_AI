import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { sql } from 'drizzle-orm';
import { startTestDb, type TestDb } from '../setup/testDb.js';
import { appendSecurityEvent } from '../../src/audit/securityLog.js';
import { verifyChain } from '../../src/audit/verifyChain.js';
import { detectAnomalies } from '../../src/security/anomaly.js';

let t: TestDb;
beforeAll(async () => { t = await startTestDb(); }, 120_000);
afterAll(async () => { await t?.stop(); });

describe('security — anomaly detection over the audit stream', () => {
  it('does not flag normal activity', async () => {
    await appendSecurityEvent(t.app.db, { orgId: null, eventType: 'auth.account_locked', severity: 'warning', payload: {} });
    const found = await detectAnomalies(t.app.db, { thresholds: { authLockouts: 5 } });
    expect(found).toEqual([]);
  });

  it('raises a tamper-evident anomaly when a lockout burst exceeds the threshold', async () => {
    for (let i = 0; i < 6; i++) {
      await appendSecurityEvent(t.app.db, { orgId: null, eventType: 'auth.account_locked', severity: 'warning', payload: { i } });
    }
    const notified: string[] = [];
    const found = await detectAnomalies(t.app.db, { thresholds: { authLockouts: 5 }, notify: (a) => { notified.push(a.kind); } });
    expect(found.map((a) => a.kind)).toContain('auth_lockout_burst');
    expect(notified).toContain('auth_lockout_burst');

    const events = await t.app.sql<{ n: number }[]>`SELECT count(*)::int AS n FROM security_events WHERE event_type = 'security.anomaly'`;
    expect(Number(events[0]?.n)).toBeGreaterThan(0);
    expect((await verifyChain(t.app.db)).ok).toBe(true);
  });

  it('de-duplicates: a second pass in the same window raises nothing new', async () => {
    const found = await detectAnomalies(t.app.db, { thresholds: { authLockouts: 5 } });
    expect(found).toEqual([]);
  });

  it('detects a privilege-change burst from the audit log', async () => {
    for (let i = 0; i < 6; i++) {
      await t.app.db.execute(sql`INSERT INTO audit_log (action, target_type, created_at) VALUES ('user.role_changed', 'user', now())`);
    }
    const found = await detectAnomalies(t.app.db, { thresholds: { roleChanges: 5 } });
    expect(found.map((a) => a.kind)).toContain('privilege_change_burst');
  });
});
