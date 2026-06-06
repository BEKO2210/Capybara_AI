import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { randomBytes } from 'node:crypto';
import { startTestDb, type TestDb } from '../setup/testDb.js';
import { DbOversightGate, type OversightNotifier } from '../../src/compliance/oversight.js';
import { seedOrgUser, type SeededPrincipal } from '../documents/helpers.js';

let t: TestDb;
let org: SeededPrincipal;
const MASTER = randomBytes(32);

beforeAll(async () => {
  t = await startTestDb();
  org = await seedOrgUser(t.admin.db, { slug: 'ov-notify', email: 'ov@example.com', role: 'owner' });
}, 120_000);
afterAll(async () => { await t?.stop(); });

describe('oversight — notification seam on new request', () => {
  it('fires the notifier exactly once when a new pending request is created', async () => {
    const calls: Array<{ toolName: string; riskLevel: string }> = [];
    const notify: OversightNotifier = (info) => { calls.push({ toolName: info.toolName, riskLevel: info.riskLevel }); };
    const ctx = { orgId: org.orgId, userId: org.userId, clearance: 3 };
    const gate = new DbOversightGate(t.app.db, ctx, MASTER, notify);

    const first = await gate.check('delete_database', { confirm: true }, 'CRITICAL');
    expect(first.approved).toBe(false);
    expect(calls).toEqual([{ toolName: 'delete_database', riskLevel: 'CRITICAL' }]);

    // Re-checking the same invocation reuses the PENDING request — no duplicate notification.
    const again = await gate.check('delete_database', { confirm: true }, 'CRITICAL');
    expect(again.requestId).toBe(first.requestId);
    expect(calls).toHaveLength(1);
  });
});
