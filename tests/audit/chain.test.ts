import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { eq } from 'drizzle-orm';
import { startTestDb, type TestDb } from '../setup/testDb.js';
import { auditLog, securityEvents } from '../../src/db/schema/index.js';
import { appendSecurityEvent } from '../../src/audit/securityLog.js';
import { verifyChain } from '../../src/audit/verifyChain.js';
import { recordAuditEvent } from '../../src/audit/audit.js';

describe('audit — tamper-evident hash-chained security events', () => {
  let t: TestDb;
  const ids: number[] = [];

  beforeAll(async () => {
    t = await startTestDb();
    // Append a few events via the RESTRICTED app role (append-only at DB layer).
    const e1 = await appendSecurityEvent(t.app.db, {
      eventType: 'auth.login.success',
      severity: 'info',
      payload: { userId: 'u1' },
    });
    const e2 = await appendSecurityEvent(t.app.db, {
      eventType: 'auth.login.failure',
      severity: 'warning',
      payload: { email: 'redacted', attempt: 3 },
    });
    const e3 = await appendSecurityEvent(t.app.db, {
      eventType: 'tool.denied',
      severity: 'critical',
      payload: { tool: 'shell', reason: 'not_allowlisted' },
    });
    ids.push(e1.id, e2.id, e3.id);
  }, 120_000);

  afterAll(async () => {
    await t?.stop();
  });

  it('verifies a well-formed chain (happy path)', async () => {
    const result = await verifyChain(t.app.db);
    expect(result.ok).toBe(true);
    expect(result.length).toBe(3);
  });

  it('records a separate queryable audit entry', async () => {
    await recordAuditEvent(t.app.db, {
      orgId: null,
      actorUserId: null,
      action: 'membership.role.updated',
      targetType: 'membership',
      targetId: 'm1',
      metadata: { from: 'member', to: 'admin' },
    });
    const rows = await t.app.db
      .select()
      .from(auditLog)
      .where(eq(auditLog.action, 'membership.role.updated'));
    expect(rows).toHaveLength(1);
  });

  it('the app role CANNOT mutate the security log (append-only at DB layer)', async () => {
    await expect(
      t.app.sql`UPDATE security_events SET severity = 'info' WHERE id = ${ids[1]!}`,
    ).rejects.toThrow(/permission denied/i);
    await expect(
      t.app.sql`DELETE FROM security_events WHERE id = ${ids[0]!}`,
    ).rejects.toThrow(/permission denied/i);
  });

  it('DETECTS tampering: mutating a row breaks the chain', async () => {
    // Simulate a privileged/DB-level attacker mutating history (only a superuser
    // can, since the app role is append-only).
    await t.admin.sql`
      UPDATE security_events SET payload = '{"tampered":true}'::jsonb WHERE id = ${ids[1]!}
    `;
    const result = await verifyChain(t.app.db);
    expect(result.ok).toBe(false);
    expect(result.brokenAt).toBe(ids[1]);
    expect(result.reason).toBe('hash_mismatch');
  });
});
