import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { startTestDb, type TestDb } from '../setup/testDb.js';
import { documents } from '../../src/db/schema/index.js';
import { getStorageUsage, enforceStorageQuota, QuotaExceededError } from '../../src/admin/storageQuota.js';
import { seedOrgUser, type SeededPrincipal } from '../documents/helpers.js';

let t: TestDb;
let org: SeededPrincipal;
let other: SeededPrincipal;
const ctx = () => ({ orgId: org.orgId, userId: org.userId, clearance: 3 });

beforeAll(async () => {
  t = await startTestDb();
  org = await seedOrgUser(t.admin.db, { slug: 'quota-org', email: 'q@example.com', role: 'owner' });
  other = await seedOrgUser(t.admin.db, { slug: 'quota-other', email: 'o@example.com', role: 'owner' });

  // 100 + 200 bytes for our org; 1000 bytes for a different org (must not count).
  await t.admin.db.insert(documents).values({ orgId: org.orgId, uploadedBy: org.userId, title: 'a', mimeType: 'text/plain', storagePath: 'a', sizeBytes: 100, classification: 'INTERNAL' });
  await t.admin.db.insert(documents).values({ orgId: org.orgId, uploadedBy: org.userId, title: 'b', mimeType: 'text/plain', storagePath: 'b', sizeBytes: 200, classification: 'INTERNAL' });
  await t.admin.db.insert(documents).values({ orgId: other.orgId, uploadedBy: other.userId, title: 'c', mimeType: 'text/plain', storagePath: 'c', sizeBytes: 1000, classification: 'INTERNAL' });
  // A soft-deleted doc must be excluded from usage.
  await t.admin.db.insert(documents).values({ orgId: org.orgId, uploadedBy: org.userId, title: 'd', mimeType: 'text/plain', storagePath: 'd', sizeBytes: 500, classification: 'INTERNAL', deletedAt: new Date() });
}, 180_000);

afterAll(async () => { await t?.stop(); });

describe('storage quota — per-organization, tenant-scoped', () => {
  it('sums only the org\'s non-deleted documents', async () => {
    expect(await getStorageUsage(t.app.db, ctx())).toBe(300);
  });

  it('allows an upload that stays within quota and reports remaining', async () => {
    const status = await enforceStorageQuota(t.app.db, ctx(), 100, 1000);
    expect(status.usedBytes).toBe(400);
    expect(status.remainingBytes).toBe(600);
  });

  it('rejects an upload that would exceed quota', async () => {
    await expect(enforceStorageQuota(t.app.db, ctx(), 800, 1000)).rejects.toBeInstanceOf(QuotaExceededError);
    try {
      await enforceStorageQuota(t.app.db, ctx(), 800, 1000);
    } catch (e) {
      const q = e as QuotaExceededError;
      expect(q.usedBytes).toBe(300);
      expect(q.limitBytes).toBe(1000);
      expect(q.attemptedBytes).toBe(800);
    }
  });
});
