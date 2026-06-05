import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { randomBytes } from 'node:crypto';
import { eq } from 'drizzle-orm';
import { startTestDb, type TestDb } from '../setup/testDb.js';
import { documents, documentChunks, conversations, messages, encryptionKeyVersions } from '../../src/db/schema/index.js';
import { encryptSecret, decryptSecret, deriveTenantKey } from '../../src/lib/crypto.js';
import { ensureKeyVersion, rotateKey, getActiveDek, countKeyVersions } from '../../src/admin/encryption.js';
import { verifyChain } from '../../src/audit/verifyChain.js';
import { loadConfig, ConfigError } from '../../src/config/index.js';
import { seedOrgUser, type SeededPrincipal } from '../documents/helpers.js';

const DOC_MASTER = randomBytes(32);
const KEK = randomBytes(32);

let t: TestDb;
let org: SeededPrincipal;
let legacyDek: Buffer;
const ctx = () => ({ orgId: org.orgId, userId: org.userId, clearance: 3 });

beforeAll(async () => {
  t = await startTestDb();
  org = await seedOrgUser(t.admin.db, { slug: 'enc-org', email: 'enc@example.com', role: 'owner' });
  legacyDek = deriveTenantKey(DOC_MASTER, org.orgId);

  const [doc] = await t.admin.db.insert(documents).values({ orgId: org.orgId, uploadedBy: org.userId, title: 'd', mimeType: 'text/plain', storagePath: 'x', sizeBytes: 1, classification: 'INTERNAL' }).returning({ id: documents.id });
  for (let i = 0; i < 2; i++) {
    await t.admin.db.insert(documentChunks).values({ orgId: org.orgId, documentId: doc!.id, chunkIndex: i, contentEncrypted: encryptSecret(`chunk ${i}`, legacyDek), embedding: new Array(768).fill(0), classification: 'INTERNAL', tokenCount: 3 });
  }
  const [conv] = await t.admin.db.insert(conversations).values({ orgId: org.orgId, userId: org.userId }).returning({ id: conversations.id });
  for (let i = 0; i < 2; i++) {
    await t.admin.db.insert(messages).values({ conversationId: conv!.id, orgId: org.orgId, userId: org.userId, role: 'user', contentEncrypted: encryptSecret(`message ${i}`, legacyDek) });
  }
}, 180_000);

afterAll(async () => { await t?.stop(); });

describe('encryption — key rotation', () => {
  it('re-encrypts all chunks + messages and keeps data readable under the new key', async () => {
    await ensureKeyVersion(t.app.db, ctx(), KEK, legacyDek);
    const result = await rotateKey(t.app.db, ctx(), KEK);
    expect(result.rotated).toBe(4); // 2 chunks + 2 messages
    expect(result.newKeyVersion).toBe(2);
    expect(result.durationMs).toBeGreaterThanOrEqual(0);

    const newDek = (await getActiveDek(t.app.db, ctx(), KEK))!;
    const chunk = (await t.admin.db.select().from(documentChunks).limit(1))[0]!;
    expect(decryptSecret(chunk.contentEncrypted, newDek)).toMatch(/^chunk /);
    // The old key no longer decrypts the re-encrypted data.
    expect(() => decryptSecret(chunk.contentEncrypted, legacyDek)).toThrow();
  });

  it('retains the old key version (not deleted), marked inactive', async () => {
    expect(await countKeyVersions(t.app.db, ctx())).toBe(2);
    const v1 = (await t.admin.db.select().from(encryptionKeyVersions).where(eq(encryptionKeyVersions.keyVersion, 1)))[0];
    expect(v1?.active).toBe(false);
    expect(v1?.retiredAt).not.toBeNull();
  });

  it('records the rotation in the tamper-evident audit log', async () => {
    const events = await t.app.sql<{ event_type: string }[]>`SELECT event_type FROM security_events WHERE event_type = 'encryption.rotated'`;
    expect(events.length).toBeGreaterThan(0);
    expect((await verifyChain(t.app.db)).ok).toBe(true);
  });

  it('migration is idempotent (running ensureKeyVersion twice yields one version)', async () => {
    const fresh = await seedOrgUser(t.admin.db, { slug: 'enc-fresh', email: 'enc2@example.com', role: 'owner' });
    const fctx = { orgId: fresh.orgId, userId: fresh.userId, clearance: 3 };
    const fdek = deriveTenantKey(DOC_MASTER, fresh.orgId);
    await ensureKeyVersion(t.app.db, fctx, KEK, fdek);
    await ensureKeyVersion(t.app.db, fctx, KEK, fdek);
    expect(await countKeyVersions(t.app.db, fctx)).toBe(1);
  });

  it('production refuses to start without MASTER_KEK', () => {
    expect(() => loadConfig({
      APP_ENV: 'production',
      DATABASE_URL: 'postgresql://u:p2word@db.internal:5432/c?sslmode=require',
      COOKIE_SECRET: 'Zk7Q2pXwL4mN8vR1tB6yH3sC0gJ-aE_uIoPqW5n',
      SESSION_SECRET: 'Hb9Fz2Lm6Qx4Rv8Tn1Yc3Sd0Gj7Aw5Pk-Ue_IoLr',
      CORS_ALLOWED_ORIGINS: 'https://app.acme-corp.io',
      APP_BASE_URL: 'https://app.acme-corp.io',
      ENCRYPTION_KEY: Buffer.alloc(32, 1).toString('hex'),
      DOCUMENT_ENCRYPTION_KEY: Buffer.alloc(32, 2).toString('hex'),
      OLLAMA_BASE_URL: 'http://ollama:11434',
      // MASTER_KEK intentionally omitted
    })).toThrow(ConfigError);
  });
});
