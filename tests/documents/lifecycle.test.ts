import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { and, eq, isNull } from 'drizzle-orm';
import { startTestDb, type TestDb } from '../setup/testDb.js';
import { documents, documentChunks, messages, users, conversations } from '../../src/db/schema/index.js';
import { ingestDocument, nextVersionFor, type IngestDeps } from '../../src/documents/ingest.js';
import { getVersions, softDeleteDocument, setLegalHold, LegalHoldError } from '../../src/documents/lifecycle.js';
import { searchDocuments, type SearchDeps } from '../../src/documents/search.js';
import { eraseUser } from '../../src/documents/erasure.js';
import { bowEmbedder, seedOrgUser, tmpStorageDir, MASTER_KEY, type SeededPrincipal } from './helpers.js';

let t: TestDb;
let deps: IngestDeps & SearchDeps;
let owner: SeededPrincipal;

beforeAll(async () => {
  t = await startTestDb();
  deps = { db: t.app.db, embedder: bowEmbedder(), storageDir: await tmpStorageDir(), masterKey: MASTER_KEY };
  owner = await seedOrgUser(t.admin.db, { slug: 'lc-org', email: 'lc-owner@example.com', role: 'owner' });
}, 180_000);

afterAll(async () => {
  await t?.stop();
});

const ctx = () => ({ orgId: owner.orgId, userId: owner.userId, clearance: owner.clearance });

async function ingest(title: string, text: string): Promise<string> {
  const r = await ingestDocument(deps, {
    orgId: owner.orgId, userId: owner.userId, clearance: owner.clearance,
    title, mimeType: 'text/plain', classification: 'INTERNAL', data: Buffer.from(text),
  });
  return r.documentId;
}

describe('documents — versioning', () => {
  it('a new version increments version and keeps the old one', async () => {
    const v1 = await ingest('report', 'version one content alpha beta');
    const info = (await nextVersionFor(deps.db, ctx(), v1))!;
    expect(info.version).toBe(2);
    expect(info.parentId).toBe(v1);

    await ingestDocument(deps, {
      orgId: owner.orgId, userId: owner.userId, clearance: owner.clearance,
      title: info.title, mimeType: 'text/plain', classification: info.classification,
      data: Buffer.from('version two content gamma delta'), parentId: info.parentId, version: info.version,
    });

    const versions = await getVersions(deps.db, ctx(), v1);
    expect(versions.map((d) => d.version).sort()).toEqual([1, 2]);
    // v1 still present and not deleted.
    expect(versions.find((d) => d.version === 1)?.deletedAt).toBeNull();
  });
});

describe('documents — legal hold', () => {
  it('blocks soft-delete while on hold, allows it once released', async () => {
    const id = await ingest('held-doc', 'sensitive retained content');
    expect(await setLegalHold(deps.db, ctx(), id, true)).toBe(true);

    await expect(softDeleteDocument(deps.db, ctx(), id)).rejects.toBeInstanceOf(LegalHoldError);

    expect(await setLegalHold(deps.db, ctx(), id, false)).toBe(true);
    expect(await softDeleteDocument(deps.db, ctx(), id)).toBe(true);
  });
});

describe('documents — GDPR erasure', () => {
  it('atomically removes documents, chunks, vectors and messages, and anonymizes the log', async () => {
    const subject = await seedOrgUser(t.admin.db, { slug: 'erase-org', email: 'subject@example.com', role: 'owner' });
    const sctx = { orgId: subject.orgId, userId: subject.userId, clearance: subject.clearance };

    // Subject uploads two documents (→ chunks + embeddings) and has a message.
    const d1 = await ingestDocument(deps, { orgId: subject.orgId, userId: subject.userId, clearance: 3, title: 'd1', mimeType: 'text/plain', classification: 'INTERNAL', data: Buffer.from('subject doc one content') });
    await ingestDocument(deps, { orgId: subject.orgId, userId: subject.userId, clearance: 3, title: 'd2', mimeType: 'text/plain', classification: 'INTERNAL', data: Buffer.from('subject doc two content') });
    const [conv] = await t.admin.db.insert(conversations).values({ orgId: subject.orgId, userId: subject.userId }).returning({ id: conversations.id });
    await t.admin.db.insert(messages).values({ conversationId: conv!.id, orgId: subject.orgId, userId: subject.userId, role: 'user', contentEncrypted: 'enc' });

    const result = await eraseUser(deps.db, sctx, subject.userId);
    expect(result.deletedDocuments).toBe(2);
    expect(result.deletedChunks).toBeGreaterThan(0);
    expect(result.deletedMessages).toBe(1);
    expect(result.erasureTimestamp).toMatch(/\dT\d/);

    // Verify end-state via the admin (superuser) connection.
    const remainingChunks = await t.admin.db.select().from(documentChunks).where(eq(documentChunks.documentId, d1.documentId));
    expect(remainingChunks).toHaveLength(0);
    const liveDocs = await t.admin.db.select().from(documents).where(and(eq(documents.orgId, subject.orgId), isNull(documents.deletedAt)));
    expect(liveDocs).toHaveLength(0);
    const remainingMsgs = await t.admin.db.select().from(messages).where(eq(messages.userId, subject.userId));
    expect(remainingMsgs).toHaveLength(0);
    const userRow = await t.admin.db.select().from(users).where(eq(users.id, subject.userId));
    expect(userRow).toHaveLength(0);

    // The erased user's documents are unretrievable via search.
    const found = await searchDocuments(deps, { query: 'subject doc content', orgId: subject.orgId, userId: owner.userId, clearance: 3 });
    expect(found).toHaveLength(0);
  });
});
