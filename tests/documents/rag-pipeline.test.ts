import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { and, eq, sql } from 'drizzle-orm';
import * as XLSX from 'xlsx';
import { PDFDocument } from 'pdf-lib';
import { Document, Packer, Paragraph } from 'docx';
import { startTestDb, type TestDb } from '../setup/testDb.js';
import { documentChunks, documentAccessLog } from '../../src/db/schema/index.js';
import { withTenantContext } from '../../src/tenancy/scope.js';
import { decryptSecret, deriveTenantKey } from '../../src/lib/crypto.js';
import { ingestDocument, type IngestDeps } from '../../src/documents/ingest.js';
import { searchDocuments, type SearchDeps } from '../../src/documents/search.js';
import { hashQuery } from '../../src/documents/accessLog.js';
import { bowEmbedder, seedOrgUser, seedMember, tmpStorageDir, MASTER_KEY, type SeededPrincipal } from './helpers.js';

let t: TestDb;
let deps: IngestDeps & SearchDeps;
let orgAOwner: SeededPrincipal;
let orgAMember: SeededPrincipal;
let orgBOwner: SeededPrincipal;

async function pdfBuffer(text: string): Promise<Buffer> {
  const doc = await PDFDocument.create();
  doc.addPage().drawText(text, { x: 50, y: 700, size: 14 });
  return Buffer.from(await doc.save());
}
async function docxBuffer(text: string): Promise<Buffer> {
  const d = new Document({ sections: [{ children: [new Paragraph(text)] }] });
  return Packer.toBuffer(d);
}
function xlsxBuffer(rows: string[][]): Buffer {
  const ws = XLSX.utils.aoa_to_sheet(rows);
  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, ws, 'Sheet1');
  return XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' }) as Buffer;
}

beforeAll(async () => {
  t = await startTestDb();
  const storageDir = await tmpStorageDir();
  deps = { db: t.app.db, embedder: bowEmbedder(), storageDir, masterKey: MASTER_KEY };
  orgAOwner = await seedOrgUser(t.admin.db, { slug: 'org-a', email: 'owner-a@example.com', role: 'owner' });
  orgAMember = await seedMember(t.admin.db, orgAOwner.orgId, { email: 'member-a@example.com', role: 'member' });
  orgBOwner = await seedOrgUser(t.admin.db, { slug: 'org-b', email: 'owner-b@example.com', role: 'owner' });
}, 180_000);

afterAll(async () => {
  await t?.stop();
});

describe('documents — ingestion across formats', () => {
  it('ingests TXT, MD, XLSX, PDF and DOCX into chunks', async () => {
    const long = 'quarterly finance report revenue growth margins forecast '.repeat(40);
    const cases: Array<{ mime: string; data: Buffer; title: string }> = [
      { mime: 'text/plain', data: Buffer.from(long), title: 'txt-doc' },
      { mime: 'text/markdown', data: Buffer.from(`# Heading\n\n${long}`), title: 'md-doc' },
      { mime: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', data: xlsxBuffer([['finance', 'revenue'], ['q1', '100']]), title: 'xlsx-doc' },
      { mime: 'application/pdf', data: await pdfBuffer('finance report revenue growth ' + long.slice(0, 200)), title: 'pdf-doc' },
      { mime: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', data: await docxBuffer(long), title: 'docx-doc' },
    ];
    for (const c of cases) {
      const res = await ingestDocument(deps, {
        orgId: orgAOwner.orgId, userId: orgAOwner.userId, clearance: orgAOwner.clearance,
        title: c.title, mimeType: c.mime, classification: 'INTERNAL', data: c.data,
      });
      expect(res.chunkCount, c.title).toBeGreaterThan(0);
    }
  });

  it('rejects a disallowed MIME type (fail-closed)', async () => {
    await expect(
      ingestDocument(deps, {
        orgId: orgAOwner.orgId, userId: orgAOwner.userId, clearance: orgAOwner.clearance,
        title: 'evil', mimeType: 'application/x-msdownload', classification: 'INTERNAL', data: Buffer.from('MZ...'),
      }),
    ).rejects.toThrow(/unsupported MIME/);
  });

  it('stores chunk content encrypted (raw DB value is not plaintext)', async () => {
    const secretText = 'PLAINTEXTNEEDLE alpha bravo charlie '.repeat(30);
    const { documentId } = await ingestDocument(deps, {
      orgId: orgAOwner.orgId, userId: orgAOwner.userId, clearance: orgAOwner.clearance,
      title: 'enc-check', mimeType: 'text/plain', classification: 'INTERNAL', data: Buffer.from(secretText),
    });
    // Read raw ciphertext as the superuser (bypasses RLS) to inspect at rest.
    const rows = await t.admin.db.select().from(documentChunks).where(eq(documentChunks.documentId, documentId)).limit(1);
    const raw = rows[0]!.contentEncrypted;
    expect(raw).not.toContain('PLAINTEXTNEEDLE');
    // …but it decrypts with the tenant key.
    const decrypted = decryptSecret(raw, deriveTenantKey(MASTER_KEY, orgAOwner.orgId));
    expect(decrypted).toContain('PLAINTEXTNEEDLE');
  });
});

describe('documents — ACL-enforced vector search', () => {
  beforeAll(async () => {
    await ingestDocument(deps, {
      orgId: orgAOwner.orgId, userId: orgAOwner.userId, clearance: orgAOwner.clearance,
      title: 'public-cats', mimeType: 'text/plain', classification: 'PUBLIC',
      data: Buffer.from('cats kittens feline whiskers purr '.repeat(20)),
    });
    await ingestDocument(deps, {
      orgId: orgAOwner.orgId, userId: orgAOwner.userId, clearance: orgAOwner.clearance,
      title: 'confidential-finance', mimeType: 'text/plain', classification: 'CONFIDENTIAL',
      data: Buffer.from('confidential salary payroll compensation figures '.repeat(20)),
    });
    await ingestDocument(deps, {
      orgId: orgBOwner.orgId, userId: orgBOwner.userId, clearance: orgBOwner.clearance,
      title: 'tenant-b-widgets', mimeType: 'text/plain', classification: 'PUBLIC',
      data: Buffer.from('widgets gadgets sprockets cats '.repeat(20)),
    });
  }, 60_000);

  it('returns relevant chunks with a similarity score', async () => {
    const results = await searchDocuments(deps, {
      query: 'cats kittens', orgId: orgAOwner.orgId, userId: orgAOwner.userId, clearance: orgAOwner.clearance,
    });
    expect(results.length).toBeGreaterThan(0);
    expect(results.some((r) => r.documentTitle === 'public-cats')).toBe(true);
    expect(typeof results[0]!.similarity).toBe('number');
  });

  it('does NOT return CONFIDENTIAL chunks to a member-level user (app layer)', async () => {
    const results = await searchDocuments(deps, {
      query: 'confidential salary payroll', orgId: orgAMember.orgId, userId: orgAMember.userId, clearance: orgAMember.clearance,
    });
    expect(results.every((r) => r.classification !== 'CONFIDENTIAL' && r.classification !== 'SECRET')).toBe(true);
  });

  it('blocks CONFIDENTIAL at the Postgres RLS layer (direct query)', async () => {
    // As the app role with member clearance (1): RLS must hide CONFIDENTIAL rows.
    const hiddenAtMember = await withTenantContext(
      t.app.db,
      { orgId: orgAOwner.orgId, userId: orgAMember.userId, clearance: 1 },
      async (tx) => tx.select().from(documentChunks).where(eq(documentChunks.classification, 'CONFIDENTIAL')),
    );
    expect(hiddenAtMember).toHaveLength(0);
    // With owner clearance (3) the same rows are visible — proving the gate is real.
    const visibleAtOwner = await withTenantContext(
      t.app.db,
      { orgId: orgAOwner.orgId, userId: orgAOwner.userId, clearance: 3 },
      async (tx) => tx.select().from(documentChunks).where(eq(documentChunks.classification, 'CONFIDENTIAL')),
    );
    expect(visibleAtOwner.length).toBeGreaterThan(0);
  });

  it('returns 0 cross-tenant results', async () => {
    const results = await searchDocuments(deps, {
      query: 'cats kittens payroll', orgId: orgBOwner.orgId, userId: orgBOwner.userId, clearance: orgBOwner.clearance,
    });
    // Org B can only ever see its own documents.
    expect(results.every((r) => r.documentTitle === 'tenant-b-widgets')).toBe(true);
  });

  it('logs the QUERY action with a hash of the query, never plaintext', async () => {
    const query = 'a-very-unique-query-string-12345';
    await searchDocuments(deps, { query, orgId: orgAOwner.orgId, userId: orgAOwner.userId, clearance: orgAOwner.clearance });
    const rows = await t.admin.db
      .select()
      .from(documentAccessLog)
      .where(and(eq(documentAccessLog.action, 'QUERY'), eq(documentAccessLog.queryTextHash, hashQuery(query))));
    expect(rows.length).toBeGreaterThan(0);
    // The plaintext query must not appear anywhere in the stored row.
    expect(JSON.stringify(rows[0])).not.toContain(query);
  });
});

describe('documents — access log is append-only at the DB layer', () => {
  it('grants the app role INSERT/SELECT but NOT UPDATE/DELETE', async () => {
    const rows = await t.app.sql<{ privilege_type: string }[]>`
      SELECT privilege_type FROM information_schema.role_table_grants
      WHERE table_name = 'document_access_log' AND grantee = 'capybara_app'
    `;
    const privs = new Set(rows.map((r) => r.privilege_type));
    expect(privs.has('SELECT')).toBe(true);
    expect(privs.has('INSERT')).toBe(true);
    expect(privs.has('UPDATE')).toBe(false);
    expect(privs.has('DELETE')).toBe(false);
  });
});
