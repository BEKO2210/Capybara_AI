import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { loadConfig } from '../../src/config/index.js';
import { buildServer } from '../../src/server.js';
import { registerDocumentRoutes } from '../../src/http/routes/documents.js';
import { registerRagChatRoute } from '../../src/http/routes/ragChat.js';
import { registerGdprRoutes } from '../../src/http/routes/adminGdpr.js';
import { ingestDocument } from '../../src/documents/ingest.js';
import type { LlmProvider } from '../../src/ai/providers/provider.interface.js';
import type { Role } from '../../src/db/schema/index.js';
import { startTestDb, type TestDb } from '../setup/testDb.js';
import { bowEmbedder, seedOrgUser, tmpStorageDir, MASTER_KEY, type SeededPrincipal } from '../documents/helpers.js';

const MAX_BYTES = 1024 * 1024; // 1 MiB

const fakeProvider: LlmProvider = {
  id: 'test-llm',
  model: 'test-llm',
  chat: async () => ({ content: '', model: 'test-llm' }),
  async *chatStream() {
    await new Promise((r) => setTimeout(r, 2));
    yield { delta: 'Based on the documents, ', done: false };
    yield { delta: 'here is the answer.', done: false };
    yield { delta: '', done: true };
  },
};

let t: TestDb;
let app: FastifyInstance;
let url: string;
let owner: SeededPrincipal;
let emptyOrg: SeededPrincipal;

function authHeaders(p: SeededPrincipal, role: Role = p.role): Record<string, string> {
  return { 'x-test-org': p.orgId, 'x-test-user': p.userId, 'x-test-role': role };
}

beforeAll(async () => {
  t = await startTestDb();
  const storageDir = await tmpStorageDir();
  const embedder = bowEmbedder();
  owner = await seedOrgUser(t.admin.db, { slug: 'http-org', email: 'http-owner@example.com', role: 'owner' });
  emptyOrg = await seedOrgUser(t.admin.db, { slug: 'empty-org', email: 'empty-owner@example.com', role: 'owner' });

  // Seed a retrievable document in the owner's org.
  await ingestDocument(
    { db: t.app.db, embedder, storageDir, masterKey: MASTER_KEY },
    {
      orgId: owner.orgId, userId: owner.userId, clearance: owner.clearance,
      title: 'kb', mimeType: 'text/plain', classification: 'INTERNAL',
      data: Buffer.from('alpha beta gamma knowledge base content '.repeat(20)),
    },
  );

  const config = loadConfig({ APP_ENV: 'test', CORS_ALLOWED_ORIGINS: 'http://localhost', LOG_LEVEL: 'fatal' });
  app = await buildServer({
    config,
    routes: async (instance) => {
      instance.addHook('preHandler', async (req) => {
        const role = req.headers['x-test-role'] as Role | undefined;
        if (role) {
          req.authContext = {
            userId: String(req.headers['x-test-user'] ?? ''),
            email: 'test@example.com',
            orgId: String(req.headers['x-test-org'] ?? ''),
            role,
            sessionId: 's',
          };
        }
      });
      await registerDocumentRoutes(instance, { db: t.app.db, embedder, storageDir, masterKey: MASTER_KEY, maxUploadBytes: MAX_BYTES });
      registerRagChatRoute(instance, {
        searchDeps: { db: t.app.db, embedder, masterKey: MASTER_KEY },
        resolveProvider: (id) => { if (id === 'test-llm') return fakeProvider; throw new Error('unknown'); },
        providerId: 'test-llm',
      });
      registerGdprRoutes(instance, { db: t.app.db });
    },
  });
  url = await app.listen({ host: '127.0.0.1', port: 0 });
}, 180_000);

afterAll(async () => {
  await app?.close();
  await t?.stop();
});

function uploadForm(content: string, type: string, filename: string, classification = 'INTERNAL'): FormData {
  const fd = new FormData();
  fd.append('title', 'My Upload');
  fd.append('classification', classification);
  fd.append('file', new Blob([content], { type }), filename);
  return fd;
}

describe('http — document upload', () => {
  it('uploads and ingests a valid file (201 with chunk count)', async () => {
    const res = await fetch(`${url}/api/documents/upload`, {
      method: 'POST',
      headers: authHeaders(owner),
      body: uploadForm('alpha beta gamma '.repeat(50), 'text/plain', 'doc.txt'),
    });
    expect(res.status).toBe(201);
    const body = (await res.json()) as { documentId: string; chunkCount: number };
    expect(body.documentId).toMatch(/^[0-9a-f-]{36}$/);
    expect(body.chunkCount).toBeGreaterThan(0);
  });

  it('rejects an oversized file (413)', async () => {
    const big = 'x'.repeat(MAX_BYTES + 1024);
    const res = await fetch(`${url}/api/documents/upload`, {
      method: 'POST',
      headers: authHeaders(owner),
      body: uploadForm(big, 'text/plain', 'big.txt'),
    });
    expect(res.status).toBe(413);
  });

  it('rejects a disallowed MIME type (415)', async () => {
    const res = await fetch(`${url}/api/documents/upload`, {
      method: 'POST',
      headers: authHeaders(owner),
      body: uploadForm('MZ executable', 'application/x-msdownload', 'evil.exe'),
    });
    expect(res.status).toBe(415);
  });

  it('forbids upload for a viewer (403)', async () => {
    const res = await fetch(`${url}/api/documents/upload`, {
      method: 'POST',
      headers: authHeaders(owner, 'viewer'),
      body: uploadForm('hello', 'text/plain', 'v.txt'),
    });
    expect(res.status).toBe(403);
  });
});

describe('http — RAG chat (SSE)', () => {
  it('streams an answer with sources and ai_generated:true', async () => {
    const res = await fetch(`${url}/api/chat/rag`, {
      method: 'POST',
      headers: { ...authHeaders(owner), 'content-type': 'application/json' },
      body: JSON.stringify({ message: 'alpha beta knowledge' }),
    });
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('text/event-stream');
    const text = await res.text();
    expect(text).toContain('event: metadata');
    expect(text).toContain('"ai_generated":true');
    const meta = JSON.parse(text.split('event: metadata\ndata: ')[1]!.split('\n')[0]!) as { sources: unknown[] };
    expect(Array.isArray(meta.sources)).toBe(true);
    expect(meta.sources.length).toBeGreaterThan(0);
  });

  it('returns the explicit "no documents" message on empty retrieval', async () => {
    const res = await fetch(`${url}/api/chat/rag`, {
      method: 'POST',
      headers: { ...authHeaders(emptyOrg), 'content-type': 'application/json' },
      body: JSON.stringify({ message: 'anything at all' }),
    });
    const text = await res.text();
    expect(text).toContain('Keine relevanten Dokumente gefunden');
    expect(text).toContain('"ai_generated":true');
    const meta = JSON.parse(text.split('event: metadata\ndata: ')[1]!.split('\n')[0]!) as { sources: unknown[] };
    expect(meta.sources).toHaveLength(0);
  });
});

describe('http — GDPR erasure endpoint', () => {
  it('requires the explicit confirmation header (400 without it)', async () => {
    const res = await fetch(`${url}/api/admin/users/${owner.userId}/gdpr-erasure`, {
      method: 'DELETE',
      headers: authHeaders(owner),
    });
    expect(res.status).toBe(400);
  });
});
