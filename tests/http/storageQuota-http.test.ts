import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { loadConfig } from '../../src/config/index.js';
import { buildServer } from '../../src/server.js';
import { registerDocumentRoutes } from '../../src/http/routes/documents.js';
import type { Role } from '../../src/db/schema/index.js';
import { startTestDb, type TestDb } from '../setup/testDb.js';
import { bowEmbedder, seedOrgUser, tmpStorageDir, MASTER_KEY, type SeededPrincipal } from '../documents/helpers.js';

// Tiny quota so a single small upload trips it.
const QUOTA_BYTES = 64;

let t: TestDb;
let app: FastifyInstance;
let url: string;
let owner: SeededPrincipal;

const auth = (p: SeededPrincipal) => ({ 'x-test-org': p.orgId, 'x-test-user': p.userId, 'x-test-role': p.role });

beforeAll(async () => {
  t = await startTestDb();
  owner = await seedOrgUser(t.admin.db, { slug: 'quota-http', email: 'qh@example.com', role: 'owner' });
  const config = loadConfig({ APP_ENV: 'test', CORS_ALLOWED_ORIGINS: 'http://localhost', LOG_LEVEL: 'fatal' });
  app = await buildServer({
    config,
    routes: async (instance) => {
      instance.addHook('preHandler', async (req) => {
        const role = req.headers['x-test-role'] as Role | undefined;
        if (role) req.authContext = { userId: String(req.headers['x-test-user'] ?? ''), email: 't@e.com', orgId: String(req.headers['x-test-org'] ?? ''), role, sessionId: 's' };
      });
      await registerDocumentRoutes(instance, {
        db: t.app.db, embedder: bowEmbedder(), storageDir: await tmpStorageDir(), masterKey: MASTER_KEY,
        maxUploadBytes: 1024 * 1024, storageQuotaBytes: QUOTA_BYTES,
      });
    },
  });
  url = await app.listen({ host: '127.0.0.1', port: 0 });
}, 180_000);

afterAll(async () => { await app?.close(); await t?.stop(); });

function form(content: string): FormData {
  const fd = new FormData();
  fd.append('title', 'Big');
  fd.append('classification', 'INTERNAL');
  fd.append('file', new Blob([content], { type: 'text/plain' }), 'big.txt');
  return fd;
}

describe('http — storage quota enforcement', () => {
  it('rejects an upload over the org quota with 413 + quota headers', async () => {
    const res = await fetch(`${url}/api/documents/upload`, { method: 'POST', headers: auth(owner), body: form('x'.repeat(200)) });
    expect(res.status).toBe(413);
    expect(((await res.json()) as { error: string }).error).toBe('storage_quota_exceeded');
    expect(res.headers.get('x-quota-limit')).toBe(String(QUOTA_BYTES));
    expect(res.headers.get('x-quota-used')).toBe('0');
  });

  it('allows an upload within quota', async () => {
    const res = await fetch(`${url}/api/documents/upload`, { method: 'POST', headers: auth(owner), body: form('tiny') });
    expect(res.status).toBe(201);
  });
});
