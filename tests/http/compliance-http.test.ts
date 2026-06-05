import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { PDFParse } from 'pdf-parse';
import { loadConfig } from '../../src/config/index.js';
import { buildServer } from '../../src/server.js';
import { registerAiEnvelope } from '../../src/http/aiResponseEnvelope.js';
import { registerComplianceRoutes } from '../../src/http/routes/compliance.js';
import { registerCompletionsRoute } from '../../src/http/routes/completions.js';
import { documentAccessLog } from '../../src/db/schema/index.js';
import type { LlmProvider } from '../../src/ai/providers/provider.interface.js';
import type { Role } from '../../src/db/schema/index.js';
import { startTestDb, type TestDb } from '../setup/testDb.js';
import { seedOrgUser, seedMember, type SeededPrincipal } from '../documents/helpers.js';

const fakeProvider: LlmProvider = {
  id: 'test-llm',
  model: 'test-llm',
  chat: async () => ({ content: 'Hallo', model: 'test-llm' }),
  async *chatStream() {
    yield { delta: 'Hallo', done: true };
  },
};

async function pdfText(buf: Buffer): Promise<string> {
  const parser = new PDFParse({ data: new Uint8Array(buf) });
  return (await parser.getText()).text;
}

let t: TestDb;
let app: FastifyInstance;
let url: string;
let owner: SeededPrincipal;
let member: SeededPrincipal;
let orgB: SeededPrincipal;

function auth(p: SeededPrincipal, role: Role = p.role): Record<string, string> {
  return { 'x-test-org': p.orgId, 'x-test-user': p.userId, 'x-test-role': role };
}

beforeAll(async () => {
  t = await startTestDb();
  owner = await seedOrgUser(t.admin.db, { slug: 'co-org', email: 'co-owner@example.com', role: 'owner' });
  member = await seedMember(t.admin.db, owner.orgId, { email: 'co-member@example.com', role: 'member' });
  orgB = await seedOrgUser(t.admin.db, { slug: 'co-org-b', email: 'co-b@example.com', role: 'owner' });

  // Seed three QUERY access-log rows so Section 2 has a known count.
  for (let i = 0; i < 3; i++) {
    await t.admin.db.insert(documentAccessLog).values({ orgId: owner.orgId, action: 'QUERY', queryTextHash: `h${i}` });
  }

  const config = loadConfig({ APP_ENV: 'test', CORS_ALLOWED_ORIGINS: 'http://localhost', LOG_LEVEL: 'fatal' });
  app = await buildServer({
    config,
    routes: (instance) => {
      instance.addHook('preHandler', async (req) => {
        const role = req.headers['x-test-role'] as Role | undefined;
        if (role) {
          req.authContext = {
            userId: String(req.headers['x-test-user'] ?? ''),
            email: 'tester@example.com',
            orgId: String(req.headers['x-test-org'] ?? ''),
            role,
            sessionId: 's',
          };
        }
      });
      registerAiEnvelope(instance, { db: t.app.db });
      registerComplianceRoutes(instance, { db: t.app.db });
      registerCompletionsRoute(instance, {
        resolveProvider: (id) => { if (id === 'test-llm') return fakeProvider; throw new Error('unknown'); },
        providerId: 'test-llm',
      });
    },
  });
  url = await app.listen({ host: '127.0.0.1', port: 0 });
}, 180_000);

afterAll(async () => {
  await app?.close();
  await t?.stop();
});

const j = (p: SeededPrincipal, role?: Role) => ({ ...auth(p, role), 'content-type': 'application/json' });

describe('http — KI-Inventar', () => {
  it('forbids a member from creating an entry (403), allows an admin (201)', async () => {
    const asMember = await fetch(`${url}/api/compliance/inventory`, {
      method: 'POST', headers: j(owner, 'member'), body: JSON.stringify({ modelName: 'm', provider: 'p' }),
    });
    expect(asMember.status).toBe(403);

    const asAdmin = await fetch(`${url}/api/compliance/inventory`, {
      method: 'POST', headers: j(owner, 'admin'),
      body: JSON.stringify({ modelName: 'gpt-4o', provider: 'openai', riskClass: 'HIGH', purpose: 'Vertragsanalyse' }),
    });
    expect(asAdmin.status).toBe(201);
  });

  it('does not expose inventory across tenants', async () => {
    const res = await fetch(`${url}/api/compliance/inventory`, { headers: auth(orgB) });
    const rows = (await res.json()) as Array<{ provider: string }>;
    expect(rows.every((r) => r.provider !== 'openai')).toBe(true);
  });

  it('exports a valid German KI-Inventar PDF containing the entries', async () => {
    const res = await fetch(`${url}/api/compliance/inventory/export.pdf`, { headers: auth(owner, 'admin') });
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('application/pdf');
    const text = await pdfText(Buffer.from(await res.arrayBuffer()));
    expect(text).toContain('KI-Inventar gemäß Art. 4 EU AI Act');
    expect(text).toContain('gpt-4o');
  });
});

describe('http — transparency envelope (completions)', () => {
  it('wraps the response in ai_meta and links the KI-Inventar entry', async () => {
    const res = await fetch(`${url}/api/chat/completions`, {
      method: 'POST', headers: j(owner), body: JSON.stringify({ message: 'Hallo' }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { data: unknown; ai_meta: { ai_generated: boolean; inventory_entry_id: string | null; compliance: { eu_ai_act: boolean } } };
    expect(body.ai_meta.ai_generated).toBe(true);
    expect(body.ai_meta.compliance.eu_ai_act).toBe(true);
    expect(body.ai_meta.inventory_entry_id).toBeTruthy();

    // The linked id is a real inventory entry for this org.
    const list = (await (await fetch(`${url}/api/compliance/inventory`, { headers: auth(owner) })).json()) as Array<{ id: string }>;
    expect(list.some((e) => e.id === body.ai_meta.inventory_entry_id)).toBe(true);
  });
});

describe('http — oversight RBAC', () => {
  it('forbids a member from approving (403)', async () => {
    const res = await fetch(`${url}/api/compliance/oversight/00000000-0000-0000-0000-000000000000/approve`, {
      method: 'POST', headers: auth(owner, 'member'),
    });
    expect(res.status).toBe(403);
  });
});

describe('http — compliance report PDF', () => {
  it('forbids a member (403)', async () => {
    const res = await fetch(`${url}/api/compliance/report.pdf`, { headers: auth(owner, 'member') });
    expect(res.status).toBe(403);
  });

  it('generates a 5-section German report whose counts match the DB, in < 10s', async () => {
    const started = Date.now();
    const res = await fetch(`${url}/api/compliance/report.pdf`, { headers: auth(owner, 'admin') });
    const elapsed = Date.now() - started;
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('application/pdf');
    const text = await pdfText(Buffer.from(await res.arrayBuffer()));

    expect(text).toContain('KI-Compliance-Bericht');
    for (const s of ['Abschnitt 1', 'Abschnitt 2', 'Abschnitt 3', 'Abschnitt 4', 'Abschnitt 5']) {
      expect(text, s).toContain(s);
    }
    // Section 2 audit count reflects the 3 seeded QUERY rows.
    expect(text).toContain('KI-Abfragen gesamt: 3');
    expect(elapsed).toBeLessThan(10_000);
  });
});
