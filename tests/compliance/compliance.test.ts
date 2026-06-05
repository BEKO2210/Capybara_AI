import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { eq, and } from 'drizzle-orm';
import { z } from 'zod';
import { startTestDb, type TestDb } from '../setup/testDb.js';
import { aiInventoryEntries, securityEvents, oversightRequests } from '../../src/db/schema/index.js';
import { seedOrgUser, MASTER_KEY, type SeededPrincipal } from '../documents/helpers.js';
import { withTenantContext } from '../../src/tenancy/scope.js';
import { ensureInventoryEntry, listInventory } from '../../src/compliance/inventory.js';
import { DbOversightGate, approveRequest, rejectRequest, expireStale } from '../../src/compliance/oversight.js';
import { verifyChain } from '../../src/audit/verifyChain.js';
import { ToolRegistry } from '../../src/ai/tools/registry.js';
import { executeTool } from '../../src/ai/tools/sandbox.js';
import { DenyAllApprovals } from '../../src/ai/tools/approval.js';
import { buildAiMeta } from '../../src/http/aiResponseEnvelope.js';
import type { ToolDefinition } from '../../src/ai/tools/tool.types.js';

let t: TestDb;
let orgA: SeededPrincipal;
let orgB: SeededPrincipal;
let ranHigh = false;

function ctx(p: SeededPrincipal) {
  return { orgId: p.orgId, userId: p.userId, clearance: p.clearance };
}

const argSchema = z.object({ n: z.number().optional(), tenant: z.string().optional() });
type Args = z.infer<typeof argSchema>;

const registry = new ToolRegistry();
const highTool: ToolDefinition<Args> = {
  name: 'wire_transfer',
  description: 'high-risk action',
  inputSchema: argSchema,
  dangerous: false,
  riskLevel: 'HIGH',
  scopes: {},
  timeoutMs: 5_000,
  handler: async () => {
    ranHigh = true;
    return { ok: true, output: 'transferred' };
  },
};
const lowTool: ToolDefinition<Args> = {
  name: 'read_clock',
  description: 'low-risk action',
  inputSchema: argSchema,
  dangerous: false,
  riskLevel: 'LOW',
  scopes: {},
  timeoutMs: 5_000,
  handler: async () => ({ ok: true, output: 'tick' }),
};
registry.register(highTool);
registry.register(lowTool);

beforeAll(async () => {
  t = await startTestDb();
  orgA = await seedOrgUser(t.admin.db, { slug: 'ci-a', email: 'a@example.com', role: 'owner' });
  orgB = await seedOrgUser(t.admin.db, { slug: 'ci-b', email: 'b@example.com', role: 'owner' });
}, 180_000);

afterAll(async () => {
  await t?.stop();
});

describe('compliance — KI-Inventar', () => {
  it('auto-creates an entry on first model use with safe defaults', async () => {
    const entry = await ensureInventoryEntry(t.app.db, ctx(orgA), { modelName: 'llama3', provider: 'ollama' });
    expect(entry.riskClass).toBe('LIMITED');
    expect(entry.humanOversightRequired).toBe(true);
    // Idempotent.
    const again = await ensureInventoryEntry(t.app.db, ctx(orgA), { modelName: 'llama3', provider: 'ollama' });
    expect(again.id).toBe(entry.id);
  });

  it('does not leak inventory across tenants', async () => {
    await ensureInventoryEntry(t.app.db, ctx(orgB), { modelName: 'gpt-x', provider: 'openai' });
    const aList = await listInventory(t.app.db, ctx(orgA));
    expect(aList.every((e) => e.provider !== 'openai')).toBe(true);
    const bList = await listInventory(t.app.db, ctx(orgB));
    expect(bList.every((e) => e.provider !== 'ollama')).toBe(true);
  });
});

describe('compliance — human oversight via the tool sandbox', () => {
  const gateFor = (p: SeededPrincipal) => new DbOversightGate(t.app.db, ctx(p), MASTER_KEY);

  it('runs a LOW-risk tool without approval', async () => {
    const inv = await executeTool(registry, 'read_clock', {}, { approvals: new DenyAllApprovals(), oversight: gateFor(orgA) });
    expect(inv.decision).toBe('allowed');
  });

  it('blocks a HIGH-risk tool with pending_approval and does not execute it', async () => {
    ranHigh = false;
    const inv = await executeTool(registry, 'wire_transfer', {}, { approvals: new DenyAllApprovals(), oversight: gateFor(orgA) });
    expect(inv.decision).toBe('pending_approval');
    expect(inv.reason).toBe('human_oversight_required');
    expect(inv.requestId).toBeTruthy();
    expect(ranHigh).toBe(false);
  });

  it('executes the HIGH-risk tool after approval, and records the decision in the tamper-evident log', async () => {
    ranHigh = false;
    const pending = await executeTool(registry, 'wire_transfer', { n: 1 }, { approvals: new DenyAllApprovals(), oversight: gateFor(orgA) });
    expect(pending.decision).toBe('pending_approval');
    expect(await approveRequest(t.app.db, ctx(orgA), pending.requestId!, orgA.userId)).toBe(true);

    const run = await executeTool(registry, 'wire_transfer', { n: 1 }, { approvals: new DenyAllApprovals(), oversight: gateFor(orgA) });
    expect(run.decision).toBe('allowed');
    expect(ranHigh).toBe(true);

    // Approval is in the hash-chained security log, which still verifies.
    const events = await t.admin.db.select().from(securityEvents).where(eq(securityEvents.eventType, 'oversight.approved'));
    expect(events.length).toBeGreaterThan(0);
    expect((await verifyChain(t.app.db)).ok).toBe(true);
  });

  it('keeps blocking a HIGH-risk tool after rejection', async () => {
    const pending = await executeTool(registry, 'wire_transfer', { n: 2 }, { approvals: new DenyAllApprovals(), oversight: gateFor(orgA) });
    expect(await rejectRequest(t.app.db, ctx(orgA), pending.requestId!, orgA.userId)).toBe(true);
    const again = await executeTool(registry, 'wire_transfer', { n: 2 }, { approvals: new DenyAllApprovals(), oversight: gateFor(orgA) });
    expect(again.decision).toBe('pending_approval'); // a fresh PENDING, still blocked
  });

  it('expires stale pending requests, which then block execution', async () => {
    const pending = await executeTool(registry, 'wire_transfer', { n: 3 }, { approvals: new DenyAllApprovals(), oversight: gateFor(orgA) });
    // Force expiry.
    await t.admin.db.update(oversightRequests).set({ expiresAt: new Date(Date.now() - 1000) }).where(eq(oversightRequests.id, pending.requestId!));
    expect(await expireStale(t.app.db, ctx(orgA))).toBeGreaterThan(0);
    const row = await t.admin.db.select().from(oversightRequests).where(eq(oversightRequests.id, pending.requestId!));
    expect(row[0]?.status).toBe('EXPIRED');
  });

  it('does not leak oversight requests across tenants', async () => {
    await executeTool(registry, 'wire_transfer', { tenant: 'b' }, { approvals: new DenyAllApprovals(), oversight: gateFor(orgB) });
    // Within org A context, org B's requests are invisible (RLS).
    const visibleToA = await withTenantContext(t.app.db, ctx(orgA), async (tx) =>
      tx.select().from(oversightRequests).where(eq(oversightRequests.toolName, 'wire_transfer')),
    );
    expect(visibleToA.length).toBeGreaterThan(0);
    expect(visibleToA.every((r) => r.orgId === orgA.orgId)).toBe(true);
  });
});

describe('compliance — transparency ai_meta', () => {
  it('reflects human-oversight requirement by tool risk level', () => {
    const high = buildAiMeta({ model: 'm', provider: 'p', humanOversightRequired: true, riskClass: 'HIGH' });
    const low = buildAiMeta({ model: 'm', provider: 'p', humanOversightRequired: false });
    expect(high.ai_generated).toBe(true);
    expect(high.human_oversight.required).toBe(true);
    expect(high.compliance.eu_ai_act).toBe(true);
    expect(high.compliance.transparency_label).toBe('KI-generierter Inhalt');
    expect(low.human_oversight.required).toBe(false);
  });
});
