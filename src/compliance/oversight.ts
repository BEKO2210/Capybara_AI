import { and, eq, isNull, lt, desc, sql } from 'drizzle-orm';
import type { AppDatabase } from '../db/client.js';
import {
  oversightRequests,
  RISK_LEVEL_RANK,
  type OversightRequest,
  type RiskLevel,
} from '../db/schema/index.js';
import { withTenantContext, type TenantContext } from '../tenancy/scope.js';
import { sha256Hex, canonicalJson } from '../lib/hash.js';
import { encryptSecret, deriveTenantKey } from '../lib/crypto.js';
import { appendSecurityEvent } from '../audit/securityLog.js';

/** A tool requires human oversight when its risk level is HIGH or above. */
export function requiresOversight(riskLevel: RiskLevel): boolean {
  return RISK_LEVEL_RANK[riskLevel] >= RISK_LEVEL_RANK.HIGH;
}

export interface OversightCheckResult {
  approved: boolean;
  requestId: string;
}

export interface OversightGate {
  check(toolName: string, args: unknown, riskLevel: RiskLevel): Promise<OversightCheckResult>;
  recordOutcome?(requestId: string, summary: string): Promise<void>;
}

/** Move any PENDING request past its expiry to EXPIRED (idempotent). */
export async function expireStale(db: AppDatabase, ctx: TenantContext): Promise<number> {
  return withTenantContext(db, ctx, async (tx) => {
    const rows = await tx
      .update(oversightRequests)
      .set({ status: 'EXPIRED', decidedAt: new Date() })
      .where(and(eq(oversightRequests.status, 'PENDING'), lt(oversightRequests.expiresAt, new Date())))
      .returning({ id: oversightRequests.id });
    return rows.length;
  });
}

/**
 * DB-backed oversight gate used by the tool sandbox. A HIGH/CRITICAL tool may
 * run only when an unconsumed APPROVED request matches its exact args; otherwise
 * a PENDING request is created (or reused) and the call is blocked.
 */
/** Fired when a NEW oversight request is created (wire to a webhook/notifier). */
export type OversightNotifier = (info: { requestId: string; toolName: string; riskLevel: RiskLevel }) => Promise<void> | void;

export class DbOversightGate implements OversightGate {
  constructor(
    private readonly db: AppDatabase,
    private readonly ctx: TenantContext,
    private readonly masterKey: Buffer,
    private readonly notify?: OversightNotifier,
  ) {}

  async check(toolName: string, args: unknown, riskLevel: RiskLevel): Promise<OversightCheckResult> {
    const argsHash = sha256Hex(canonicalJson(args));
    await expireStale(this.db, this.ctx);

    return withTenantContext(this.db, this.ctx, async (tx) => {
      // A valid, unconsumed approval for this exact invocation.
      const approved = await tx
        .select()
        .from(oversightRequests)
        .where(
          and(
            eq(oversightRequests.toolName, toolName),
            eq(oversightRequests.toolArgsHash, argsHash),
            eq(oversightRequests.status, 'APPROVED'),
            isNull(oversightRequests.outcomeSummary),
          ),
        )
        .limit(1);
      if (approved[0]) return { approved: true, requestId: approved[0].id };

      // Reuse an existing PENDING, or create one.
      const pending = await tx
        .select()
        .from(oversightRequests)
        .where(
          and(
            eq(oversightRequests.toolName, toolName),
            eq(oversightRequests.toolArgsHash, argsHash),
            eq(oversightRequests.status, 'PENDING'),
          ),
        )
        .limit(1);
      if (pending[0]) return { approved: false, requestId: pending[0].id };

      const tenantKey = deriveTenantKey(this.masterKey, this.ctx.orgId);
      const [created] = await tx
        .insert(oversightRequests)
        .values({
          orgId: this.ctx.orgId,
          requestedBy: this.ctx.userId,
          toolName,
          toolArgsHash: argsHash,
          toolArgsEncrypted: encryptSecret(canonicalJson(args), tenantKey),
          riskLevel,
          status: 'PENDING',
          expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
        })
        .returning({ id: oversightRequests.id });
      // Notify responders that a new human-oversight decision is required.
      if (this.notify) await this.notify({ requestId: created!.id, toolName, riskLevel });
      return { approved: false, requestId: created!.id };
    });
  }

  async recordOutcome(requestId: string, summary: string): Promise<void> {
    await withTenantContext(this.db, this.ctx, async (tx) => {
      await tx
        .update(oversightRequests)
        .set({ outcomeSummary: summary })
        .where(eq(oversightRequests.id, requestId));
    });
  }
}

async function decide(
  db: AppDatabase,
  ctx: TenantContext,
  id: string,
  deciderId: string,
  status: 'APPROVED' | 'REJECTED',
): Promise<boolean> {
  const ok = await withTenantContext(db, ctx, async (tx) => {
    const rows = await tx
      .update(oversightRequests)
      .set({ status, decidedBy: deciderId, decidedAt: new Date() })
      .where(and(eq(oversightRequests.id, id), eq(oversightRequests.status, 'PENDING')))
      .returning({ id: oversightRequests.id });
    return rows.length > 0;
  });
  if (ok) {
    // Tamper-evident audit of the decision (hash-chained security log).
    await appendSecurityEvent(db, {
      orgId: ctx.orgId,
      eventType: status === 'APPROVED' ? 'oversight.approved' : 'oversight.rejected',
      severity: 'warning',
      payload: { requestId: id, decidedBy: deciderId },
    });
  }
  return ok;
}

export function approveRequest(db: AppDatabase, ctx: TenantContext, id: string, deciderId: string): Promise<boolean> {
  return decide(db, ctx, id, deciderId, 'APPROVED');
}

export function rejectRequest(db: AppDatabase, ctx: TenantContext, id: string, deciderId: string): Promise<boolean> {
  return decide(db, ctx, id, deciderId, 'REJECTED');
}

export function listOversight(
  db: AppDatabase,
  ctx: TenantContext,
  opts: { pendingOnly?: boolean } = {},
): Promise<OversightRequest[]> {
  return withTenantContext(db, ctx, async (tx) => {
    const base = tx.select().from(oversightRequests);
    const rows = opts.pendingOnly
      ? await base.where(eq(oversightRequests.status, 'PENDING')).orderBy(desc(oversightRequests.createdAt))
      : await base.orderBy(desc(oversightRequests.createdAt));
    return rows;
  });
}

/** Count oversight requests by status (for the compliance report). */
export function countByStatus(db: AppDatabase, ctx: TenantContext): Promise<Record<string, number>> {
  return withTenantContext(db, ctx, async (tx) => {
    const rows = (await tx.execute(sql`
      SELECT status, COUNT(*)::int AS n FROM oversight_requests GROUP BY status
    `)) as unknown as { status: string; n: number }[];
    const out: Record<string, number> = { PENDING: 0, APPROVED: 0, REJECTED: 0, EXPIRED: 0 };
    for (const r of rows) out[r.status] = Number(r.n);
    return out;
  });
}
