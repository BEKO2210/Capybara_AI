import { sql } from 'drizzle-orm';
import type { AppDatabase } from '../db/client.js';
import { withTenantContext, type TenantContext } from '../tenancy/scope.js';

/** Aggregate, PII-free org statistics for the admin dashboard / billing. */
export interface OrgStats {
  users: { total: number; active: number; invited: number; deactivated: number };
  documents: { total: number; totalSizeBytes: number; byClassification: Record<string, number> };
  queries: { total: number; byDay: Array<{ date: string; count: number }> };
  llmCalls: { total: number; byProvider: Record<string, number>; byModel: Record<string, number>; estimatedTokensIn: number; estimatedTokensOut: number };
  storage: { documentsBytes: number; vectorsRows: number };
  compliance: { oversightPending: number; oversightApproved: number; oversightRejected: number; gdprErasures: number };
}

export function orgStats(db: AppDatabase, ctx: TenantContext, days = 30): Promise<OrgStats> {
  const sinceIso = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
  return withTenantContext(db, ctx, async (tx) => {
    const exec = async <T>(q: ReturnType<typeof sql>): Promise<T[]> => (await tx.execute(q)) as unknown as T[];

    const [userRow] = await exec<{ total: number; active: number; invited: number; deactivated: number }>(sql`
      SELECT
        count(*) AS total,
        count(*) FILTER (WHERE u.status = 'active') AS active,
        count(*) FILTER (WHERE u.status = 'invited') AS invited,
        count(*) FILTER (WHERE u.status = 'inactive') AS deactivated
      FROM memberships m JOIN users u ON u.id = m.user_id`);

    const [docRow] = await exec<{ total: number; total_size: number }>(sql`
      SELECT count(*) AS total, COALESCE(sum(size_bytes), 0) AS total_size
      FROM documents WHERE deleted_at IS NULL`);
    const byClassRows = await exec<{ classification: string; n: number }>(sql`
      SELECT classification, count(*)::int AS n FROM documents WHERE deleted_at IS NULL GROUP BY classification`);
    const byClassification: Record<string, number> = {};
    for (const r of byClassRows) byClassification[r.classification] = Number(r.n);

    const [qTotal] = await exec<{ n: number }>(sql`
      SELECT count(*)::int AS n FROM document_access_log WHERE action = 'QUERY' AND created_at >= ${sinceIso}`);
    const byDayRows = await exec<{ d: string; n: number }>(sql`
      SELECT to_char(created_at, 'YYYY-MM-DD') AS d, count(*)::int AS n
      FROM document_access_log WHERE action = 'QUERY' AND created_at >= ${sinceIso}
      GROUP BY d ORDER BY d`);

    const llmRows = await exec<{ provider: string | null; model: string | null; n: number; tin: number; tout: number }>(sql`
      SELECT provider, model, count(*)::int AS n,
             COALESCE(sum((metadata_json->>'tokensIn')::numeric), 0) AS tin,
             COALESCE(sum((metadata_json->>'tokensOut')::numeric), 0) AS tout
      FROM metering_events WHERE event_type = 'LLM_CALL' AND created_at >= ${sinceIso}
      GROUP BY provider, model`);
    const byProvider: Record<string, number> = {};
    const byModel: Record<string, number> = {};
    let llmTotal = 0, tokensIn = 0, tokensOut = 0;
    for (const r of llmRows) {
      const n = Number(r.n);
      llmTotal += n;
      byProvider[r.provider ?? 'unknown'] = (byProvider[r.provider ?? 'unknown'] ?? 0) + n;
      byModel[r.model ?? 'unknown'] = (byModel[r.model ?? 'unknown'] ?? 0) + n;
      tokensIn += Number(r.tin);
      tokensOut += Number(r.tout);
    }

    const [vec] = await exec<{ n: number }>(sql`SELECT count(*)::int AS n FROM document_chunks`);
    const [over] = await exec<{ pending: number; approved: number; rejected: number }>(sql`
      SELECT count(*) FILTER (WHERE status='PENDING') AS pending,
             count(*) FILTER (WHERE status='APPROVED') AS approved,
             count(*) FILTER (WHERE status='REJECTED') AS rejected
      FROM oversight_requests`);
    const [gdpr] = await exec<{ n: number }>(sql`
      SELECT count(*)::int AS n FROM audit_log WHERE action = 'gdpr.user.erased' AND org_id = ${ctx.orgId}::uuid`);

    const docsBytes = Number(docRow?.total_size ?? 0);
    return {
      users: {
        total: Number(userRow?.total ?? 0), active: Number(userRow?.active ?? 0),
        invited: Number(userRow?.invited ?? 0), deactivated: Number(userRow?.deactivated ?? 0),
      },
      documents: { total: Number(docRow?.total ?? 0), totalSizeBytes: docsBytes, byClassification },
      queries: { total: Number(qTotal?.n ?? 0), byDay: byDayRows.map((r) => ({ date: r.d, count: Number(r.n) })) },
      llmCalls: { total: llmTotal, byProvider, byModel, estimatedTokensIn: tokensIn, estimatedTokensOut: tokensOut },
      storage: { documentsBytes: docsBytes, vectorsRows: Number(vec?.n ?? 0) },
      compliance: {
        oversightPending: Number(over?.pending ?? 0), oversightApproved: Number(over?.approved ?? 0),
        oversightRejected: Number(over?.rejected ?? 0), gdprErasures: Number(gdpr?.n ?? 0),
      },
    };
  });
}
