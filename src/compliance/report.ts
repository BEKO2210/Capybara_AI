import { sql, desc } from 'drizzle-orm';
import type { AppDatabase } from '../db/client.js';
import { aiInventoryEntries } from '../db/schema/index.js';
import { withTenantContext, type TenantContext } from '../tenancy/scope.js';
import { countByStatus } from './oversight.js';
import type { ComplianceReportData } from './pdf.js';

/** Gather all data for the compliance report (last 90 days). */
export async function gatherReportData(
  db: AppDatabase,
  ctx: TenantContext,
  orgName: string,
  generatedBy: string,
): Promise<ComplianceReportData> {
  const sinceIso = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString();
  const oversight = await countByStatus(db, ctx);

  return withTenantContext(db, ctx, async (tx) => {
    const inventory = await tx.select().from(aiInventoryEntries).orderBy(desc(aiInventoryEntries.createdAt));

    const counts = (await tx.execute(sql`
      SELECT
        (SELECT count(*) FROM document_access_log WHERE action = 'QUERY' AND created_at >= ${sinceIso}) AS ai_queries,
        (SELECT count(*) FROM documents WHERE deleted_at IS NULL) AS documents_processed,
        (SELECT count(*) FROM audit_log WHERE action = 'gdpr.user.erased' AND org_id = ${ctx.orgId}::uuid) AS gdpr_erasures
    `)) as unknown as { ai_queries: number; documents_processed: number; gdpr_erasures: number }[];
    const c = counts[0] ?? { ai_queries: 0, documents_processed: 0, gdpr_erasures: 0 };

    const secRows = (await tx.execute(sql`
      SELECT event_type, count(*)::int AS n FROM security_events
      WHERE org_id = ${ctx.orgId}::uuid AND created_at >= ${sinceIso}
      GROUP BY event_type
    `)) as unknown as { event_type: string; n: number }[];
    const securityEventsByType: Record<string, number> = {};
    for (const r of secRows) securityEventsByType[r.event_type] = Number(r.n);

    return {
      orgName,
      generatedBy,
      inventory,
      audit: {
        aiQueries: Number(c.ai_queries),
        documentsProcessed: Number(c.documents_processed),
        oversight: { pending: oversight['PENDING'] ?? 0, approved: oversight['APPROVED'] ?? 0, rejected: oversight['REJECTED'] ?? 0 },
        gdprErasures: Number(c.gdpr_erasures),
        securityEventsByType,
      },
    };
  });
}
