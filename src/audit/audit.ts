import type { AppDatabase } from '../db/client.js';
import { auditLog } from '../db/schema/index.js';

/**
 * Records a business/sensitive-action audit entry. Distinct from the
 * tamper-evident security event log: this is the queryable "who did what"
 * trail. Callers MUST NOT pass secrets or raw PII in `metadata`.
 */
export interface AuditInput {
  orgId?: string | null;
  actorUserId?: string | null;
  action: string;
  targetType?: string | null;
  targetId?: string | null;
  metadata?: Record<string, unknown> | null;
  ip?: string | null;
}

export async function recordAuditEvent(db: AppDatabase, input: AuditInput): Promise<string> {
  const [row] = await db
    .insert(auditLog)
    .values({
      orgId: input.orgId ?? null,
      actorUserId: input.actorUserId ?? null,
      action: input.action,
      targetType: input.targetType ?? null,
      targetId: input.targetId ?? null,
      metadata: input.metadata ?? null,
      ip: input.ip ?? null,
    })
    .returning({ id: auditLog.id });
  if (!row) throw new Error('failed to record audit event');
  return row.id;
}
