import { createHash } from 'node:crypto';
import { documentAccessLog, type DocumentAction } from '../db/schema/index.js';
import type { Tx } from '../tenancy/scope.js';

/** SHA-256 of a query string — the only form of query text ever persisted. */
export function hashQuery(query: string): string {
  return createHash('sha256').update(query, 'utf8').digest('hex');
}

export interface AccessLogInput {
  orgId: string;
  action: DocumentAction;
  documentId?: string | null;
  userId?: string | null;
  queryText?: string | null;
  ip?: string | null;
}

/** Append an access-log entry. Must run inside a tenant-scoped transaction. */
export async function logAccess(tx: Tx, input: AccessLogInput): Promise<void> {
  await tx.insert(documentAccessLog).values({
    orgId: input.orgId,
    action: input.action,
    documentId: input.documentId ?? null,
    userId: input.userId ?? null,
    queryTextHash: input.queryText ? hashQuery(input.queryText) : null,
    ipAddress: input.ip ?? null,
  });
}
