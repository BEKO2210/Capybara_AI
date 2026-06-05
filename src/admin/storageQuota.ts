import { sql } from 'drizzle-orm';
import type { AppDatabase } from '../db/client.js';
import { withTenantContext, type TenantContext } from '../tenancy/scope.js';

/**
 * Per-organization storage quota. Sums the bytes of non-deleted documents under
 * tenant context (RLS-scoped) and refuses uploads that would exceed the limit.
 */

export class QuotaExceededError extends Error {
  constructor(
    readonly usedBytes: number,
    readonly limitBytes: number,
    readonly attemptedBytes: number,
  ) {
    super('storage quota exceeded');
    this.name = 'QuotaExceededError';
  }
}

/** Current storage consumption (bytes) for the org, excluding soft-deleted docs. */
export function getStorageUsage(db: AppDatabase, ctx: TenantContext): Promise<number> {
  return withTenantContext(db, ctx, async (tx) => {
    const rows = (await tx.execute(
      sql`SELECT COALESCE(SUM(size_bytes), 0)::bigint AS used FROM documents WHERE deleted_at IS NULL`,
    )) as unknown as { used: string | number }[];
    return Number(rows[0]?.used ?? 0);
  });
}

export interface QuotaStatus {
  readonly usedBytes: number;
  readonly limitBytes: number;
  readonly remainingBytes: number;
}

/**
 * Throw {@link QuotaExceededError} if storing `addBytes` more would push the org
 * over `limitBytes`. Returns the post-write quota status on success.
 */
export async function enforceStorageQuota(
  db: AppDatabase,
  ctx: TenantContext,
  addBytes: number,
  limitBytes: number,
): Promise<QuotaStatus> {
  const used = await getStorageUsage(db, ctx);
  if (used + addBytes > limitBytes) {
    throw new QuotaExceededError(used, limitBytes, addBytes);
  }
  return { usedBytes: used + addBytes, limitBytes, remainingBytes: limitBytes - used - addBytes };
}
