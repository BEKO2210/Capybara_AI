import { asc } from 'drizzle-orm';
import type { AppDatabase } from '../db/client.js';
import { securityEvents } from '../db/schema/index.js';
import { canonicalJson } from '../lib/hash.js';
import { GENESIS_HASH, computeHash } from './securityLog.js';

/**
 * Offline integrity verifier for the security_events hash chain. Recomputes
 * every row's hash from its stored content + the prior hash and compares to the
 * stored hash, also checking that prev_hash links are intact. Returns the first
 * broken link, if any — giving tamper-evidence.
 */

export interface ChainVerification {
  ok: boolean;
  /** Count of rows checked. */
  length: number;
  /** id of the first row that failed verification, if any. */
  brokenAt?: number;
  reason?: 'hash_mismatch' | 'prev_hash_mismatch';
}

export async function verifyChain(db: AppDatabase): Promise<ChainVerification> {
  const rows = await db
    .select()
    .from(securityEvents)
    .orderBy(asc(securityEvents.id));

  let prevHash = GENESIS_HASH;
  for (const row of rows) {
    if (row.prevHash !== prevHash) {
      return { ok: false, length: rows.length, brokenAt: row.id, reason: 'prev_hash_mismatch' };
    }
    const content = canonicalJson({
      orgId: row.orgId,
      eventType: row.eventType,
      severity: row.severity,
      payload: row.payload,
      createdAt: row.createdAt.toISOString(),
    });
    const expected = computeHash(prevHash, content);
    if (expected !== row.hash) {
      return { ok: false, length: rows.length, brokenAt: row.id, reason: 'hash_mismatch' };
    }
    prevHash = row.hash;
  }

  return { ok: true, length: rows.length };
}
