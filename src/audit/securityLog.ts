import { sql, desc } from 'drizzle-orm';
import type { AppDatabase } from '../db/client.js';
import { securityEvents } from '../db/schema/index.js';
import { sha256Hex, canonicalJson } from '../lib/hash.js';

/**
 * Tamper-evident security event log (hash-chained, append-only).
 *
 * Appends are serialized with a transaction-scoped advisory lock so concurrent
 * writers cannot fork the chain. Each row's hash binds the previous hash and
 * the canonical content; verifyChain() recomputes the chain to detect any
 * later mutation/deletion.
 */

export type Severity = 'info' | 'warning' | 'critical';

/** Genesis predecessor hash for the first row. */
export const GENESIS_HASH = '0'.repeat(64);

/** Fixed advisory-lock key serializing appends to this log. */
const CHAIN_LOCK_KEY = 4242424242;

export interface SecurityEventInput {
  orgId?: string | null;
  eventType: string;
  severity: Severity;
  payload: unknown;
}

/** Canonical, deterministic content string that the hash commits to. */
function canonicalContent(e: {
  orgId: string | null;
  eventType: string;
  severity: string;
  payload: unknown;
  createdAtIso: string;
}): string {
  return canonicalJson({
    orgId: e.orgId,
    eventType: e.eventType,
    severity: e.severity,
    payload: e.payload,
    createdAt: e.createdAtIso,
  });
}

export function computeHash(prevHash: string, content: string): string {
  return sha256Hex(`${prevHash}\n${content}`);
}

export interface AppendedEvent {
  id: number;
  hash: string;
}

export async function appendSecurityEvent(
  db: AppDatabase,
  input: SecurityEventInput,
): Promise<AppendedEvent> {
  return db.transaction(async (tx) => {
    // Serialize appends: no concurrent writer can read the same tail.
    await tx.execute(sql`SELECT pg_advisory_xact_lock(${CHAIN_LOCK_KEY})`);

    const last = await tx
      .select({ hash: securityEvents.hash })
      .from(securityEvents)
      .orderBy(desc(securityEvents.id))
      .limit(1);
    const prevHash = last[0]?.hash ?? GENESIS_HASH;

    const orgId = input.orgId ?? null;
    const createdAt = new Date();
    const content = canonicalContent({
      orgId,
      eventType: input.eventType,
      severity: input.severity,
      payload: input.payload,
      createdAtIso: createdAt.toISOString(),
    });
    const hash = computeHash(prevHash, content);

    const [row] = await tx
      .insert(securityEvents)
      .values({
        orgId,
        eventType: input.eventType,
        severity: input.severity,
        payload: input.payload,
        prevHash,
        hash,
        createdAt,
      })
      .returning({ id: securityEvents.id });
    if (!row) throw new Error('failed to append security event');

    return { id: row.id, hash };
  });
}
