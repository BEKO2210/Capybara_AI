import { createPrivateKey, createPublicKey, sign as edSign, verify as edVerify, type KeyObject } from 'node:crypto';
import { appendFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { asc, desc, sql } from 'drizzle-orm';
import type { AppDatabase } from '../db/client.js';
import { auditAnchors, securityEvents } from '../db/schema/index.js';
import { canonicalJson } from '../lib/hash.js';

/**
 * Off-box anchoring of the tamper-evident security-event chain.
 *
 * A checkpoint commits to the current chain head (last event id + hash + count)
 * and is signed with an Ed25519 key. Verification uses a public key held
 * OUTSIDE the database, so a DB superuser who rewrites `security_events` cannot
 * forge a matching anchor — the divergence is detectable. Checkpoints may also
 * be shipped to an append-only off-box sink (file today; webhook/object store
 * by supplying a custom sink).
 */

export const ANCHOR_ALGORITHM = 'ed25519';

export interface AnchorContent {
  checkpointSeq: number;
  eventId: number;
  eventCount: number;
  chainHash: string;
  createdAt: string; // ISO
}

/** Deterministic bytes the signature commits to. */
export function anchorMessage(c: AnchorContent): Buffer {
  return Buffer.from(
    canonicalJson({
      checkpointSeq: c.checkpointSeq,
      eventId: c.eventId,
      eventCount: c.eventCount,
      chainHash: c.chainHash,
      createdAt: c.createdAt,
      algorithm: ANCHOR_ALGORITHM,
    }),
    'utf8',
  );
}

export function loadAnchorPrivateKey(pem: string): KeyObject {
  return createPrivateKey(pem);
}
export function loadAnchorPublicKey(pem: string): KeyObject {
  return createPublicKey(pem);
}

/** A consumer for newly created anchors (e.g. ship off-box). */
export type AnchorSink = (record: AnchorContent & { signature: string }) => Promise<void> | void;

/**
 * Append each checkpoint as a JSON line to `<dir>/anchors.jsonl`. Pairs with a
 * write-once / append-only medium (e.g. an object-lock bucket synced from dir)
 * to make the off-box copy independent of the database.
 */
export function fileAnchorSink(dir: string): AnchorSink {
  return async (record) => {
    await mkdir(dir, { recursive: true });
    await appendFile(join(dir, 'anchors.jsonl'), JSON.stringify(record) + '\n', { mode: 0o600 });
  };
}

interface ChainHead {
  eventId: number;
  eventCount: number;
  chainHash: string;
}

const GENESIS_HEAD: ChainHead = { eventId: 0, eventCount: 0, chainHash: '0'.repeat(64) };

async function chainHead(db: AppDatabase): Promise<ChainHead> {
  const last = await db
    .select({ id: securityEvents.id, hash: securityEvents.hash })
    .from(securityEvents)
    .orderBy(desc(securityEvents.id))
    .limit(1);
  if (!last[0]) return GENESIS_HEAD;
  const cnt = (await db.execute(sql`SELECT count(*)::bigint AS n FROM security_events`)) as unknown as { n: string | number }[];
  return { eventId: last[0].id, eventCount: Number(cnt[0]?.n ?? 0), chainHash: last[0].hash };
}

export interface AnchorResult {
  checkpointSeq: number;
  eventId: number;
  eventCount: number;
  chainHash: string;
}

/**
 * Create a signed checkpoint over the current chain head. Idempotent-ish: if the
 * head is unchanged since the last anchor, no new anchor is written and the
 * previous one is returned (avoids redundant checkpoints on idle systems).
 */
export async function createAnchor(
  db: AppDatabase,
  privateKey: KeyObject,
  sink?: AnchorSink,
): Promise<AnchorResult> {
  const head = await chainHead(db);
  const lastRows = await db.select().from(auditAnchors).orderBy(desc(auditAnchors.checkpointSeq)).limit(1);
  const last = lastRows[0];
  if (last && last.eventId === head.eventId && last.chainHash === head.chainHash) {
    return { checkpointSeq: last.checkpointSeq, eventId: last.eventId, eventCount: last.eventCount, chainHash: last.chainHash };
  }
  const checkpointSeq = (last?.checkpointSeq ?? 0) + 1;
  const createdAt = new Date();
  const content: AnchorContent = {
    checkpointSeq,
    eventId: head.eventId,
    eventCount: head.eventCount,
    chainHash: head.chainHash,
    createdAt: createdAt.toISOString(),
  };
  const signature = edSign(null, anchorMessage(content), privateKey).toString('base64');

  await db.insert(auditAnchors).values({
    checkpointSeq,
    eventId: head.eventId,
    eventCount: head.eventCount,
    chainHash: head.chainHash,
    algorithm: ANCHOR_ALGORITHM,
    signature,
    createdAt,
  });

  if (sink) await sink({ ...content, signature });
  return { checkpointSeq, eventId: head.eventId, eventCount: head.eventCount, chainHash: head.chainHash };
}

export interface AnchorVerification {
  ok: boolean;
  checked: number;
  brokenAt?: number; // checkpointSeq
  reason?: 'bad_signature' | 'hash_mismatch' | 'missing_event';
}

/**
 * Verify every anchor: (1) the Ed25519 signature is valid under the public key,
 * and (2) the anchored chain_hash still matches the referenced event's stored
 * hash. A rewritten chain fails (2); a forged anchor fails (1).
 */
export async function verifyAnchors(db: AppDatabase, publicKey: KeyObject): Promise<AnchorVerification> {
  const anchors = await db.select().from(auditAnchors).orderBy(asc(auditAnchors.checkpointSeq));
  let checked = 0;
  for (const a of anchors) {
    const content: AnchorContent = {
      checkpointSeq: a.checkpointSeq,
      eventId: a.eventId,
      eventCount: a.eventCount,
      chainHash: a.chainHash,
      createdAt: a.createdAt.toISOString(),
    };
    const sigOk = edVerify(null, anchorMessage(content), publicKey, Buffer.from(a.signature, 'base64'));
    if (!sigOk) return { ok: false, checked, brokenAt: a.checkpointSeq, reason: 'bad_signature' };

    if (a.eventId > 0) {
      const rows = await db
        .select({ hash: securityEvents.hash })
        .from(securityEvents)
        .where(sql`${securityEvents.id} = ${a.eventId}`)
        .limit(1);
      if (!rows[0]) return { ok: false, checked, brokenAt: a.checkpointSeq, reason: 'missing_event' };
      if (rows[0].hash !== a.chainHash) return { ok: false, checked, brokenAt: a.checkpointSeq, reason: 'hash_mismatch' };
    }
    checked++;
  }
  return { ok: true, checked };
}
