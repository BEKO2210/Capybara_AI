import { randomBytes } from 'node:crypto';
import { eq, desc, sql } from 'drizzle-orm';
import type { AppDatabase } from '../db/client.js';
import { encryptionKeyVersions, documentChunks, messages } from '../db/schema/index.js';
import { withTenantContext, type TenantContext, type Tx } from '../tenancy/scope.js';
import { encryptSecret, decryptSecret } from '../lib/crypto.js';
import { appendSecurityEvent } from '../audit/securityLog.js';

/** Envelope: wrap/unwrap a Data Encryption Key (DEK) with the master KEK. */
function wrapDek(dek: Buffer, kek: Buffer): string {
  return encryptSecret(dek.toString('base64'), kek);
}
function unwrapDek(blob: string, kek: Buffer): Buffer {
  return Buffer.from(decryptSecret(blob, kek), 'base64');
}

/**
 * Ensure an active key version exists for the org. Idempotent: if none exists,
 * version 1 is created wrapping `legacyDek` (so already-encrypted data remains
 * readable). Returns the active DEK.
 */
export async function ensureKeyVersion(db: AppDatabase, ctx: TenantContext, kek: Buffer, legacyDek: Buffer): Promise<Buffer> {
  return withTenantContext(db, ctx, async (tx) => {
    const active = await activeRow(tx);
    if (active) return unwrapDek(active.keyEncrypted, kek);
    await tx.insert(encryptionKeyVersions)
      .values({ orgId: ctx.orgId, keyVersion: 1, keyEncrypted: wrapDek(legacyDek, kek), active: true })
      .onConflictDoNothing();
    const created = await activeRow(tx);
    return unwrapDek(created!.keyEncrypted, kek);
  });
}

async function activeRow(tx: Tx) {
  const rows = await tx.select().from(encryptionKeyVersions).where(eq(encryptionKeyVersions.active, true)).limit(1);
  return rows[0];
}

export async function getActiveDek(db: AppDatabase, ctx: TenantContext, kek: Buffer): Promise<Buffer | null> {
  return withTenantContext(db, ctx, async (tx) => {
    const row = await activeRow(tx);
    return row ? unwrapDek(row.keyEncrypted, kek) : null;
  });
}

export interface RotationResult {
  rotated: number;
  newKeyVersion: number;
  durationMs: number;
}

/**
 * Rotate the org's DEK: generate a new DEK, re-encrypt all chunk + message
 * ciphertext in batches of 100, retire the old version (kept for audit), and
 * record a tamper-evident audit event. Fails closed if no active key exists.
 */
export async function rotateKey(db: AppDatabase, ctx: TenantContext, kek: Buffer): Promise<RotationResult> {
  const started = Date.now();
  const result = await withTenantContext(db, ctx, async (tx) => {
    const current = await activeRow(tx);
    if (!current) throw new Error('no active key version; run migration first');
    const oldDek = unwrapDek(current.keyEncrypted, kek);
    const newDek = randomBytes(32);
    const newVersion = current.keyVersion + 1;

    let rotated = 0;
    rotated += await reencryptChunks(tx, oldDek, newDek);
    rotated += await reencryptMessages(tx, oldDek, newDek);

    await tx.update(encryptionKeyVersions).set({ active: false, retiredAt: new Date() }).where(eq(encryptionKeyVersions.id, current.id));
    await tx.insert(encryptionKeyVersions).values({ orgId: ctx.orgId, keyVersion: newVersion, keyEncrypted: wrapDek(newDek, kek), active: true });
    return { rotated, newKeyVersion: newVersion };
  });

  await appendSecurityEvent(db, {
    orgId: ctx.orgId, eventType: 'encryption.rotated', severity: 'warning',
    payload: { newKeyVersion: result.newKeyVersion, rotated: result.rotated },
  });
  return { ...result, durationMs: Date.now() - started };
}

const BATCH = 100;

async function reencryptChunks(tx: Tx, oldDek: Buffer, newDek: Buffer): Promise<number> {
  let total = 0;
  for (let offset = 0; ; offset += BATCH) {
    const rows = await tx.select({ id: documentChunks.id, content: documentChunks.contentEncrypted })
      .from(documentChunks).orderBy(documentChunks.id).limit(BATCH).offset(offset);
    if (rows.length === 0) break;
    for (const row of rows) {
      await tx.update(documentChunks)
        .set({ contentEncrypted: encryptSecret(decryptSecret(row.content, oldDek), newDek) })
        .where(eq(documentChunks.id, row.id));
      total++;
    }
    if (rows.length < BATCH) break;
  }
  return total;
}

async function reencryptMessages(tx: Tx, oldDek: Buffer, newDek: Buffer): Promise<number> {
  let total = 0;
  for (let offset = 0; ; offset += BATCH) {
    const rows = await tx.select({ id: messages.id, content: messages.contentEncrypted })
      .from(messages).orderBy(messages.id).limit(BATCH).offset(offset);
    if (rows.length === 0) break;
    for (const row of rows) {
      await tx.update(messages)
        .set({ contentEncrypted: encryptSecret(decryptSecret(row.content, oldDek), newDek) })
        .where(eq(messages.id, row.id));
      total++;
    }
    if (rows.length < BATCH) break;
  }
  return total;
}

/** Count key versions (for tests / audit). */
export function countKeyVersions(db: AppDatabase, ctx: TenantContext): Promise<number> {
  return withTenantContext(db, ctx, async (tx) => {
    const r = (await tx.execute(sql`SELECT count(*)::int AS n FROM encryption_key_versions`)) as unknown as { n: number }[];
    return Number(r[0]?.n ?? 0);
  });
}
