import { randomBytes, createHash } from 'node:crypto';
import { mkdir, writeFile, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import { eq, isNull } from 'drizzle-orm';

// archiver ships as CommonJS; load via require for reliable interop under both
// the Node ESM build and the vitest transform. v8 exposes the Archiver class.
const require = createRequire(import.meta.url);
const archiver = require('archiver') as (
  format: string,
  options?: { zlib?: { level?: number } },
) => import('archiver').Archiver;
import type { AppDatabase } from '../db/client.js';
import {
  exportJobs, users, memberships, documents, conversations, messages, auditLog, aiInventoryEntries,
  type ExportJob,
} from '../db/schema/index.js';
import { withTenantContext, type TenantContext } from '../tenancy/scope.js';
import { encryptSecret, decryptSecret, deriveTenantKey } from '../lib/crypto.js';
import { readEncrypted } from '../documents/storage.js';

export interface ExportDeps {
  storageDir: string; // where export artifacts are written
  documentStorageDir: string;
  masterKey: Buffer;
}

export async function createExportJob(db: AppDatabase, ctx: TenantContext): Promise<{ jobId: string }> {
  const job = await withTenantContext(db, ctx, async (tx) => {
    const [row] = await tx
      .insert(exportJobs)
      .values({ orgId: ctx.orgId, requestedBy: ctx.userId, status: 'PENDING' })
      .returning({ id: exportJobs.id });
    return row!;
  });
  return { jobId: job.id };
}

export function getJob(db: AppDatabase, ctx: TenantContext, jobId: string): Promise<ExportJob | null> {
  return withTenantContext(db, ctx, async (tx) => {
    const rows = await tx.select().from(exportJobs).where(eq(exportJobs.id, jobId)).limit(1);
    return rows[0] ?? null;
  });
}

/** Build the encrypted export ZIP and mark the job DONE. */
export async function runExportJob(db: AppDatabase, ctx: TenantContext, jobId: string, deps: ExportDeps): Promise<void> {
  await withTenantContext(db, ctx, (tx) => tx.update(exportJobs).set({ status: 'RUNNING' }).where(eq(exportJobs.id, jobId)));
  try {
    const tenantKey = deriveTenantKey(deps.masterKey, ctx.orgId);

    const payload = await withTenantContext(db, ctx, async (tx) => {
      const userRows = await tx
        .select({ id: users.id, email: users.email, role: memberships.role, status: users.status })
        .from(memberships).innerJoin(users, eq(users.id, memberships.userId));
      const docRows = await tx.select().from(documents).where(isNull(documents.deletedAt));
      const convRows = await tx.select().from(conversations);
      const msgRows = await tx.select().from(messages);
      const auditRows = await tx.select().from(auditLog).where(eq(auditLog.orgId, ctx.orgId));
      const invRows = await tx.select().from(aiInventoryEntries);
      return { userRows, docRows, convRows, msgRows, auditRows, invRows };
    });

    const archive = archiver('zip', { zlib: { level: 9 } });
    const chunks: Buffer[] = [];
    archive.on('data', (c: Buffer) => chunks.push(c));
    const built = new Promise<Buffer>((resolve, reject) => {
      archive.on('end', () => resolve(Buffer.concat(chunks)));
      archive.on('error', reject);
    });

    archive.append(JSON.stringify(payload.userRows, null, 2), { name: 'org_data/users.json' });
    archive.append(
      JSON.stringify(payload.convRows.map((c) => ({ ...c, messages: payload.msgRows.filter((m) => m.conversationId === c.id).map((m) => ({ ...m, content: decryptSecret(m.contentEncrypted, tenantKey) })) })), null, 2),
      { name: 'org_data/conversations.json' },
    );
    archive.append(JSON.stringify(payload.auditRows, null, 2), { name: 'org_data/audit_log.json' });
    archive.append(JSON.stringify(payload.invRows, null, 2), { name: 'org_data/inventory.json' });
    for (const doc of payload.docRows) {
      try {
        const original = await readEncrypted(deps.documentStorageDir, ctx.orgId, deps.masterKey, doc.storagePath);
        archive.append(original, { name: `org_data/documents/${doc.id}-${doc.title}` });
      } catch {
        // skip unreadable artifact
      }
    }
    await archive.finalize();
    const zip = await built;

    // Encrypt the ZIP at rest with the per-tenant key.
    const encrypted = encryptSecret(zip.toString('base64'), tenantKey);
    const dir = join(deps.storageDir, ctx.orgId);
    await mkdir(dir, { recursive: true });
    const filePath = join(dir, `${jobId}.zip.enc`);
    await writeFile(filePath, encrypted, 'utf8');

    const token = randomBytes(32).toString('base64url');
    await withTenantContext(db, ctx, (tx) =>
      tx.update(exportJobs).set({
        status: 'DONE', filePath, downloadTokenHash: createHash('sha256').update(token).digest('hex'),
        expiresAt: new Date(Date.now() + 60 * 60 * 1000), completedAt: new Date(),
      }).where(eq(exportJobs.id, jobId)),
    );
    // Stash the one-time token where the caller can read it (job row not used for token plaintext).
    exportTokens.set(jobId, token);
  } catch (err) {
    await withTenantContext(db, ctx, (tx) =>
      tx.update(exportJobs).set({ status: 'FAILED', error: err instanceof Error ? err.message : String(err) }).where(eq(exportJobs.id, jobId)),
    );
  }
}

/** One-time download tokens kept in memory until first surfaced to the requester. */
const exportTokens = new Map<string, string>();
export function takeDownloadToken(jobId: string): string | undefined {
  const t = exportTokens.get(jobId);
  if (t) exportTokens.delete(jobId);
  return t;
}

/** Resolve a download: validates token + expiry, returns the decrypted ZIP, then deletes it. */
export async function consumeDownload(
  db: AppDatabase,
  ctx: TenantContext,
  jobId: string,
  token: string,
  deps: ExportDeps,
): Promise<Buffer | null> {
  const job = await getJob(db, ctx, jobId);
  if (!job || job.status !== 'DONE' || !job.filePath || !job.downloadTokenHash) return null;
  if (!job.expiresAt || job.expiresAt.getTime() < Date.now()) return null;
  if (createHash('sha256').update(token).digest('hex') !== job.downloadTokenHash) return null;

  const tenantKey = deriveTenantKey(deps.masterKey, ctx.orgId);
  const blob = await readFile(job.filePath, 'utf8');
  const zip = Buffer.from(decryptSecret(blob, tenantKey), 'base64');

  // Delete the artifact after download.
  await rm(job.filePath, { force: true });
  await withTenantContext(db, ctx, (tx) => tx.update(exportJobs).set({ status: 'EXPIRED' }).where(eq(exportJobs.id, jobId)));
  return zip;
}
