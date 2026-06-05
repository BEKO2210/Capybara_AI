import { eq } from 'drizzle-orm';
import type { AppDatabase } from '../db/client.js';
import { documents, documentChunks, CLASSIFICATION_RANK, type Classification } from '../db/schema/index.js';
import { withTenantContext } from '../tenancy/scope.js';
import { encryptSecret, deriveTenantKey } from '../lib/crypto.js';
import type { Embedder } from '../ai/embeddings/embedder.js';
import { detectKind, extractText } from './extract.js';
import { chunkText } from './chunk.js';
import { storeEncrypted, deleteStored } from './storage.js';
import { logAccess } from './accessLog.js';
import type { Scanner } from './clamav.js';

export class IngestError extends Error {
  constructor(
    message: string,
    readonly code: 'unsupported_type' | 'infected' | 'classification_exceeds_clearance' | 'empty',
  ) {
    super(message);
    this.name = 'IngestError';
  }
}

export interface IngestDeps {
  db: AppDatabase;
  embedder: Embedder;
  storageDir: string;
  masterKey: Buffer;
  scan?: Scanner | undefined;
}

export interface IngestInput {
  orgId: string;
  userId: string;
  clearance: number;
  title: string;
  mimeType: string;
  classification: Classification;
  data: Buffer;
  ip?: string | undefined;
  parentId?: string | undefined;
  version?: number | undefined;
}

export interface IngestResult {
  documentId: string;
  title: string;
  chunkCount: number;
  classification: Classification;
}

/**
 * Document ingestion pipeline (steps 2–10; auth/size are enforced by the route).
 * MIME allowlist → optional virus scan → encrypted storage → text extraction →
 * chunking → embedding → encrypted chunk + vector persistence → UPLOAD log.
 * Every dangerous default fails closed.
 */
export async function ingestDocument(deps: IngestDeps, input: IngestInput): Promise<IngestResult> {
  const kind = detectKind(input.mimeType);
  if (!kind) throw new IngestError(`unsupported MIME type: ${input.mimeType}`, 'unsupported_type');

  // Cannot upload a document more sensitive than your own clearance.
  if (CLASSIFICATION_RANK[input.classification] > input.clearance) {
    throw new IngestError('classification exceeds uploader clearance', 'classification_exceeds_clearance');
  }

  // Virus scan (if configured). Fail closed on infection.
  if (deps.scan) {
    const result = await deps.scan(input.data);
    if (!result.clean) {
      throw new IngestError(`infected: ${result.signature ?? 'unknown'}`, 'infected');
    }
  }

  const text = await extractText(input.data, kind);
  const chunks = chunkText(text);
  if (chunks.length === 0) throw new IngestError('no extractable text', 'empty');

  // Embed before touching the DB so a provider failure leaves no partial state.
  const vectors = await deps.embedder.embed(chunks.map((c) => c.content));

  // Store the encrypted original; roll back the file if the DB write fails.
  const stored = await storeEncrypted(deps.storageDir, input.orgId, deps.masterKey, input.data);
  const tenantKey = deriveTenantKey(deps.masterKey, input.orgId);

  try {
    return await withTenantContext(
      deps.db,
      { orgId: input.orgId, userId: input.userId, clearance: input.clearance },
      async (tx) => {
        const [doc] = await tx
          .insert(documents)
          .values({
            orgId: input.orgId,
            uploadedBy: input.userId,
            title: input.title,
            mimeType: input.mimeType,
            storagePath: stored.storagePath,
            sizeBytes: stored.sizeBytes,
            classification: input.classification,
            ...(input.parentId ? { parentId: input.parentId } : {}),
            ...(input.version ? { version: input.version } : {}),
          })
          .returning({ id: documents.id });
        if (!doc) throw new Error('failed to insert document');

        await tx.insert(documentChunks).values(
          chunks.map((c, i) => ({
            orgId: input.orgId,
            documentId: doc.id,
            chunkIndex: c.index,
            contentEncrypted: encryptSecret(c.content, tenantKey),
            embedding: vectors[i]!,
            classification: input.classification,
            tokenCount: c.tokenCount,
          })),
        );

        await logAccess(tx, {
          orgId: input.orgId,
          action: 'UPLOAD',
          documentId: doc.id,
          userId: input.userId,
          ...(input.ip ? { ip: input.ip } : {}),
        });

        return {
          documentId: doc.id,
          title: input.title,
          chunkCount: chunks.length,
          classification: input.classification,
        };
      },
    );
  } catch (err) {
    await deleteStored(deps.storageDir, stored.storagePath).catch(() => {});
    throw err;
  }
}

/** Helper for the GET /documents/:id/upload new-version flow. */
export async function nextVersionFor(db: AppDatabase, ctx: { orgId: string; userId: string; clearance: number }, documentId: string): Promise<{ parentId: string; version: number; title: string; classification: Classification } | null> {
  return withTenantContext(db, ctx, async (tx) => {
    const rows = await tx.select().from(documents).where(eq(documents.id, documentId)).limit(1);
    const doc = rows[0];
    if (!doc) return null;
    return {
      parentId: doc.parentId ?? doc.id,
      version: doc.version + 1,
      title: doc.title,
      classification: doc.classification as Classification,
    };
  });
}
