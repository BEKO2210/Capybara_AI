import { and, eq, inArray, sql } from 'drizzle-orm';
import type { AppDatabase } from '../db/client.js';
import { documents, documentChunks, messages, users, auditLog } from '../db/schema/index.js';
import { withTenantContext, type TenantContext } from '../tenancy/scope.js';

export interface ErasureResult {
  deletedDocuments: number;
  deletedChunks: number;
  deletedMessages: number;
  erasureTimestamp: string;
}

/**
 * GDPR Art. 17 erasure — atomic and irreversible. In a single transaction:
 * soft-delete the user's documents, hard-delete their chunks+embeddings and
 * messages, anonymize the (append-only) access log via a vetted SECURITY
 * DEFINER function, delete the account, and record an audit event. Scoped to
 * the acting org for tenant data; the account itself is removed globally.
 */
export async function eraseUser(
  db: AppDatabase,
  adminCtx: TenantContext,
  targetUserId: string,
): Promise<ErasureResult> {
  return withTenantContext(db, adminCtx, async (tx) => {
    const docs = await tx
      .select({ id: documents.id })
      .from(documents)
      .where(and(eq(documents.orgId, adminCtx.orgId), eq(documents.uploadedBy, targetUserId)));
    const docIds = docs.map((d) => d.id);

    let deletedChunks = 0;
    let deletedDocuments = 0;
    if (docIds.length > 0) {
      const chunkRows = await tx
        .delete(documentChunks)
        .where(inArray(documentChunks.documentId, docIds))
        .returning({ id: documentChunks.id });
      deletedChunks = chunkRows.length;

      const docRows = await tx
        .update(documents)
        .set({ deletedAt: new Date(), updatedAt: new Date() })
        .where(inArray(documents.id, docIds))
        .returning({ id: documents.id });
      deletedDocuments = docRows.length;
    }

    const msgRows = await tx
      .delete(messages)
      .where(eq(messages.userId, targetUserId))
      .returning({ id: messages.id });
    const deletedMessages = msgRows.length;

    // Anonymize the append-only access log (app role lacks UPDATE; the function
    // is SECURITY DEFINER and runs in this transaction).
    await tx.execute(sql`SELECT gdpr_anonymize_access_log(${targetUserId}::uuid)`);

    // Remove the account (cascades memberships/sessions/backup codes).
    await tx.delete(users).where(eq(users.id, targetUserId));

    const erasureTimestamp = new Date().toISOString();
    await tx.insert(auditLog).values({
      orgId: adminCtx.orgId,
      actorUserId: adminCtx.userId,
      action: 'gdpr.user.erased',
      targetType: 'user',
      targetId: targetUserId,
      metadata: { deletedDocuments, deletedChunks, deletedMessages, erasureTimestamp },
    });

    return { deletedDocuments, deletedChunks, deletedMessages, erasureTimestamp };
  });
}
