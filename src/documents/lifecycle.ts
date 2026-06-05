import { and, eq, isNull, or, desc } from 'drizzle-orm';
import type { AppDatabase } from '../db/client.js';
import { documents, documentAccessLog, type Document } from '../db/schema/index.js';
import { withTenantContext, type TenantContext } from '../tenancy/scope.js';
import { logAccess } from './accessLog.js';

export class LegalHoldError extends Error {
  constructor() {
    super('document is under legal hold and cannot be deleted');
    this.name = 'LegalHoldError';
  }
}

/** List non-deleted documents the caller is cleared to see (RLS enforces both). */
export function listDocuments(
  db: AppDatabase,
  ctx: TenantContext,
  page: { limit?: number; offset?: number } = {},
): Promise<Document[]> {
  const limit = Math.min(page.limit ?? 50, 200);
  const offset = page.offset ?? 0;
  return withTenantContext(db, ctx, async (tx) =>
    tx
      .select()
      .from(documents)
      .where(isNull(documents.deletedAt))
      .orderBy(desc(documents.createdAt))
      .limit(limit)
      .offset(offset),
  );
}

export function getDocument(
  db: AppDatabase,
  ctx: TenantContext,
  id: string,
): Promise<{ document: Document; accessLog: unknown[] } | null> {
  return withTenantContext(db, ctx, async (tx) => {
    const rows = await tx.select().from(documents).where(eq(documents.id, id)).limit(1);
    const doc = rows[0];
    if (!doc) return null;
    const log = await tx
      .select()
      .from(documentAccessLog)
      .where(eq(documentAccessLog.documentId, id))
      .orderBy(desc(documentAccessLog.createdAt))
      .limit(100);
    return { document: doc, accessLog: log };
  });
}

/** Version history: the root document plus all of its versions. */
export function getVersions(db: AppDatabase, ctx: TenantContext, id: string): Promise<Document[]> {
  return withTenantContext(db, ctx, async (tx) => {
    const rows = await tx.select().from(documents).where(eq(documents.id, id)).limit(1);
    const doc = rows[0];
    if (!doc) return [];
    const rootId = doc.parentId ?? doc.id;
    return tx
      .select()
      .from(documents)
      .where(or(eq(documents.id, rootId), eq(documents.parentId, rootId)))
      .orderBy(documents.version);
  });
}

/** Soft-delete a document. Blocked when legal_hold is set. */
export async function softDeleteDocument(
  db: AppDatabase,
  ctx: TenantContext,
  id: string,
  ip?: string,
): Promise<boolean> {
  return withTenantContext(db, ctx, async (tx) => {
    const rows = await tx.select().from(documents).where(eq(documents.id, id)).limit(1);
    const doc = rows[0];
    if (!doc) return false;
    if (doc.legalHold) throw new LegalHoldError();
    await tx
      .update(documents)
      .set({ deletedAt: new Date(), updatedAt: new Date() })
      .where(eq(documents.id, id));
    await logAccess(tx, { orgId: ctx.orgId, action: 'DELETE', documentId: id, userId: ctx.userId, ...(ip ? { ip } : {}) });
    return true;
  });
}

/** Set or release legal hold (route enforces who may do which). */
export function setLegalHold(
  db: AppDatabase,
  ctx: TenantContext,
  id: string,
  hold: boolean,
): Promise<boolean> {
  return withTenantContext(db, ctx, async (tx) => {
    const res = await tx
      .update(documents)
      .set({ legalHold: hold, updatedAt: new Date() })
      .where(and(eq(documents.id, id), isNull(documents.deletedAt)))
      .returning({ id: documents.id });
    return res.length > 0;
  });
}
