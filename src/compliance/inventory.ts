import { and, eq, desc } from 'drizzle-orm';
import type { AppDatabase } from '../db/client.js';
import { aiInventoryEntries, type AiInventoryEntry, type RiskClass } from '../db/schema/index.js';
import { withTenantContext, type TenantContext } from '../tenancy/scope.js';

/**
 * KI-Inventar service (EU AI Act Art. 4). Entries are auto-created on first use
 * of an LLM provider with safe defaults (risk class LIMITED, human oversight
 * required), and editable by admins.
 */
export interface InventoryInput {
  modelId?: string;
  modelName: string;
  provider: string;
  purpose?: string;
  riskClass?: RiskClass;
  humanOversightRequired?: boolean;
  dataCategoriesProcessed?: string[];
  legalBasis?: string;
  notes?: string;
}

/** Idempotently ensure an inventory entry exists for a model; returns it. */
export async function ensureInventoryEntry(
  db: AppDatabase,
  ctx: TenantContext,
  model: { modelId?: string | null; modelName: string; provider: string },
): Promise<AiInventoryEntry> {
  return withTenantContext(db, ctx, async (tx) => {
    const existing = await tx
      .select()
      .from(aiInventoryEntries)
      .where(
        and(
          eq(aiInventoryEntries.modelName, model.modelName),
          eq(aiInventoryEntries.provider, model.provider),
        ),
      )
      .limit(1);
    if (existing[0]) return existing[0];

    const [created] = await tx
      .insert(aiInventoryEntries)
      .values({
        orgId: ctx.orgId,
        modelId: model.modelId ?? null,
        modelName: model.modelName,
        provider: model.provider,
        purpose: 'Textgenerierung',
        riskClass: 'LIMITED',
        humanOversightRequired: true,
        legalBasis: 'Art. 6 Abs. 1 lit. f DSGVO (berechtigtes Interesse)',
        createdBy: ctx.userId,
      })
      .onConflictDoNothing()
      .returning();
    if (created) return created;
    // Lost a race; fetch the row the other writer inserted.
    const row = await tx
      .select()
      .from(aiInventoryEntries)
      .where(
        and(
          eq(aiInventoryEntries.modelName, model.modelName),
          eq(aiInventoryEntries.provider, model.provider),
        ),
      )
      .limit(1);
    return row[0]!;
  });
}

export function listInventory(db: AppDatabase, ctx: TenantContext): Promise<AiInventoryEntry[]> {
  return withTenantContext(db, ctx, async (tx) =>
    tx.select().from(aiInventoryEntries).orderBy(desc(aiInventoryEntries.createdAt)),
  );
}

export function createInventory(
  db: AppDatabase,
  ctx: TenantContext,
  input: InventoryInput,
): Promise<AiInventoryEntry> {
  return withTenantContext(db, ctx, async (tx) => {
    const [row] = await tx
      .insert(aiInventoryEntries)
      .values({
        orgId: ctx.orgId,
        modelId: input.modelId ?? null,
        modelName: input.modelName,
        provider: input.provider,
        purpose: input.purpose ?? '',
        riskClass: input.riskClass ?? 'LIMITED',
        humanOversightRequired: input.humanOversightRequired ?? true,
        dataCategoriesProcessed: input.dataCategoriesProcessed ?? [],
        legalBasis: input.legalBasis ?? '',
        notes: input.notes ?? '',
        createdBy: ctx.userId,
      })
      .returning();
    return row!;
  });
}

export function updateInventory(
  db: AppDatabase,
  ctx: TenantContext,
  id: string,
  input: Partial<InventoryInput>,
): Promise<AiInventoryEntry | null> {
  return withTenantContext(db, ctx, async (tx) => {
    const [row] = await tx
      .update(aiInventoryEntries)
      .set({
        ...(input.modelName !== undefined ? { modelName: input.modelName } : {}),
        ...(input.provider !== undefined ? { provider: input.provider } : {}),
        ...(input.purpose !== undefined ? { purpose: input.purpose } : {}),
        ...(input.riskClass !== undefined ? { riskClass: input.riskClass } : {}),
        ...(input.humanOversightRequired !== undefined ? { humanOversightRequired: input.humanOversightRequired } : {}),
        ...(input.dataCategoriesProcessed !== undefined ? { dataCategoriesProcessed: input.dataCategoriesProcessed } : {}),
        ...(input.legalBasis !== undefined ? { legalBasis: input.legalBasis } : {}),
        ...(input.notes !== undefined ? { notes: input.notes } : {}),
        updatedAt: new Date(),
      })
      .where(eq(aiInventoryEntries.id, id))
      .returning();
    return row ?? null;
  });
}

export function deleteInventory(db: AppDatabase, ctx: TenantContext, id: string): Promise<boolean> {
  return withTenantContext(db, ctx, async (tx) => {
    const rows = await tx
      .delete(aiInventoryEntries)
      .where(eq(aiInventoryEntries.id, id))
      .returning({ id: aiInventoryEntries.id });
    return rows.length > 0;
  });
}
