import type { AppDatabase } from '../db/client.js';
import { meteringEvents, type MeteringEventType } from '../db/schema/index.js';
import { withTenantContext, type TenantContext, type Tx } from '../tenancy/scope.js';

export interface MeteringInput {
  eventType: MeteringEventType;
  quantity?: number;
  unit?: string;
  model?: string;
  provider?: string;
  metadata?: Record<string, unknown>;
}

function values(orgId: string, input: MeteringInput) {
  return {
    orgId,
    eventType: input.eventType,
    quantity: String(input.quantity ?? 1),
    unit: input.unit ?? 'count',
    model: input.model ?? null,
    provider: input.provider ?? null,
    metadataJson: input.metadata ?? null,
  };
}

/** Append a metering event within an existing tenant-scoped transaction. */
export async function recordMeteringTx(tx: Tx, orgId: string, input: MeteringInput): Promise<void> {
  await tx.insert(meteringEvents).values(values(orgId, input));
}

/** Append a metering event (opens its own tenant-scoped transaction). */
export async function recordMetering(db: AppDatabase, ctx: TenantContext, input: MeteringInput): Promise<void> {
  await withTenantContext(db, ctx, async (tx) => recordMeteringTx(tx, ctx.orgId, input));
}
