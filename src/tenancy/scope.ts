import { sql } from 'drizzle-orm';
import type { AppDatabase } from '../db/client.js';

/**
 * Tenant/identity scoping for Row-Level Security.
 *
 * Every tenant-scoped data access runs inside a transaction that sets the
 * `app.current_org` GUC (and, for identity operations, `app.current_user_id`)
 * via set_config(...) — parameterised, so values can never be injected. The
 * Postgres RLS policies read these GUCs; because the app role cannot bypass
 * RLS, this is the authoritative isolation boundary.
 */

/** The exact transaction type Drizzle hands to a transaction callback. */
export type Tx = Parameters<Parameters<AppDatabase['transaction']>[0]>[0];

/** Run `fn` with the active tenant set to `orgId` (local to the transaction). */
export function withTenant<T>(
  db: AppDatabase,
  orgId: string,
  fn: (tx: Tx) => Promise<T>,
): Promise<T> {
  return db.transaction(async (tx) => {
    await tx.execute(sql`SELECT set_config('app.current_org', ${orgId}, true)`);
    return fn(tx);
  });
}

/** Run `fn` with the acting identity set to `userId` (e.g. cross-org lookups). */
export function withIdentity<T>(
  db: AppDatabase,
  userId: string,
  fn: (tx: Tx) => Promise<T>,
): Promise<T> {
  return db.transaction(async (tx) => {
    await tx.execute(sql`SELECT set_config('app.current_user_id', ${userId}, true)`);
    return fn(tx);
  });
}

/** Run `fn` with both tenant and identity context set. */
export function withTenantAndIdentity<T>(
  db: AppDatabase,
  orgId: string,
  userId: string,
  fn: (tx: Tx) => Promise<T>,
): Promise<T> {
  return db.transaction(async (tx) => {
    await tx.execute(sql`SELECT set_config('app.current_org', ${orgId}, true)`);
    await tx.execute(sql`SELECT set_config('app.current_user_id', ${userId}, true)`);
    return fn(tx);
  });
}
