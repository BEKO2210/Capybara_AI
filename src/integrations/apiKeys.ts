import { randomBytes, createHash } from 'node:crypto';
import { eq, desc, sql } from 'drizzle-orm';
import type { AppDatabase } from '../db/client.js';
import { apiKeys, type ApiKey, type ApiKeyScope } from '../db/schema/index.js';
import { withTenantContext, type TenantContext } from '../tenancy/scope.js';

const PREFIX = 'capy_';

function hashKey(raw: string): string {
  return createHash('sha256').update(raw).digest('hex');
}

export interface CreatedApiKey {
  id: string;
  key: string; // returned ONCE
  prefix: string;
}

export async function createApiKey(
  db: AppDatabase,
  ctx: TenantContext,
  input: { name: string; scopes: ApiKeyScope[]; expiresAt?: Date | null },
): Promise<CreatedApiKey> {
  const raw = PREFIX + randomBytes(24).toString('base64url');
  const keyPrefix = raw.slice(0, 8);
  return withTenantContext(db, ctx, async (tx) => {
    const [row] = await tx
      .insert(apiKeys)
      .values({
        orgId: ctx.orgId,
        createdBy: ctx.userId,
        name: input.name,
        keyHash: hashKey(raw),
        keyPrefix,
        scopes: input.scopes,
        expiresAt: input.expiresAt ?? null,
      })
      .returning({ id: apiKeys.id });
    return { id: row!.id, key: raw, prefix: keyPrefix };
  });
}

export function listApiKeys(db: AppDatabase, ctx: TenantContext): Promise<Omit<ApiKey, 'keyHash'>[]> {
  return withTenantContext(db, ctx, async (tx) => {
    const rows = await tx.select().from(apiKeys).orderBy(desc(apiKeys.createdAt));
    return rows.map(({ keyHash, ...rest }) => rest);
  });
}

export function revokeApiKey(db: AppDatabase, ctx: TenantContext, id: string): Promise<boolean> {
  return withTenantContext(db, ctx, async (tx) => {
    const rows = await tx.update(apiKeys).set({ active: false }).where(eq(apiKeys.id, id)).returning({ id: apiKeys.id });
    return rows.length > 0;
  });
}

export interface AuthenticatedApiKey {
  keyId: string;
  orgId: string;
  scopes: string[];
}

/** Authenticate a raw API key. Returns null on any failure (fail-closed). */
export async function authenticateApiKey(db: AppDatabase, raw: string): Promise<AuthenticatedApiKey | null> {
  if (!raw || !raw.startsWith(PREFIX)) return null;
  const rows = (await db.execute(sql`SELECT * FROM api_key_by_hash(${hashKey(raw)})`)) as unknown as Array<{
    id: string; org_id: string; scopes: string[]; expires_at: string | null; active: boolean;
  }>;
  const r = rows[0];
  if (!r || !r.active) return null;
  if (r.expires_at && new Date(r.expires_at).getTime() < Date.now()) return null;

  // Best-effort last-used stamp (within tenant context).
  await withTenantContext(db, { orgId: r.org_id, userId: r.org_id, clearance: 0 }, async (tx) => {
    await tx.update(apiKeys).set({ lastUsedAt: new Date() }).where(eq(apiKeys.id, r.id));
  }).catch(() => {});

  return { keyId: r.id, orgId: r.org_id, scopes: r.scopes };
}
