import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { eq } from 'drizzle-orm';
import { startTestDb, type TestDb } from '../setup/testDb.js';
import { organizations, users, memberships } from '../../src/db/schema/index.js';
import { withTenant } from '../../src/tenancy/scope.js';

describe('database — tenant isolation via Postgres RLS', () => {
  let t: TestDb;
  let orgA: string;
  let orgB: string;
  let userA: string;
  let userB: string;

  beforeAll(async () => {
    t = await startTestDb();

    // Seed as the SUPERUSER admin (bypasses RLS) — represents trusted setup.
    const ua = await t.admin.db
      .insert(users)
      .values({ email: 'a@example.com', passwordHash: 'x' })
      .returning({ id: users.id });
    const ub = await t.admin.db
      .insert(users)
      .values({ email: 'b@example.com', passwordHash: 'x' })
      .returning({ id: users.id });
    const oa = await t.admin.db
      .insert(organizations)
      .values({ slug: 'org-a', name: 'Org A' })
      .returning({ id: organizations.id });
    const ob = await t.admin.db
      .insert(organizations)
      .values({ slug: 'org-b', name: 'Org B' })
      .returning({ id: organizations.id });

    userA = ua[0]!.id;
    userB = ub[0]!.id;
    orgA = oa[0]!.id;
    orgB = ob[0]!.id;

    await t.admin.db.insert(memberships).values({ orgId: orgA, userId: userA, role: 'owner' });
    await t.admin.db.insert(memberships).values({ orgId: orgB, userId: userB, role: 'owner' });
  }, 120_000);

  afterAll(async () => {
    await t?.stop();
  });

  it('the application role is NOT a superuser and cannot bypass RLS', async () => {
    const rows = await t.app.sql<
      { rolsuper: boolean; rolbypassrls: boolean }[]
    >`SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`;
    expect(rows[0]?.rolsuper).toBe(false);
    expect(rows[0]?.rolbypassrls).toBe(false);
  });

  it('returns NO rows when no tenant context is set (deny-by-default)', async () => {
    const rows = await t.app.db.select().from(memberships);
    expect(rows).toHaveLength(0);
  });

  it('within Org A context, only Org A memberships are visible', async () => {
    const rows = await withTenant(t.app.db, orgA, async (tx) =>
      tx.select().from(memberships),
    );
    expect(rows).toHaveLength(1);
    expect(rows[0]?.orgId).toBe(orgA);
  });

  it('within Org B context, Org A rows are invisible (no cross-tenant read)', async () => {
    const rows = await withTenant(t.app.db, orgB, async (tx) =>
      tx.select().from(memberships).where(eq(memberships.orgId, orgA)),
    );
    expect(rows).toHaveLength(0);
  });

  it('cannot WRITE a row into another tenant (RLS WITH CHECK blocks it)', async () => {
    let error: unknown;
    try {
      await withTenant(t.app.db, orgA, async (tx) => {
        // Acting in Org A, attempt to insert a membership owned by Org B.
        await tx.insert(memberships).values({ orgId: orgB, userId: userA, role: 'member' });
      });
    } catch (e) {
      error = e;
    }
    // The write must be rejected, and specifically by the RLS WITH CHECK policy.
    expect(error).toBeDefined();
    const cause = (error as { cause?: { message?: string } })?.cause;
    const message = `${cause?.message ?? ''} ${(error as Error)?.message ?? ''}`;
    expect(message).toMatch(/row-level security/i);
  });
});
