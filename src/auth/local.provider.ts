import { randomBytes } from 'node:crypto';
import { eq } from 'drizzle-orm';
import type { AppDatabase } from '../db/client.js';
import { organizations, users, memberships } from '../db/schema/index.js';
import { withTenant } from '../tenancy/scope.js';
import { hashPassword, verifyPassword } from './password.js';
import type { AuthenticatedIdentity, PasswordAuthProvider } from './provider.js';

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function slugFromEmail(email: string): string {
  const local = email.split('@')[0] ?? 'org';
  const base = local.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'org';
  return `${base}-${randomBytes(4).toString('hex')}`;
}

export interface RegistrationResult {
  readonly identity: AuthenticatedIdentity;
  readonly orgId: string;
}

/**
 * Local username/password authentication provider (development / self-host
 * default). Registration provisions a personal organization and an owner
 * membership so a new user immediately has a tenant context.
 *
 * The owner membership is inserted via `withTenant(orgId, ...)`, satisfying the
 * memberships RLS WITH CHECK policy — i.e. even bootstrap respects RLS.
 */
export class LocalAuthProvider implements PasswordAuthProvider {
  readonly id = 'local';
  readonly kind = 'password' as const;

  constructor(private readonly db: AppDatabase) {}

  async register(emailRaw: string, password: string, orgName?: string): Promise<RegistrationResult> {
    const email = normalizeEmail(emailRaw);

    const existing = await this.db
      .select({ id: users.id })
      .from(users)
      .where(eq(users.email, email))
      .limit(1);
    if (existing[0]) {
      throw new Error('email already registered');
    }

    const passwordHash = await hashPassword(password);
    const [user] = await this.db
      .insert(users)
      .values({ email, passwordHash })
      .returning({ id: users.id });
    if (!user) throw new Error('failed to create user');

    const [org] = await this.db
      .insert(organizations)
      .values({ slug: slugFromEmail(email), name: orgName ?? `${email}'s organization` })
      .returning({ id: organizations.id });
    if (!org) throw new Error('failed to create organization');

    await withTenant(this.db, org.id, async (tx) => {
      await tx.insert(memberships).values({ orgId: org.id, userId: user.id, role: 'owner' });
    });

    return { identity: { userId: user.id, email }, orgId: org.id };
  }

  async authenticate(emailRaw: string, password: string): Promise<AuthenticatedIdentity | null> {
    const email = normalizeEmail(emailRaw);
    const rows = await this.db
      .select({ id: users.id, email: users.email, passwordHash: users.passwordHash, status: users.status })
      .from(users)
      .where(eq(users.email, email))
      .limit(1);

    const user = rows[0];
    if (!user || user.status !== 'active') {
      // Perform a dummy verification to reduce user-enumeration timing signal.
      await verifyPassword(
        '$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$0000000000000000000000000000000000000000000',
        password,
      );
      return null;
    }

    const ok = await verifyPassword(user.passwordHash, password);
    if (!ok) return null;

    return { userId: user.id, email: user.email };
  }
}
