import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { startTestDb, type TestDb } from '../setup/testDb.js';
import { memberships } from '../../src/db/schema/index.js';
import { withTenant } from '../../src/tenancy/scope.js';
import { LocalAuthProvider } from '../../src/auth/local.provider.js';
import {
  createSession,
  validateSession,
  revokeSession,
  hashToken,
} from '../../src/auth/session.js';

const PASSWORD = 'Correct-Horse-Battery-Staple-42';

describe('auth — local provider + opaque sessions (RLS-enforced app role)', () => {
  let t: TestDb;
  let provider: LocalAuthProvider;

  beforeAll(async () => {
    t = await startTestDb();
    provider = new LocalAuthProvider(t.app.db);
  }, 120_000);

  afterAll(async () => {
    await t?.stop();
  });

  it('registers a user, normalizes email, and provisions an owner membership', async () => {
    const { identity, orgId } = await provider.register('Alice@Example.com ', PASSWORD);
    expect(identity.email).toBe('alice@example.com');
    expect(identity.userId).toMatch(/^[0-9a-f-]{36}$/);

    // The owner membership was inserted under RLS (withTenant) during registration.
    const rows = await withTenant(t.app.db, orgId, async (tx) =>
      tx.select().from(memberships),
    );
    expect(rows).toHaveLength(1);
    expect(rows[0]?.role).toBe('owner');
    expect(rows[0]?.userId).toBe(identity.userId);
  });

  it('authenticates with the correct password', async () => {
    const identity = await provider.authenticate('alice@example.com', PASSWORD);
    expect(identity).not.toBeNull();
    expect(identity?.email).toBe('alice@example.com');
  });

  it('FAILS authentication with a wrong password (returns null, not an error)', async () => {
    const identity = await provider.authenticate('alice@example.com', 'wrong-password');
    expect(identity).toBeNull();
  });

  it('FAILS authentication for an unknown email', async () => {
    const identity = await provider.authenticate('nobody@example.com', PASSWORD);
    expect(identity).toBeNull();
  });

  it('rejects duplicate registration', async () => {
    await expect(provider.register('alice@example.com', PASSWORD)).rejects.toThrow();
  });

  it('issues an opaque session and stores only its hash (not the raw token)', async () => {
    const { identity } = await provider.register('bob@example.com', PASSWORD);
    const session = await createSession(t.app.db, { userId: identity.userId });

    // Raw token must NOT be persisted; only its SHA-256 hash.
    const stored = await t.app.sql<{ token_hash: string }[]>`
      SELECT token_hash FROM sessions WHERE user_id = ${identity.userId}
    `;
    expect(stored[0]?.token_hash).toBe(hashToken(session.token));
    expect(stored[0]?.token_hash).not.toBe(session.token);

    const validated = await validateSession(t.app.db, session.token);
    expect(validated?.userId).toBe(identity.userId);
    expect(validated?.email).toBe('bob@example.com');
  });

  it('rejects a tampered or revoked session token (fail-closed)', async () => {
    const { identity } = await provider.register('carol@example.com', PASSWORD);
    const session = await createSession(t.app.db, { userId: identity.userId });

    expect(await validateSession(t.app.db, session.token + 'x')).toBeNull();

    await revokeSession(t.app.db, session.token);
    expect(await validateSession(t.app.db, session.token)).toBeNull();
  });
});
