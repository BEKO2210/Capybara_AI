import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { randomBytes } from 'node:crypto';
import { eq } from 'drizzle-orm';
import { TOTP, Secret } from 'otpauth';
import { startTestDb, type TestDb } from '../setup/testDb.js';
import { users } from '../../src/db/schema/index.js';
import { LocalAuthProvider } from '../../src/auth/local.provider.js';
import {
  beginEnrollment,
  verifyAndEnable,
  verifyTotp,
  verifyBackupCode,
  isMfaEnabled,
} from '../../src/auth/mfa.js';

const KEY = randomBytes(32);
const PERIOD = 30;

function tokenFor(secretBase32: string): string {
  const totp = new TOTP({
    issuer: 'Capybara_AI',
    label: 'test',
    algorithm: 'SHA1',
    digits: 6,
    period: PERIOD,
    secret: Secret.fromBase32(secretBase32),
  });
  return totp.generate();
}

function currentStep(): number {
  return Math.floor(Date.now() / 1000 / PERIOD);
}

describe('auth/mfa — TOTP second factor', () => {
  let t: TestDb;
  let userId: string;
  let secretBase32: string;
  let backupCodes: string[];

  beforeAll(async () => {
    t = await startTestDb();
    const provider = new LocalAuthProvider(t.app.db);
    const { identity } = await provider.register('mfa@example.com', 'Correct-Horse-Battery-42');
    userId = identity.userId;
  }, 120_000);

  afterAll(async () => {
    await t?.stop();
  });

  it('begins enrollment without enabling MFA', async () => {
    const challenge = await beginEnrollment(t.app.db, userId, 'mfa@example.com', KEY);
    secretBase32 = challenge.secretBase32;
    expect(challenge.otpauthUri).toMatch(/^otpauth:\/\/totp\//);
    expect(await isMfaEnabled(t.app.db, userId)).toBe(false);
  });

  it('rejects a wrong code during enrollment (stays disabled)', async () => {
    const res = await verifyAndEnable(t.app.db, userId, '000000', KEY);
    expect(res.ok).toBe(false);
    expect(await isMfaEnabled(t.app.db, userId)).toBe(false);
  });

  it('enables MFA on a correct code and issues 8 backup codes', async () => {
    const res = await verifyAndEnable(t.app.db, userId, tokenFor(secretBase32), KEY);
    expect(res.ok).toBe(true);
    expect(res.backupCodes).toHaveLength(8);
    backupCodes = res.backupCodes!;
    expect(await isMfaEnabled(t.app.db, userId)).toBe(true);
  });

  it('verifies a correct TOTP at login and then blocks replay of the same code', async () => {
    // Simulate a later login window so the just-enrolled step doesn't block us.
    await t.app.db.update(users).set({ mfaLastStep: currentStep() - 1 }).where(eq(users.id, userId));
    const token = tokenFor(secretBase32);
    expect(await verifyTotp(t.app.db, userId, token, KEY)).toBe(true);
    // Same code in the same window must now be rejected (replay).
    expect(await verifyTotp(t.app.db, userId, token, KEY)).toBe(false);
  });

  it('rejects a wrong TOTP at login', async () => {
    expect(await verifyTotp(t.app.db, userId, '111111', KEY)).toBe(false);
  });

  it('consumes a backup code once and rejects reuse / unknown codes', async () => {
    const code = backupCodes[0]!;
    expect(await verifyBackupCode(t.app.db, userId, code)).toBe(true);
    expect(await verifyBackupCode(t.app.db, userId, code)).toBe(false); // already used
    expect(await verifyBackupCode(t.app.db, userId, 'deadbeef00')).toBe(false);
  });
});
