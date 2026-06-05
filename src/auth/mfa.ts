import { randomBytes } from 'node:crypto';
import { and, eq, isNull } from 'drizzle-orm';
import { TOTP, Secret } from 'otpauth';
import type { AppDatabase } from '../db/client.js';
import { users, mfaBackupCodes } from '../db/schema/index.js';
import { encryptSecret, decryptSecret } from '../lib/crypto.js';
import { hashPassword, verifyPassword } from './password.js';

/**
 * TOTP multi-factor authentication (RFC 6238: SHA-1, 30s period, 6 digits).
 *
 * - Enrollment: generate a secret → present an otpauth:// URI (QR) → the user
 *   must verify the first code before MFA is enabled (`mfaEnabled`).
 * - Secrets are AES-256-GCM encrypted at rest (`users.mfa_secret`).
 * - Replay defense: the matched TOTP step is recorded in `mfa_last_step`; a code
 *   from the same or an earlier step is rejected (a code cannot be used twice).
 * - Backup codes: 8 single-use codes, Argon2id-hashed, consumed on use.
 */

const PERIOD = 30;
const ISSUER = 'Capybara_AI';
const VALIDATION_WINDOW = 1; // ±1 step clock-skew tolerance
const BACKUP_CODE_COUNT = 8;

function buildTotp(secretBase32: string, label: string): TOTP {
  return new TOTP({
    issuer: ISSUER,
    label,
    algorithm: 'SHA1',
    digits: 6,
    period: PERIOD,
    secret: Secret.fromBase32(secretBase32),
  });
}

function currentStep(): number {
  return Math.floor(Date.now() / 1000 / PERIOD);
}

/** Validate a token; returns the matched absolute step, or null if invalid. */
function matchStep(secretBase32: string, token: string): number | null {
  const totp = buildTotp(secretBase32, 'verify');
  const delta = totp.validate({ token, window: VALIDATION_WINDOW });
  if (delta === null) return null;
  return currentStep() + delta;
}

export interface EnrollmentChallenge {
  secretBase32: string; // show to the user once (manual entry)
  otpauthUri: string; // encode as QR
}

/** Begin enrollment: store an encrypted secret (not yet enabled). */
export async function beginEnrollment(
  db: AppDatabase,
  userId: string,
  email: string,
  key: Buffer,
): Promise<EnrollmentChallenge> {
  const secret = new Secret({ size: 20 }); // 160-bit
  const totp = buildTotp(secret.base32, email);
  await db
    .update(users)
    .set({ mfaSecret: encryptSecret(secret.base32, key), mfaEnabled: false, mfaLastStep: null })
    .where(eq(users.id, userId));
  return { secretBase32: secret.base32, otpauthUri: totp.toString() };
}

export interface EnableResult {
  ok: boolean;
  backupCodes?: string[]; // returned once, on success
}

/** Verify the first code and enable MFA, issuing backup codes. */
export async function verifyAndEnable(
  db: AppDatabase,
  userId: string,
  token: string,
  key: Buffer,
): Promise<EnableResult> {
  const rows = await db.select().from(users).where(eq(users.id, userId)).limit(1);
  const user = rows[0];
  if (!user?.mfaSecret) return { ok: false };

  const step = matchStep(decryptSecret(user.mfaSecret, key), token);
  if (step === null) return { ok: false };

  const backupCodes = await regenerateBackupCodes(db, userId);
  await db.update(users).set({ mfaEnabled: true, mfaLastStep: step }).where(eq(users.id, userId));
  return { ok: true, backupCodes };
}

/** Whether the user has completed MFA enrollment. */
export async function isMfaEnabled(db: AppDatabase, userId: string): Promise<boolean> {
  const rows = await db
    .select({ mfaEnabled: users.mfaEnabled })
    .from(users)
    .where(eq(users.id, userId))
    .limit(1);
  return rows[0]?.mfaEnabled ?? false;
}

/** Verify a TOTP code at login. Rejects replays (same/earlier step). */
export async function verifyTotp(
  db: AppDatabase,
  userId: string,
  token: string,
  key: Buffer,
): Promise<boolean> {
  const rows = await db.select().from(users).where(eq(users.id, userId)).limit(1);
  const user = rows[0];
  if (!user || !user.mfaEnabled || !user.mfaSecret) return false;

  const step = matchStep(decryptSecret(user.mfaSecret, key), token);
  if (step === null) return false;
  if (user.mfaLastStep !== null && step <= user.mfaLastStep) return false; // replay

  await db.update(users).set({ mfaLastStep: step }).where(eq(users.id, userId));
  return true;
}

/** Consume a single-use backup code. Returns true if it was valid & unused. */
export async function verifyBackupCode(
  db: AppDatabase,
  userId: string,
  code: string,
): Promise<boolean> {
  const rows = await db
    .select()
    .from(mfaBackupCodes)
    .where(and(eq(mfaBackupCodes.userId, userId), isNull(mfaBackupCodes.usedAt)));

  for (const row of rows) {
    if (await verifyPassword(row.codeHash, code)) {
      await db
        .update(mfaBackupCodes)
        .set({ usedAt: new Date() })
        .where(eq(mfaBackupCodes.id, row.id));
      return true;
    }
  }
  return false;
}

/** Replace any existing backup codes with a fresh set; returns plaintext once. */
export async function regenerateBackupCodes(db: AppDatabase, userId: string): Promise<string[]> {
  await db.delete(mfaBackupCodes).where(eq(mfaBackupCodes.userId, userId));
  const codes = Array.from({ length: BACKUP_CODE_COUNT }, () => randomBytes(5).toString('hex'));
  const values = await Promise.all(
    codes.map(async (code) => ({ userId, codeHash: await hashPassword(code) })),
  );
  await db.insert(mfaBackupCodes).values(values);
  return codes;
}
