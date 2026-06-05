import { createCipheriv, createDecipheriv, randomBytes, hkdfSync } from 'node:crypto';

/**
 * Derive a deterministic, per-tenant 32-byte subkey from a master key using
 * HKDF-SHA256, with the organization id as salt. Different orgs get
 * cryptographically independent keys, so a leak of one tenant's derived key
 * does not expose others, and the master key never encrypts data directly.
 */
export function deriveTenantKey(masterKey: Buffer, orgId: string): Buffer {
  const derived = hkdfSync('sha256', masterKey, Buffer.from(orgId, 'utf8'), Buffer.from('capybara-doc-v1'), 32);
  return Buffer.from(derived);
}

/**
 * Authenticated symmetric encryption for secrets at rest (e.g. TOTP secrets),
 * using AES-256-GCM with a server-held 32-byte key (`ENCRYPTION_KEY`).
 *
 * Wire format (base64): [12-byte IV][16-byte GCM tag][ciphertext].
 * GCM provides integrity: tampering causes decryption to throw.
 */
const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const TAG_LENGTH = 16;

export function encryptSecret(plaintext: string, key: Buffer): string {
  if (key.length !== 32) throw new Error('encryption key must be 32 bytes');
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, key, iv);
  const enc = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString('base64');
}

export function decryptSecret(blob: string, key: Buffer): string {
  if (key.length !== 32) throw new Error('encryption key must be 32 bytes');
  const buf = Buffer.from(blob, 'base64');
  if (buf.length < IV_LENGTH + TAG_LENGTH) throw new Error('ciphertext too short');
  const iv = buf.subarray(0, IV_LENGTH);
  const tag = buf.subarray(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
  const enc = buf.subarray(IV_LENGTH + TAG_LENGTH);
  const decipher = createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(enc), decipher.final()]).toString('utf8');
}
