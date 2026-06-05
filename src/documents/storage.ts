import { mkdir, writeFile, readFile, rm } from 'node:fs/promises';
import { join, dirname, normalize } from 'node:path';
import { randomUUID } from 'node:crypto';
import { encryptSecret, decryptSecret, deriveTenantKey } from '../lib/crypto.js';

/**
 * Encrypted file storage. Files are written under `{baseDir}/{orgId}/{uuid}.enc`
 * — a random UUID, never the original filename — and encrypted with AES-256-GCM
 * under the org's HKDF-derived subkey. The DB stores only the relative path.
 */
export interface StoredFile {
  storagePath: string; // relative: {orgId}/{uuid}.enc
  sizeBytes: number;
}

function resolveSafe(baseDir: string, relativePath: string): string {
  const abs = normalize(join(baseDir, relativePath));
  const root = normalize(baseDir);
  if (abs !== root && !abs.startsWith(root + '/')) {
    throw new Error('storage path escapes base directory');
  }
  return abs;
}

export async function storeEncrypted(
  baseDir: string,
  orgId: string,
  masterKey: Buffer,
  data: Buffer,
): Promise<StoredFile> {
  const key = deriveTenantKey(masterKey, orgId);
  const relativePath = `${orgId}/${randomUUID()}.enc`;
  const abs = resolveSafe(baseDir, relativePath);
  await mkdir(dirname(abs), { recursive: true });
  await writeFile(abs, encryptSecret(data.toString('base64'), key), 'utf8');
  return { storagePath: relativePath, sizeBytes: data.length };
}

export async function readEncrypted(
  baseDir: string,
  orgId: string,
  masterKey: Buffer,
  storagePath: string,
): Promise<Buffer> {
  const key = deriveTenantKey(masterKey, orgId);
  const blob = await readFile(resolveSafe(baseDir, storagePath), 'utf8');
  return Buffer.from(decryptSecret(blob, key), 'base64');
}

export async function deleteStored(baseDir: string, storagePath: string): Promise<void> {
  await rm(resolveSafe(baseDir, storagePath), { force: true });
}
