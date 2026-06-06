import { readFileSync } from 'node:fs';

/**
 * Key-material source abstraction. Today keys may come straight from the
 * environment (`env`) or from files (`file`) — the latter is the standard
 * pattern for secrets projected by a secrets manager / KMS sidecar (HashiCorp
 * Vault Agent, AWS/GCP secret CSI drivers, Docker/Kubernetes secrets), which
 * write the fetched secret to a tmpfs file rather than an env var.
 *
 * This keeps a single seam so a future native KMS client (decrypt-on-boot) can
 * be added without touching config.ts: implement another branch returning the
 * resolved key strings.
 */

export type KeySource = 'env' | 'file';

export interface ResolvedKeyMaterial {
  encryptionKey: string | undefined;
  documentEncryptionKey: string | undefined;
  masterKek: string | undefined;
}

function readKeyFile(path: string): string {
  // Trim a single trailing newline that file-projected secrets commonly carry.
  return readFileSync(path, 'utf8').replace(/\r?\n$/, '');
}

/**
 * Resolve the three at-rest key strings according to KEY_SOURCE. Throws on a
 * missing/unreadable file when `file` mode is selected and a *_FILE path is set
 * (fail-closed — we never silently fall back to a weaker source).
 */
export function resolveKeyMaterial(env: NodeJS.ProcessEnv): ResolvedKeyMaterial {
  const source = (env['KEY_SOURCE'] ?? 'env') as KeySource;
  if (source === 'file') {
    const pick = (filePath: string | undefined, inline: string | undefined): string | undefined => {
      if (filePath && filePath.trim().length > 0) return readKeyFile(filePath);
      return inline; // allow per-key fallback to inline env if no *_FILE given
    };
    return {
      encryptionKey: pick(env['ENCRYPTION_KEY_FILE'], env['ENCRYPTION_KEY']),
      documentEncryptionKey: pick(env['DOCUMENT_ENCRYPTION_KEY_FILE'], env['DOCUMENT_ENCRYPTION_KEY']),
      masterKek: pick(env['MASTER_KEK_FILE'], env['MASTER_KEK']),
    };
  }
  return {
    encryptionKey: env['ENCRYPTION_KEY'],
    documentEncryptionKey: env['DOCUMENT_ENCRYPTION_KEY'],
    masterKek: env['MASTER_KEK'],
  };
}
