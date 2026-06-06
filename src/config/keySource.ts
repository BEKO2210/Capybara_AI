import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';

/**
 * Key-material source abstraction. Keys may come from the environment (`env`),
 * from files (`file`) projected by a secrets manager / KMS sidecar (Vault Agent,
 * AWS/GCP secret CSI driver, Docker/Kubernetes secrets), or from a command
 * (`command`) — e.g. `vault kv get …` or `aws kms decrypt …` — which is the
 * native-KMS integration path without bundling a cloud SDK.
 *
 * One seam, so a future in-process KMS client slots in as another branch.
 */

export type KeySource = 'env' | 'file' | 'command';

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
 * Run an operator-configured command and return its stdout (trimmed). The
 * command string is trusted server configuration (like a cron entry), executed
 * via the shell so operators can use pipes/flags. A non-zero exit throws,
 * keeping startup fail-closed.
 */
function readKeyCommand(command: string): string {
  return execFileSync('/bin/sh', ['-c', command], { encoding: 'utf8', maxBuffer: 1 << 20 }).replace(/\r?\n$/, '');
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
  if (source === 'command') {
    const pick = (cmd: string | undefined, inline: string | undefined): string | undefined => {
      if (cmd && cmd.trim().length > 0) return readKeyCommand(cmd);
      return inline; // per-key fallback to inline env if no *_COMMAND given
    };
    return {
      encryptionKey: pick(env['ENCRYPTION_KEY_COMMAND'], env['ENCRYPTION_KEY']),
      documentEncryptionKey: pick(env['DOCUMENT_ENCRYPTION_KEY_COMMAND'], env['DOCUMENT_ENCRYPTION_KEY']),
      masterKek: pick(env['MASTER_KEK_COMMAND'], env['MASTER_KEK']),
    };
  }
  return {
    encryptionKey: env['ENCRYPTION_KEY'],
    documentEncryptionKey: env['DOCUMENT_ENCRYPTION_KEY'],
    masterKek: env['MASTER_KEK'],
  };
}
