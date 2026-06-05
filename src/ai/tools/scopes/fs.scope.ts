import { readFile as fsReadFile, writeFile as fsWriteFile, realpath } from 'node:fs/promises';
import { resolve, dirname, basename, sep } from 'node:path';
import type { FsCapability, FsScope } from '../tool.types.js';

export class FsAccessError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'FsAccessError';
  }
}

/**
 * Resolve `p` to an absolute, symlink-resolved path and assert it lies within
 * one of the allowed roots. Defends against `..` traversal (resolve normalizes)
 * and symlink escapes (realpath). For writes, the target may not exist yet, so
 * we resolve the real parent directory and re-join the basename.
 */
async function resolveWithin(p: string, roots: string[], forWrite: boolean): Promise<string> {
  if (roots.length === 0) throw new FsAccessError('no allowed paths configured');

  const abs = resolve(p);
  let real: string;
  try {
    real = await realpath(abs);
  } catch {
    if (!forWrite) throw new FsAccessError('path not found');
    // Resolve the existing parent, then append the (non-existent) basename.
    const parent = await realpath(dirname(abs)).catch(() => {
      throw new FsAccessError('parent directory not found');
    });
    real = resolve(parent, basename(abs));
  }

  const realRoots = await Promise.all(
    roots.map((r) => realpath(r).catch(() => resolve(r))),
  );
  const contained = realRoots.some((root) => real === root || real.startsWith(root + sep));
  if (!contained) throw new FsAccessError('path is outside the allowed roots');
  return real;
}

export function createFsCapability(scope: FsScope | undefined): FsCapability {
  return {
    async readFile(p: string): Promise<string> {
      if (!scope || scope.mode === 'none') throw new FsAccessError('filesystem read not granted');
      const abs = await resolveWithin(p, scope.allowedPaths, false);
      return fsReadFile(abs, 'utf8');
    },
    async writeFile(p: string, data: string): Promise<void> {
      if (!scope || scope.mode !== 'readwrite') throw new FsAccessError('filesystem write not granted');
      const abs = await resolveWithin(p, scope.allowedPaths, true);
      await fsWriteFile(abs, data, 'utf8');
    },
  };
}
