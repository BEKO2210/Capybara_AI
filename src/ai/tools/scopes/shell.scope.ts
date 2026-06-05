import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { ShellCapability, ShellScope } from '../tool.types.js';

const pexecFile = promisify(execFile);

export class ShellAccessError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ShellAccessError';
  }
}

/**
 * Shell capability — DENY BY DEFAULT. No P0 tool is granted a shell scope. Even
 * when granted, only exact-match allowlisted executables may run, and they run
 * via execFile with an argv array (never a shell string), so argument values
 * cannot be interpreted as shell syntax (no injection).
 */
export function createShellCapability(scope: ShellScope | undefined): ShellCapability {
  return {
    async exec(command: string, args: string[] = []): Promise<{ stdout: string; stderr: string }> {
      if (!scope || scope.allowedCommands.length === 0) {
        throw new ShellAccessError('shell execution not granted');
      }
      if (!scope.allowedCommands.includes(command)) {
        throw new ShellAccessError(`command not allowlisted: ${command}`);
      }
      const { stdout, stderr } = await pexecFile(command, args, {
        timeout: 5_000,
        maxBuffer: 1024 * 1024,
      });
      return { stdout: String(stdout), stderr: String(stderr) };
    },
  };
}
