import { z } from 'zod';
import type { ToolDefinition } from '../tool.types.js';

/**
 * The only built-in P0 tool: a safe reference that exercises the sandbox
 * end-to-end while requesting NO capabilities (no fs/network/shell/secrets) and
 * doing nothing dangerous. It simply echoes validated input back.
 */
export const echoTool: ToolDefinition<{ message: string }> = {
  name: 'echo',
  description: 'Returns the provided message unchanged. Requests no capabilities.',
  inputSchema: z.object({ message: z.string().max(4_000) }),
  dangerous: false,
  scopes: {},
  timeoutMs: 5_000,
  handler: async (args) => ({ ok: true, output: args.message }),
};
