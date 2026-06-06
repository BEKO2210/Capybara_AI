import { createFsCapability } from './scopes/fs.scope.js';
import { createNetCapability } from './scopes/network.scope.js';
import { createShellCapability } from './scopes/shell.scope.js';
import { redact as defaultRedact } from '../redaction/redactor.js';
import type { ApprovalGate } from './approval.js';
import type { ToolRegistry } from './registry.js';
import { UnknownToolError } from './registry.js';
import type { ToolContext, ToolResult, ToolScopes, IsolationRunner } from './tool.types.js';
import { requiresOversight, type OversightGate } from '../../compliance/oversight.js';

export type ToolDecision = 'allowed' | 'denied' | 'pending_approval';

export interface ToolInvocation {
  tool: string;
  decision: ToolDecision;
  /** Present when decision === 'allowed'. */
  result?: ToolResult;
  /** Machine-readable reason for denial/pending. */
  reason?: string;
  /** Oversight request id when decision === 'pending_approval' (risk >= HIGH). */
  requestId?: string;
  /** Redacted copy of the arguments, safe to log/persist. */
  redactedArgs: unknown;
}

export interface ExecuteOptions {
  approvals: ApprovalGate;
  /** Secrets available to grant; only those listed in a tool's scope are passed. */
  secrets?: Record<string, string>;
  /** Override redaction (defaults to the pattern-based redactor). */
  redactor?: (value: unknown) => unknown;
  /** Injectable fetch for network-scoped tools (tests). */
  fetchImpl?: typeof fetch;
  /** DB-backed human-oversight gate (required for HIGH/CRITICAL-risk tools). */
  oversight?: OversightGate;
  /**
   * External isolation runner for tools marked `requiresIsolation`. When absent,
   * such tools are DENIED (fail-closed) — untrusted code never runs in-process.
   */
  isolationRunner?: IsolationRunner;
}

class ToolTimeoutError extends Error {
  constructor() {
    super('tool execution timed out');
    this.name = 'ToolTimeoutError';
  }
}

function buildContext(
  scopes: ToolScopes,
  deps: { secrets: Record<string, string>; signal: AbortSignal; fetchImpl?: typeof fetch },
): ToolContext {
  const grantedSecrets: Record<string, string> = {};
  for (const key of scopes.secrets ?? []) {
    const value = deps.secrets[key];
    if (value !== undefined) grantedSecrets[key] = value;
  }

  return {
    fs: createFsCapability(scopes.fs),
    net: createNetCapability(scopes.network, deps.fetchImpl ?? fetch),
    shell: createShellCapability(scopes.shell),
    secrets: Object.freeze(grantedSecrets),
    signal: deps.signal,
  };
}

function abortRejection(signal: AbortSignal): Promise<never> {
  return new Promise<never>((_, reject) => {
    if (signal.aborted) return reject(new ToolTimeoutError());
    signal.addEventListener('abort', () => reject(new ToolTimeoutError()), { once: true });
  });
}

function errorMessage(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/**
 * Execute a tool through the sandbox. Order of enforcement (all fail closed):
 *   1. allowlist  — unknown tool => denied.
 *   2. validation — args must satisfy the tool's Zod schema.
 *   3. approval   — dangerous tools require an approved invocation; HIGH-risk
 *                   tools require human oversight; isolation-required tools are
 *                   routed to an external runner (denied if none configured).
 *   4. scopes     — the handler only receives capabilities for its scopes.
 *   5. timeout    — hard wall-clock cap via AbortController.
 * Arguments are redacted for the returned record regardless of outcome.
 */
export async function executeTool(
  registry: ToolRegistry,
  name: unknown,
  rawArgs: unknown,
  options: ExecuteOptions,
): Promise<ToolInvocation> {
  const redact = options.redactor ?? defaultRedact;
  const redactedArgs = redact(rawArgs);

  // 1. Allowlist.
  let def;
  try {
    def = registry.get(name);
  } catch (e) {
    if (e instanceof UnknownToolError) {
      return { tool: String(name), decision: 'denied', reason: 'not_allowlisted', redactedArgs };
    }
    throw e;
  }

  // 2. Argument validation.
  const parsed = def.inputSchema.safeParse(rawArgs);
  if (!parsed.success) {
    return { tool: def.name, decision: 'denied', reason: 'invalid_arguments', redactedArgs };
  }

  // 3. Human approval for dangerous tools.
  if (def.dangerous) {
    const approved = await options.approvals.isApproved(def.name, parsed.data);
    if (!approved) {
      return {
        tool: def.name,
        decision: 'pending_approval',
        reason: 'awaiting_human_approval',
        redactedArgs,
      };
    }
  }

  // 3b. EU AI Act Art. 14 — DB-backed human oversight for HIGH/CRITICAL tools.
  let oversightRequestId: string | undefined;
  if (def.riskLevel && requiresOversight(def.riskLevel)) {
    if (!options.oversight) {
      // Fail closed: a high-risk tool cannot run without an oversight gate.
      return { tool: def.name, decision: 'denied', reason: 'oversight_unavailable', redactedArgs };
    }
    const decision = await options.oversight.check(def.name, parsed.data, def.riskLevel);
    if (!decision.approved) {
      return {
        tool: def.name,
        decision: 'pending_approval',
        reason: 'human_oversight_required',
        requestId: decision.requestId,
        redactedArgs,
      };
    }
    oversightRequestId = decision.requestId;
  }

  // 3c. Isolation boundary — untrusted-code tools never run in-process.
  if (def.requiresIsolation) {
    if (!options.isolationRunner) {
      return { tool: def.name, decision: 'denied', reason: 'isolation_unavailable', redactedArgs };
    }
    try {
      const result = await options.isolationRunner.run(def, parsed.data, { timeoutMs: def.timeoutMs });
      if (oversightRequestId && options.oversight?.recordOutcome) {
        await options.oversight.recordOutcome(oversightRequestId, `executed (isolated): ok=${result.ok}`);
      }
      return { tool: def.name, decision: 'allowed', result, redactedArgs };
    } catch (e) {
      return { tool: def.name, decision: 'allowed', result: { ok: false, error: errorMessage(e) }, redactedArgs };
    }
  }

  // 4 + 5. Scoped capabilities + hard timeout.
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), def.timeoutMs);
  const ctx = buildContext(def.scopes, {
    secrets: options.secrets ?? {},
    signal: controller.signal,
    ...(options.fetchImpl ? { fetchImpl: options.fetchImpl } : {}),
  });

  try {
    const result = await Promise.race([def.handler(parsed.data, ctx), abortRejection(controller.signal)]);
    if (oversightRequestId && options.oversight?.recordOutcome) {
      await options.oversight.recordOutcome(oversightRequestId, `executed: ok=${result.ok}`);
    }
    return { tool: def.name, decision: 'allowed', result, redactedArgs };
  } catch (e) {
    const error = e instanceof ToolTimeoutError ? 'timeout' : errorMessage(e);
    return { tool: def.name, decision: 'allowed', result: { ok: false, error }, redactedArgs };
  } finally {
    clearTimeout(timer);
  }
}
