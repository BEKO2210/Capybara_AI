import type { z } from 'zod';
import type { RiskLevel } from '../../db/schema/index.js';

/**
 * Tool sandbox type model.
 *
 * A tool declares the capability SCOPES it needs. Scopes default to nothing:
 * a tool with no `fs` scope cannot touch the filesystem, no `network` scope
 * cannot make outbound calls, no `shell` scope cannot execute commands, and it
 * only sees the specific secrets it lists. The runtime hands the tool a
 * ToolContext whose capabilities ENFORCE those scopes, so a tool can never
 * exceed what it declared and an operator allowed.
 */

export interface FsScope {
  mode: 'none' | 'read' | 'readwrite';
  /** Absolute roots the tool may access. Everything else is denied. */
  allowedPaths: string[];
}

export interface NetworkScope {
  /** Hostnames the tool may target. */
  allowedHosts: string[];
  /** Permit private/loopback ranges (self-hosted internal services). */
  allowPrivateRanges?: boolean;
}

export interface ShellScope {
  /** Exact executables permitted. Empty (or absent scope) => shell denied. */
  allowedCommands: string[];
}

export interface ToolScopes {
  fs?: FsScope;
  network?: NetworkScope;
  shell?: ShellScope;
  /** Names of secrets to inject into the context. Default: none. */
  secrets?: string[];
}

export interface FsCapability {
  readFile(path: string): Promise<string>;
  writeFile(path: string, data: string): Promise<void>;
}

export interface NetCapability {
  fetch(url: string, init?: RequestInit): Promise<Response>;
}

export interface ShellCapability {
  exec(command: string, args?: string[]): Promise<{ stdout: string; stderr: string }>;
}

export interface ToolContext {
  readonly fs: FsCapability;
  readonly net: NetCapability;
  readonly shell: ShellCapability;
  readonly secrets: Readonly<Record<string, string>>;
  readonly signal: AbortSignal;
}

export interface ToolResult {
  ok: boolean;
  output?: unknown;
  error?: string;
}

export interface ToolDefinition<TArgs = unknown> {
  name: string;
  description: string;
  /** Zod schema; args are validated before the handler runs. */
  inputSchema: z.ZodType<TArgs>;
  /** Dangerous tools require explicit human approval before each execution. */
  dangerous: boolean;
  /**
   * EU AI Act Art. 14 risk level. Tools at HIGH or above require a DB-backed
   * human-oversight approval (oversight_requests) before execution.
   */
  riskLevel?: RiskLevel;
  scopes: ToolScopes;
  /** Hard wall-clock cap for a single invocation. */
  timeoutMs: number;
  /**
   * When true, the tool MUST run inside an external isolation boundary
   * (container / microVM / gVisor) — never in-process. The sandbox FAILS CLOSED:
   * such a tool is denied unless an `IsolationRunner` is provided. Use this for
   * any tool that executes untrusted/third-party code; in-process capability
   * scopes are not a substitute for kernel isolation.
   */
  requiresIsolation?: boolean;
  handler: (args: TArgs, ctx: ToolContext) => Promise<ToolResult>;
}

/**
 * Pluggable execution boundary for isolation-required tools. Operators provide
 * an implementation backed by a container-per-invocation / microVM / gVisor
 * runner. The sandbox routes `requiresIsolation` tools here instead of calling
 * the in-process handler.
 */
export interface IsolationRunner {
  run(def: ToolDefinition, args: unknown, opts: { timeoutMs: number }): Promise<ToolResult>;
}
