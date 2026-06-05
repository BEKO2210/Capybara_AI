import type { ToolDefinition } from './tool.types.js';

export class UnknownToolError extends Error {
  constructor(name: unknown) {
    super(`tool not in allowlist: ${typeof name === 'string' ? name : '(non-string)'}`);
    this.name = 'UnknownToolError';
  }
}

/**
 * The tool registry is an explicit ALLOWLIST. A tool that has not been
 * registered cannot be invoked; lookups of unknown or non-string names fail
 * closed (throw), mirroring a default-deny posture.
 */
export class ToolRegistry {
  private readonly tools = new Map<string, ToolDefinition<unknown>>();

  register<TArgs>(def: ToolDefinition<TArgs>): void {
    if (typeof def.name !== 'string' || def.name.length === 0) {
      throw new Error('tool name must be a non-empty string');
    }
    if (this.tools.has(def.name)) {
      throw new Error(`tool already registered: ${def.name}`);
    }
    this.tools.set(def.name, def as ToolDefinition<unknown>);
  }

  has(name: unknown): boolean {
    return typeof name === 'string' && this.tools.has(name);
  }

  get(name: unknown): ToolDefinition<unknown> {
    if (typeof name !== 'string') throw new UnknownToolError(name);
    const tool = this.tools.get(name);
    if (!tool) throw new UnknownToolError(name);
    return tool;
  }

  list(): string[] {
    return [...this.tools.keys()];
  }
}
