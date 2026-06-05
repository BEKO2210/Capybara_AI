import { z } from 'zod';
import { OpenAiCompatibleProvider } from './openaiCompatible.js';
import { AnthropicProvider } from './anthropic.js';
import type { LlmProvider } from './provider.interface.js';

/** Schema for a single server-configured provider. baseUrl is server-only. */
export const llmProviderConfigSchema = z.object({
  id: z.string().min(1),
  type: z.enum(['openai-compatible', 'anthropic']),
  baseUrl: z.string().url(),
  model: z.string().min(1),
  apiKey: z.string().optional(),
});
export type LlmProviderConfig = z.infer<typeof llmProviderConfigSchema>;

export const llmProvidersSchema = z.array(llmProviderConfigSchema);

export class UnknownProviderError extends Error {
  constructor(id: string) {
    super(`unknown LLM provider: ${id}`);
    this.name = 'UnknownProviderError';
  }
}

export interface RegistryOptions {
  defaultProvider?: string | undefined;
  requestTimeoutMs?: number | undefined;
  /** Injectable for tests. */
  fetchImpl?: typeof fetch | undefined;
}

/**
 * Holds the providers defined in server configuration and resolves them by id.
 * Callers pick a provider by id only — they cannot introduce a new endpoint.
 */
export class ProviderRegistry {
  private readonly providers = new Map<string, LlmProvider>();
  private readonly defaultId: string | undefined;

  constructor(configs: readonly LlmProviderConfig[], options: RegistryOptions = {}) {
    for (const c of configs) {
      const common = {
        id: c.id,
        baseUrl: c.baseUrl,
        model: c.model,
        ...(c.apiKey ? { apiKey: c.apiKey } : {}),
        ...(options.requestTimeoutMs ? { defaultTimeoutMs: options.requestTimeoutMs } : {}),
        ...(options.fetchImpl ? { fetchImpl: options.fetchImpl } : {}),
      };
      switch (c.type) {
        case 'openai-compatible':
          this.providers.set(c.id, new OpenAiCompatibleProvider(common));
          break;
        case 'anthropic':
          this.providers.set(c.id, new AnthropicProvider(common));
          break;
      }
    }
    this.defaultId = options.defaultProvider;
  }

  get(id: string): LlmProvider {
    const provider = this.providers.get(id);
    if (!provider) throw new UnknownProviderError(id);
    return provider;
  }

  getDefault(): LlmProvider {
    if (!this.defaultId) throw new UnknownProviderError('(default)');
    return this.get(this.defaultId);
  }

  ids(): string[] {
    return [...this.providers.keys()];
  }
}
