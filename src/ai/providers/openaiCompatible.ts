import type {
  CallOptions,
  ChatRequest,
  ChatResponse,
  LlmProvider,
} from './provider.interface.js';

/**
 * Provider for any OpenAI-compatible chat endpoint (Ollama, vLLM, llama.cpp's
 * server, etc.). The base URL is supplied ONCE from server configuration and is
 * immutable for the life of the provider — there is no per-request override.
 */

export interface OpenAiCompatibleConfig {
  id: string;
  baseUrl: string;
  model: string;
  apiKey?: string | undefined;
  defaultTimeoutMs?: number;
  /** Injectable for tests; defaults to global fetch. */
  fetchImpl?: typeof fetch;
}

interface OpenAiChatCompletion {
  model?: string;
  choices?: Array<{ message?: { content?: string }; finish_reason?: string }>;
}

export class OpenAiCompatibleProvider implements LlmProvider {
  readonly id: string;
  readonly model: string;
  private readonly baseUrl: string;
  private readonly apiKey: string | undefined;
  private readonly defaultTimeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(config: OpenAiCompatibleConfig) {
    this.id = config.id;
    this.model = config.model;
    this.baseUrl = config.baseUrl.replace(/\/+$/, '');
    this.apiKey = config.apiKey;
    this.defaultTimeoutMs = config.defaultTimeoutMs ?? 30_000;
    this.fetchImpl = config.fetchImpl ?? fetch;
  }

  async chat(request: ChatRequest, options: CallOptions = {}): Promise<ChatResponse> {
    const url = `${this.baseUrl}/v1/chat/completions`;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? this.defaultTimeoutMs);

    const headers: Record<string, string> = { 'content-type': 'application/json' };
    if (this.apiKey) headers['authorization'] = `Bearer ${this.apiKey}`;

    try {
      const res = await this.fetchImpl(url, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          model: request.model ?? this.model,
          messages: request.messages,
          temperature: request.temperature,
          max_tokens: request.maxTokens,
        }),
        signal: options.signal ?? controller.signal,
      });

      if (!res.ok) {
        throw new Error(`provider "${this.id}" returned HTTP ${res.status}`);
      }

      const data = (await res.json()) as OpenAiChatCompletion;
      const choice = data.choices?.[0];
      return {
        content: choice?.message?.content ?? '',
        model: data.model ?? this.model,
        ...(choice?.finish_reason ? { finishReason: choice.finish_reason } : {}),
      };
    } finally {
      clearTimeout(timer);
    }
  }
}
