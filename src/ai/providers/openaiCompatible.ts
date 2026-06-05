import type {
  CallOptions,
  ChatRequest,
  ChatResponse,
  ChatStreamChunk,
  LlmProvider,
} from './provider.interface.js';
import { iterateSse } from './sseParse.js';

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

  async *chatStream(
    request: ChatRequest,
    options: CallOptions = {},
  ): AsyncGenerator<ChatStreamChunk> {
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
          stream: true,
        }),
        signal: options.signal ?? controller.signal,
      });
      if (!res.ok) throw new Error(`provider "${this.id}" returned HTTP ${res.status}`);
      if (!res.body) throw new Error(`provider "${this.id}" returned no stream body`);

      for await (const evt of iterateSse(res.body)) {
        if (evt.data === '[DONE]') {
          yield { delta: '', done: true };
          return;
        }
        let json: OpenAiChatCompletion & { choices?: Array<{ delta?: { content?: string }; finish_reason?: string }> };
        try {
          json = JSON.parse(evt.data);
        } catch {
          continue;
        }
        const choice = json.choices?.[0];
        const delta = choice?.delta?.content ?? '';
        if (delta) yield { delta, done: false };
        if (choice?.finish_reason) {
          yield { delta: '', done: true, finishReason: choice.finish_reason };
          return;
        }
      }
      yield { delta: '', done: true };
    } finally {
      clearTimeout(timer);
    }
  }
}
