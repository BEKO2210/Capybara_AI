import type {
  CallOptions,
  ChatMessage,
  ChatRequest,
  ChatResponse,
  ChatStreamChunk,
  LlmProvider,
} from './provider.interface.js';
import { iterateSse } from './sseParse.js';

/**
 * Anthropic Messages API provider. Server-only endpoint (base URL comes from
 * configuration, never from the caller — same SSRF rule as every provider).
 * The API key is sent via the `x-api-key` header.
 */

const ANTHROPIC_VERSION = '2023-06-01';
const DEFAULT_MAX_TOKENS = 1024;

export interface AnthropicConfig {
  id: string;
  baseUrl: string;
  model: string;
  apiKey?: string | undefined;
  defaultTimeoutMs?: number;
  fetchImpl?: typeof fetch;
}

interface AnthropicMessageResponse {
  model?: string;
  stop_reason?: string;
  content?: Array<{ type: string; text?: string }>;
}

/** Split our messages into Anthropic's `system` string + user/assistant turns. */
function splitMessages(messages: ChatMessage[]): {
  system: string | undefined;
  turns: Array<{ role: 'user' | 'assistant'; content: string }>;
} {
  const systemParts: string[] = [];
  const turns: Array<{ role: 'user' | 'assistant'; content: string }> = [];
  for (const m of messages) {
    if (m.role === 'system') systemParts.push(m.content);
    else if (m.role === 'assistant') turns.push({ role: 'assistant', content: m.content });
    else turns.push({ role: 'user', content: m.content }); // 'user' and 'tool' → user
  }
  return { system: systemParts.length ? systemParts.join('\n') : undefined, turns };
}

export class AnthropicProvider implements LlmProvider {
  readonly id: string;
  readonly model: string;
  private readonly baseUrl: string;
  private readonly apiKey: string | undefined;
  private readonly defaultTimeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(config: AnthropicConfig) {
    this.id = config.id;
    this.model = config.model;
    this.baseUrl = config.baseUrl.replace(/\/+$/, '');
    this.apiKey = config.apiKey;
    this.defaultTimeoutMs = config.defaultTimeoutMs ?? 30_000;
    this.fetchImpl = config.fetchImpl ?? fetch;
  }

  private headers(): Record<string, string> {
    const h: Record<string, string> = {
      'content-type': 'application/json',
      'anthropic-version': ANTHROPIC_VERSION,
    };
    if (this.apiKey) h['x-api-key'] = this.apiKey;
    return h;
  }

  private body(request: ChatRequest, stream: boolean): string {
    const { system, turns } = splitMessages(request.messages);
    return JSON.stringify({
      model: request.model ?? this.model,
      max_tokens: request.maxTokens ?? DEFAULT_MAX_TOKENS,
      temperature: request.temperature,
      ...(system ? { system } : {}),
      messages: turns,
      stream,
    });
  }

  async chat(request: ChatRequest, options: CallOptions = {}): Promise<ChatResponse> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? this.defaultTimeoutMs);
    try {
      const res = await this.fetchImpl(`${this.baseUrl}/v1/messages`, {
        method: 'POST',
        headers: this.headers(),
        body: this.body(request, false),
        signal: options.signal ?? controller.signal,
      });
      if (!res.ok) throw new Error(`provider "${this.id}" returned HTTP ${res.status}`);
      const data = (await res.json()) as AnthropicMessageResponse;
      const content = (data.content ?? [])
        .filter((b) => b.type === 'text')
        .map((b) => b.text ?? '')
        .join('');
      return {
        content,
        model: data.model ?? this.model,
        ...(data.stop_reason ? { finishReason: data.stop_reason } : {}),
      };
    } finally {
      clearTimeout(timer);
    }
  }

  async *chatStream(
    request: ChatRequest,
    options: CallOptions = {},
  ): AsyncGenerator<ChatStreamChunk> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? this.defaultTimeoutMs);
    try {
      const res = await this.fetchImpl(`${this.baseUrl}/v1/messages`, {
        method: 'POST',
        headers: this.headers(),
        body: this.body(request, true),
        signal: options.signal ?? controller.signal,
      });
      if (!res.ok) throw new Error(`provider "${this.id}" returned HTTP ${res.status}`);
      if (!res.body) throw new Error(`provider "${this.id}" returned no stream body`);

      for await (const evt of iterateSse(res.body)) {
        let json: { type?: string; delta?: { text?: string }; stop_reason?: string };
        try {
          json = JSON.parse(evt.data);
        } catch {
          continue;
        }
        if (json.type === 'content_block_delta' && json.delta?.text) {
          yield { delta: json.delta.text, done: false };
        } else if (json.type === 'message_stop' || evt.event === 'message_stop') {
          yield { delta: '', done: true };
          return;
        }
      }
      yield { delta: '', done: true };
    } finally {
      clearTimeout(timer);
    }
  }
}
