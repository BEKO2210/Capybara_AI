/**
 * LLM provider abstraction.
 *
 * Crucially, a ChatRequest carries NO endpoint/base_url field. The target
 * endpoint is fixed when the provider is constructed from SERVER configuration.
 * Callers select a provider by its configured id — they can never point the
 * server at an arbitrary URL. This closes the SSRF-via-base_url gap.
 */

export type ChatRole = 'system' | 'user' | 'assistant' | 'tool';

export interface ChatMessage {
  role: ChatRole;
  content: string;
}

export interface ChatRequest {
  messages: ChatMessage[];
  /** Optional model override; still constrained to what the provider serves. */
  model?: string;
  temperature?: number;
  maxTokens?: number;
}

export interface ChatResponse {
  content: string;
  model: string;
  finishReason?: string;
}

export interface CallOptions {
  signal?: AbortSignal;
  timeoutMs?: number;
}

export interface LlmProvider {
  readonly id: string;
  readonly model: string;
  chat(request: ChatRequest, options?: CallOptions): Promise<ChatResponse>;
}
