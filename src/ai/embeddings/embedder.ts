import type { Config } from '../../config/index.js';

/**
 * Text embedding abstraction. Endpoints are SERVER-ONLY (from config) — a caller
 * can never point embedding generation at an arbitrary URL (same SSRF rule as
 * the chat providers).
 */
export interface Embedder {
  readonly dimensions: number;
  embed(texts: string[]): Promise<number[][]>;
}

export const EMBEDDING_DIMENSIONS = 768;

interface OllamaEmbeddingResponse {
  embedding?: number[];
}
interface OpenAiEmbeddingResponse {
  data?: Array<{ embedding: number[] }>;
}

/** Local Ollama embeddings (`/api/embeddings`), one request per text. */
export class OllamaEmbedder implements Embedder {
  readonly dimensions = EMBEDDING_DIMENSIONS;
  constructor(
    private readonly baseUrl: string,
    private readonly model: string,
    private readonly fetchImpl: typeof fetch = fetch,
  ) {}

  async embed(texts: string[]): Promise<number[][]> {
    const out: number[][] = [];
    for (const text of texts) {
      const res = await this.fetchImpl(`${this.baseUrl.replace(/\/+$/, '')}/api/embeddings`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ model: this.model, prompt: text }),
      });
      if (!res.ok) throw new Error(`embedding provider returned HTTP ${res.status}`);
      const data = (await res.json()) as OllamaEmbeddingResponse;
      if (!Array.isArray(data.embedding)) throw new Error('embedding provider returned no vector');
      out.push(data.embedding);
    }
    return out;
  }
}

/** OpenAI-compatible embeddings (`/embeddings`), batched. */
export class OpenAiEmbedder implements Embedder {
  readonly dimensions = EMBEDDING_DIMENSIONS;
  constructor(
    private readonly baseUrl: string,
    private readonly model: string,
    private readonly apiKey: string,
    private readonly fetchImpl: typeof fetch = fetch,
  ) {}

  async embed(texts: string[]): Promise<number[][]> {
    const res = await this.fetchImpl(`${this.baseUrl.replace(/\/+$/, '')}/embeddings`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${this.apiKey}` },
      // text-embedding-3-* support the `dimensions` param; pin to our column width.
      body: JSON.stringify({ model: this.model, input: texts, dimensions: EMBEDDING_DIMENSIONS }),
    });
    if (!res.ok) throw new Error(`embedding provider returned HTTP ${res.status}`);
    const data = (await res.json()) as OpenAiEmbeddingResponse;
    if (!data.data?.length) throw new Error('embedding provider returned no vectors');
    return data.data.map((d) => d.embedding);
  }
}

/** Build the configured embedder. Throws (fail-closed) if misconfigured. */
export function createEmbedderFromConfig(config: Config): Embedder {
  if (config.embeddings.provider === 'openai') {
    if (!config.embeddings.openaiApiKey) throw new Error('OPENAI_API_KEY required for openai embeddings');
    return new OpenAiEmbedder(config.embeddings.openaiBaseUrl, config.embeddings.openaiModel, config.embeddings.openaiApiKey);
  }
  if (!config.embeddings.ollamaBaseUrl) throw new Error('OLLAMA_BASE_URL required for local embeddings');
  return new OllamaEmbedder(config.embeddings.ollamaBaseUrl, config.embeddings.model);
}
