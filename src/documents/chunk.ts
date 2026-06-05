import { getEncoding, type Tiktoken } from 'js-tiktoken';

/** Token-based chunking with overlap, using a tiktoken encoding. */
export interface TextChunk {
  index: number;
  content: string;
  tokenCount: number;
}

let encoder: Tiktoken | null = null;
function enc(): Tiktoken {
  if (!encoder) encoder = getEncoding('cl100k_base');
  return encoder;
}

export function chunkText(
  text: string,
  opts: { chunkSize?: number; overlap?: number } = {},
): TextChunk[] {
  const chunkSize = opts.chunkSize ?? 512;
  const overlap = opts.overlap ?? 100;
  const step = Math.max(1, chunkSize - overlap);

  const e = enc();
  const tokens = e.encode(text);
  if (tokens.length === 0) return [];

  const chunks: TextChunk[] = [];
  let start = 0;
  let index = 0;
  while (start < tokens.length) {
    const slice = tokens.slice(start, start + chunkSize);
    chunks.push({ index: index++, content: e.decode(slice), tokenCount: slice.length });
    if (start + chunkSize >= tokens.length) break;
    start += step;
  }
  return chunks;
}
