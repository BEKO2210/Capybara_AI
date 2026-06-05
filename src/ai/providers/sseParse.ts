export interface SseEvent {
  event?: string;
  data: string;
}

/**
 * Parse a server-sent-event byte stream (a `fetch` response body) incrementally.
 * Yields one event per blank-line-delimited block. The reader is cancelled in
 * `finally`, so breaking out of a `for await` (client disconnect) closes the
 * upstream connection rather than buffering the rest — this is our back-pressure
 * mechanism.
 */
export async function* iterateSse(
  body: ReadableStream<Uint8Array>,
): AsyncGenerator<SseEvent> {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      buffer = buffer.replace(/\r\n/g, '\n');
      let sep: number;
      while ((sep = buffer.indexOf('\n\n')) !== -1) {
        const block = buffer.slice(0, sep);
        buffer = buffer.slice(sep + 2);
        const parsed = parseBlock(block);
        if (parsed) yield parsed;
      }
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
}

function parseBlock(block: string): SseEvent | null {
  let event: string | undefined;
  const dataLines: string[] = [];
  for (const line of block.split('\n')) {
    if (line.startsWith('data:')) dataLines.push(line.slice(5).trimStart());
    else if (line.startsWith('event:')) event = line.slice(6).trim();
    // comment lines (":...") and unknown fields are ignored
  }
  if (dataLines.length === 0) return null;
  return event !== undefined ? { event, data: dataLines.join('\n') } : { data: dataLines.join('\n') };
}
