import type { FastifyInstance, FastifyReply } from 'fastify';
import { z } from 'zod';
import type { LlmProvider } from '../ai/providers/provider.interface.js';

/**
 * Server-Sent Events endpoint for streaming chat completions.
 *
 * - Provider is selected by id (server-config registry) — never a caller URL.
 * - Back-pressure: writes await 'drain' so we never buffer the whole response.
 * - Clean disconnect: on client close we stop iterating; the provider's async
 *   generator runs its cleanup (cancelling the upstream request).
 * - Rate limiting applies to this route like any other.
 */
const bodySchema = z.object({
  providerId: z.string().min(1),
  messages: z
    .array(
      z.object({
        role: z.enum(['system', 'user', 'assistant', 'tool']),
        content: z.string(),
      }),
    )
    .min(1),
});

export interface ChatStreamRouteDeps {
  /** Resolve a provider by id; throws for unknown ids (fail-closed). */
  resolveProvider: (id: string) => LlmProvider;
  /** Optional per-route rate-limit override. */
  rateLimit?: { max: number; timeWindow: number };
}

function writeSse(reply: FastifyReply, payload: string): Promise<void> {
  return new Promise((resolve) => {
    const ok = reply.raw.write(payload);
    if (ok) resolve();
    else reply.raw.once('drain', resolve);
  });
}

export function registerChatStreamRoute(app: FastifyInstance, deps: ChatStreamRouteDeps): void {
  const routeOpts = deps.rateLimit ? { config: { rateLimit: deps.rateLimit } } : {};

  app.post('/ai/chat/stream', routeOpts, async (req, reply) => {
    const parsed = bodySchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: 'invalid request' });

    let provider: LlmProvider;
    try {
      provider = deps.resolveProvider(parsed.data.providerId);
    } catch {
      return reply.code(404).send({ error: 'unknown provider' });
    }

    // Take over the socket for manual SSE framing.
    reply.hijack();
    const res = reply.raw;
    res.writeHead(200, {
      'content-type': 'text/event-stream',
      'cache-control': 'no-cache, no-transform',
      connection: 'keep-alive',
      'x-accel-buffering': 'no',
    });

    // Detect a client disconnect: the response socket closing BEFORE we finish
    // writing. (Listening on the request stream's 'close' is unreliable — it
    // fires as soon as the request body is fully read.)
    let clientClosed = false;
    res.on('close', () => {
      if (!res.writableFinished) clientClosed = true;
    });

    try {
      for await (const chunk of provider.chatStream({ messages: parsed.data.messages })) {
        if (clientClosed || res.writableEnded) break;
        await writeSse(reply, `data: ${JSON.stringify(chunk)}\n\n`);
        if (chunk.done) break;
      }
      if (!clientClosed && !res.writableEnded) {
        await writeSse(reply, 'event: done\ndata: {}\n\n');
      }
    } catch {
      if (!res.writableEnded) {
        res.write(`event: error\ndata: ${JSON.stringify({ error: 'stream_failed' })}\n\n`);
      }
    } finally {
      if (!res.writableEnded) res.end();
    }
  });
}
