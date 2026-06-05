import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { FastifyInstance } from 'fastify';
import { loadConfig } from '../../src/config/index.js';
import { buildServer } from '../../src/server.js';
import { registerChatStreamRoute } from '../../src/http/aiStream.js';
import { OpenAiCompatibleProvider } from '../../src/ai/providers/openaiCompatible.js';
import type { LlmProvider } from '../../src/ai/providers/provider.interface.js';

const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));

// ─── 1. Provider-level streaming against a mock SSE upstream ──────────────────
describe('ai/providers — OpenAI-compatible streaming', () => {
  let upstream: Server;
  let baseUrl: string;

  beforeAll(async () => {
    upstream = createServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      for (const tok of ['He', 'llo', '!']) {
        res.write(`data: ${JSON.stringify({ choices: [{ delta: { content: tok } }] })}\n\n`);
      }
      res.write('data: [DONE]\n\n');
      res.end();
    });
    await new Promise<void>((r) => upstream.listen(0, '127.0.0.1', r));
    baseUrl = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}`;
  });

  afterAll(async () => {
    await new Promise<void>((r) => upstream.close(() => r()));
  });

  it('yields token deltas and a final done chunk', async () => {
    const provider = new OpenAiCompatibleProvider({ id: 'oai', baseUrl, model: 'm' });
    const deltas: string[] = [];
    let sawDone = false;
    for await (const chunk of provider.chatStream({ messages: [{ role: 'user', content: 'hi' }] })) {
      if (chunk.delta) deltas.push(chunk.delta);
      if (chunk.done) sawDone = true;
    }
    expect(deltas.join('')).toBe('Hello!');
    expect(sawDone).toBe(true);
  });
});

// ─── 2. SSE endpoint: emit, rate-limit, clean disconnect ─────────────────────
describe('http — SSE chat stream endpoint', () => {
  let slowCleanupRan = false;

  const fastProvider: LlmProvider = {
    id: 'fast',
    model: 'm',
    chat: async () => ({ content: '', model: 'm' }),
    async *chatStream() {
      for (const tok of ['a', 'b', 'c']) {
        await delay(2); // real streams await the network between chunks
        yield { delta: tok, done: false };
      }
      yield { delta: '', done: true };
    },
  };

  const slowProvider: LlmProvider = {
    id: 'slow',
    model: 'm',
    chat: async () => ({ content: '', model: 'm' }),
    async *chatStream() {
      try {
        for (let i = 0; i < 100; i++) {
          yield { delta: `t${i}`, done: false };
          await delay(30);
        }
      } finally {
        slowCleanupRan = true; // runs when the consumer breaks (disconnect)
      }
    },
  };

  function resolveProvider(id: string): LlmProvider {
    if (id === 'fast') return fastProvider;
    if (id === 'slow') return slowProvider;
    throw new Error('unknown provider');
  }

  async function startApp(rateLimit?: { max: number; timeWindow: number }): Promise<{ app: FastifyInstance; url: string }> {
    const config = loadConfig({ APP_ENV: 'test', CORS_ALLOWED_ORIGINS: 'http://localhost', LOG_LEVEL: 'fatal' });
    const app = await buildServer({
      config,
      routes: (instance) =>
        registerChatStreamRoute(instance, { resolveProvider, ...(rateLimit ? { rateLimit } : {}) }),
    });
    const url = await app.listen({ host: '127.0.0.1', port: 0 });
    return { app, url };
  }

  it('streams SSE token events and a terminal done event', async () => {
    const { app, url } = await startApp();
    try {
      const res = await fetch(`${url}/ai/chat/stream`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ providerId: 'fast', messages: [{ role: 'user', content: 'hi' }] }),
      });
      expect(res.status).toBe(200);
      expect(res.headers.get('content-type')).toContain('text/event-stream');
      const text = await res.text();
      expect(text).toContain('data: {"delta":"a","done":false}');
      expect(text).toContain('event: done');
    } finally {
      await app.close();
    }
  });

  it('returns 404 for an unknown provider (fail-closed)', async () => {
    const { app, url } = await startApp();
    try {
      const res = await fetch(`${url}/ai/chat/stream`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ providerId: 'nope', messages: [{ role: 'user', content: 'hi' }] }),
      });
      expect(res.status).toBe(404);
    } finally {
      await app.close();
    }
  });

  it('enforces the rate limit on the streaming route', async () => {
    const { app, url } = await startApp({ max: 2, timeWindow: 60_000 });
    try {
      const hit = async () =>
        (
          await fetch(`${url}/ai/chat/stream`, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ providerId: 'fast', messages: [{ role: 'user', content: 'hi' }] }),
          })
        ).status;
      expect(await hit()).toBe(200);
      expect(await hit()).toBe(200);
      expect(await hit()).toBe(429);
    } finally {
      await app.close();
    }
  });

  it('stops the provider stream cleanly when the client disconnects', async () => {
    slowCleanupRan = false;
    const { app, url } = await startApp();
    try {
      const controller = new AbortController();
      const res = await fetch(`${url}/ai/chat/stream`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ providerId: 'slow', messages: [{ role: 'user', content: 'hi' }] }),
        signal: controller.signal,
      });
      const reader = res.body!.getReader();
      await reader.read(); // receive at least the first chunk
      controller.abort(); // client disconnects mid-stream
      await reader.cancel().catch(() => {});
      // Give the server a moment to observe the close and run generator cleanup.
      await delay(300);
      expect(slowCleanupRan).toBe(true);
    } finally {
      await app.close();
    }
  });
});
