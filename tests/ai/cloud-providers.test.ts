import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { OpenAiCompatibleProvider } from '../../src/ai/providers/openaiCompatible.js';
import { AnthropicProvider } from '../../src/ai/providers/anthropic.js';

let server: Server;
let baseUrl: string;

beforeAll(async () => {
  server = createServer((req, res) => {
    let raw = '';
    req.on('data', (c) => (raw += c));
    req.on('end', async () => {
      const body = raw ? JSON.parse(raw) : {};
      // Simulate "unknown model" upstream errors (fail-closed).
      if (body.model === 'unknown-model') {
        res.writeHead(404, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'model not found' }));
        return;
      }
      // Simulate a slow endpoint to exercise client-side timeout.
      if (body.model === 'slow-model') {
        await new Promise((r) => setTimeout(r, 300));
      }
      if (req.url === '/v1/chat/completions') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(
          JSON.stringify({
            model: body.model,
            choices: [{ message: { role: 'assistant', content: 'oai-hello' }, finish_reason: 'stop' }],
          }),
        );
      } else if (req.url === '/v1/messages') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(
          JSON.stringify({
            model: body.model,
            stop_reason: 'end_turn',
            content: [{ type: 'text', text: 'anthropic-hello' }],
          }),
        );
      } else {
        res.writeHead(404);
        res.end();
      }
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

describe('ai/providers — OpenAI-compatible (cloud + local)', () => {
  const provider = () => new OpenAiCompatibleProvider({ id: 'oai', baseUrl, model: 'gpt-x', apiKey: 'k' });

  it('completes a chat (happy path)', async () => {
    const res = await provider().chat({ messages: [{ role: 'user', content: 'hi' }] });
    expect(res.content).toBe('oai-hello');
  });

  it('fails closed on an unknown model (upstream error)', async () => {
    await expect(
      provider().chat({ messages: [{ role: 'user', content: 'hi' }], model: 'unknown-model' }),
    ).rejects.toThrow(/HTTP 404/);
  });

  it('enforces the request timeout', async () => {
    await expect(
      provider().chat({ messages: [{ role: 'user', content: 'hi' }], model: 'slow-model' }, { timeoutMs: 50 }),
    ).rejects.toThrow();
  });
});

describe('ai/providers — Anthropic', () => {
  const provider = () => new AnthropicProvider({ id: 'anthropic', baseUrl, model: 'claude-x', apiKey: 'k' });

  it('completes a chat (happy path)', async () => {
    const res = await provider().chat({ messages: [{ role: 'user', content: 'hi' }] });
    expect(res.content).toBe('anthropic-hello');
  });

  it('fails closed on an unknown model (upstream error)', async () => {
    await expect(
      provider().chat({ messages: [{ role: 'user', content: 'hi' }], model: 'unknown-model' }),
    ).rejects.toThrow(/HTTP 404/);
  });

  it('enforces the request timeout', async () => {
    await expect(
      provider().chat({ messages: [{ role: 'user', content: 'hi' }], model: 'slow-model' }, { timeoutMs: 50 }),
    ).rejects.toThrow();
  });
});
