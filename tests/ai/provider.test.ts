import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { ProviderRegistry, UnknownProviderError } from '../../src/ai/providers/registry.js';
import type { ChatRequest } from '../../src/ai/providers/provider.interface.js';
import { loadConfig, ConfigError } from '../../src/config/index.js';

interface RecordedRequest {
  url: string;
  host: string | undefined;
  body: unknown;
}

describe('ai/providers — server-only endpoints (no caller base_url)', () => {
  let server: Server;
  let baseUrl: string;
  const recorded: RecordedRequest[] = [];

  beforeAll(async () => {
    server = createServer((req, res) => {
      let raw = '';
      req.on('data', (c) => (raw += c));
      req.on('end', () => {
        recorded.push({ url: req.url ?? '', host: req.headers.host, body: raw ? JSON.parse(raw) : null });
        res.setHeader('content-type', 'application/json');
        res.end(
          JSON.stringify({
            model: 'mock-model',
            choices: [{ message: { role: 'assistant', content: 'pong' }, finish_reason: 'stop' }],
          }),
        );
      });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as AddressInfo).port;
    baseUrl = `http://127.0.0.1:${port}`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it('resolves a configured provider and performs a chat (happy path)', async () => {
    const registry = new ProviderRegistry([
      { id: 'local', type: 'openai-compatible', baseUrl, model: 'mock-model' },
    ]);
    const res = await registry.get('local').chat({
      messages: [{ role: 'user', content: 'ping' }],
    });
    expect(res.content).toBe('pong');
    expect(res.model).toBe('mock-model');
    expect(recorded.at(-1)?.url).toBe('/v1/chat/completions');
  });

  it('fails closed for an unknown provider id', () => {
    const registry = new ProviderRegistry([
      { id: 'local', type: 'openai-compatible', baseUrl, model: 'mock-model' },
    ]);
    expect(() => registry.get('does-not-exist')).toThrow(UnknownProviderError);
  });

  it('IGNORES any caller-supplied endpoint override (SSRF gap closed)', async () => {
    const registry = new ProviderRegistry([
      { id: 'local', type: 'openai-compatible', baseUrl, model: 'mock-model' },
    ]);
    const before = recorded.length;
    // Attempt to smuggle an attacker endpoint via extra fields — must be ignored.
    const malicious = {
      messages: [{ role: 'user', content: 'ping' }],
      baseUrl: 'http://169.254.169.254/latest/meta-data',
      url: 'http://evil.example',
    } as unknown as ChatRequest;
    const res = await registry.get('local').chat(malicious);
    expect(res.content).toBe('pong');
    // The request still went to the configured mock host, not the attacker URL.
    const last = recorded[recorded.length - 1];
    expect(recorded.length).toBe(before + 1);
    expect(last?.host).toContain('127.0.0.1');
  });
});

describe('ai/providers — fail-closed config parsing', () => {
  it('parses valid LLM_PROVIDERS from server config', () => {
    const cfg = loadConfig({
      APP_ENV: 'test',
      LLM_PROVIDERS: JSON.stringify([
        { id: 'ollama', type: 'openai-compatible', baseUrl: 'http://127.0.0.1:11434', model: 'llama3' },
      ]),
      LLM_DEFAULT_PROVIDER: 'ollama',
    });
    expect(cfg.llm.providers).toHaveLength(1);
    expect(cfg.llm.defaultProvider).toBe('ollama');
  });

  it('refuses malformed LLM_PROVIDERS JSON', () => {
    expect(() => loadConfig({ APP_ENV: 'test', LLM_PROVIDERS: 'not-json' })).toThrow(ConfigError);
  });

  it('refuses a default provider that matches no configured provider', () => {
    expect(() =>
      loadConfig({
        APP_ENV: 'test',
        LLM_PROVIDERS: JSON.stringify([
          { id: 'ollama', type: 'openai-compatible', baseUrl: 'http://127.0.0.1:11434', model: 'llama3' },
        ]),
        LLM_DEFAULT_PROVIDER: 'missing',
      }),
    ).toThrow(ConfigError);
  });
});
