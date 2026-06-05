import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { FastifyInstance } from 'fastify';
import { loadConfig } from '../../src/config/index.js';
import { buildServer } from '../../src/server.js';
import { startTestDb, type TestDb } from '../setup/testDb.js';

let t: TestDb;
const config = () => loadConfig({ APP_ENV: 'test', CORS_ALLOWED_ORIGINS: 'http://localhost', LOG_LEVEL: 'fatal' });

beforeAll(async () => { t = await startTestDb(); }, 120_000);
afterAll(async () => { await t?.stop(); });

describe('healthz — deep component health', () => {
  let healthy: FastifyInstance;
  let degraded: FastifyInstance;

  afterAll(async () => { await healthy?.close(); await degraded?.close(); });

  it('reports 200 + ok components when DB, vector search, and a fresh backup are present', async () => {
    const backupDir = await mkdtemp(join(tmpdir(), 'capy-bk-'));
    await writeFile(join(backupDir, 'capybara-20260605.sql.gz'), 'x');
    healthy = await buildServer({ config: config(), health: { db: t.app.db, backupDir } });

    const res = await healthy.inject({ method: 'GET', url: '/healthz' });
    expect(res.statusCode).toBe(200);
    const body = res.json() as { status: string; version: string; lastBackup: string | null; components: Record<string, string> };
    expect(body.status).toBe('ok');
    expect(body.version).toMatch(/^\d+\.\d+\.\d+$/);
    expect(body.components['db']).toBe('ok');
    expect(body.components['vectorSearch']).toBe('ok');
    expect(body.components['backup']).toBe('ok');
    expect(body.lastBackup).not.toBeNull();
  });

  it('returns 503 + degraded when no recent backup exists', async () => {
    const emptyDir = await mkdtemp(join(tmpdir(), 'capy-bk-empty-'));
    degraded = await buildServer({ config: config(), health: { db: t.app.db, backupDir: emptyDir } });

    const res = await degraded.inject({ method: 'GET', url: '/healthz' });
    expect(res.statusCode).toBe(503);
    const body = res.json() as { status: string; components: Record<string, string>; lastBackup: string | null };
    expect(body.status).toBe('degraded');
    expect(body.components['backup']).toBe('degraded');
    expect(body.lastBackup).toBeNull();
  });

  it('stays a minimal liveness probe when no health deps are wired', async () => {
    const app = await buildServer({ config: config() });
    const res = await app.inject({ method: 'GET', url: '/healthz' });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ status: 'ok' });
    await app.close();
  });
});
