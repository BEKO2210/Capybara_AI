import { readdir, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { sql } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import type { AppDatabase } from '../db/client.js';
import { APP_VERSION } from '../version.js';

/**
 * Liveness/readiness + deep health.
 *
 * `/readyz` and the bare `/healthz` (no deps) expose only a coarse status and
 * are safe to leave unauthenticated. When health dependencies are supplied,
 * `/healthz` additionally reports component health (database, vector search),
 * the last successful backup, and the build version, returning 503 when any
 * critical component is degraded or down so load balancers can drain the node.
 */

export interface HealthDeps {
  /** Restricted app DB connection; enables DB + vector-search probes. */
  db?: AppDatabase;
  /** Directory backups are written to; enables last-backup reporting. */
  backupDir?: string;
  /** Max backup age (ms) before the node is considered degraded. */
  backupMaxAgeMs?: number;
  /** Override the reported version (defaults to the build version). */
  version?: string;
}

type ComponentState = 'ok' | 'degraded' | 'down';

async function probeDb(db: AppDatabase): Promise<ComponentState> {
  try {
    await db.execute(sql`SELECT 1`);
    return 'ok';
  } catch {
    return 'down';
  }
}

async function probeVectorSearch(db: AppDatabase): Promise<ComponentState> {
  try {
    const rows = (await db.execute(
      sql`SELECT 1 AS ok FROM pg_extension WHERE extname = 'vector'`,
    )) as unknown as { ok: number }[];
    return rows.length > 0 ? 'ok' : 'down';
  } catch {
    return 'down';
  }
}

/** Newest backup file mtime in `dir`, or null if none/unreadable. */
async function lastBackupAt(dir: string): Promise<Date | null> {
  try {
    const entries = await readdir(dir);
    const backups = entries.filter((f) => /\.(sql\.gz|sql|dump|tar\.gz)$/.test(f));
    let newest: Date | null = null;
    for (const f of backups) {
      const s = await stat(join(dir, f));
      if (!newest || s.mtime > newest) newest = s.mtime;
    }
    return newest;
  } catch {
    return null;
  }
}

export function registerHealthRoutes(app: FastifyInstance, deps: HealthDeps = {}): void {
  app.get('/readyz', async () => ({ status: 'ready' }));

  app.get('/healthz', async (_req, reply) => {
    // No dependencies wired → minimal liveness probe (backward compatible).
    if (!deps.db && !deps.backupDir) {
      return { status: 'ok' };
    }

    const version = deps.version ?? APP_VERSION;
    const components: Record<string, ComponentState> = {};

    if (deps.db) {
      components['db'] = await probeDb(deps.db);
      // Only probe vector search if the DB is reachable at all.
      components['vectorSearch'] = components['db'] === 'down' ? 'down' : await probeVectorSearch(deps.db);
    }

    let lastBackup: string | null = null;
    if (deps.backupDir) {
      const at = await lastBackupAt(deps.backupDir);
      lastBackup = at ? at.toISOString() : null;
      const maxAge = deps.backupMaxAgeMs ?? 48 * 60 * 60_000;
      const stale = !at || Date.now() - at.getTime() > maxAge;
      components['backup'] = stale ? 'degraded' : 'ok';
    }

    const states = Object.values(components);
    const status: ComponentState = states.includes('down')
      ? 'down'
      : states.includes('degraded')
        ? 'degraded'
        : 'ok';

    const body = { status, version, lastBackup, components };
    if (status !== 'ok') return reply.code(503).send(body);
    return body;
  });
}
