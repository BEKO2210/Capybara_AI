import { createDbClient } from '../db/client.js';
import { detectAnomalies } from './anomaly.js';

/**
 * Scan recent audit/security streams for anomalous bursts and raise
 * `security.anomaly` events. Intended for cron. Exits non-zero when anomalies
 * are detected, so a scheduler/alerting layer can page.
 *
 * Required environment: DATABASE_URL.
 */
async function main(): Promise<void> {
  const url = process.env['DATABASE_URL'];
  if (!url) {
    console.error('DATABASE_URL is required');
    process.exit(1);
  }
  const client = createDbClient(url, 1);
  try {
    const found = await detectAnomalies(client.db);
    if (found.length === 0) {
      console.log('no anomalies detected');
      return;
    }
    for (const a of found) console.error(`ANOMALY ${a.kind}: ${a.count} in ${a.windowMinutes}m (threshold ${a.threshold})`);
    process.exitCode = 2;
  } finally {
    await client.close();
  }
}

main().catch((err: unknown) => {
  console.error('anomaly detection failed:', err instanceof Error ? err.message : err);
  process.exit(1);
});
