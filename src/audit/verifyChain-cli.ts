import { createDbClient } from '../db/client.js';
import { verifyChain } from './verifyChain.js';

/**
 * Offline tamper-evidence check for the security_events hash chain. Exits 0 when
 * the chain is intact, 1 when a break is detected (or on error) — suitable for
 * cron / post-restore verification (see docs/DISASTER_RECOVERY.md).
 *
 * Required environment:
 *   DATABASE_URL — DSN to read the security_events table (app role is fine).
 */
async function main(): Promise<void> {
  const url = process.env['DATABASE_URL'];
  if (!url) {
    console.error('DATABASE_URL is required');
    process.exit(1);
  }
  const client = createDbClient(url, 1);
  try {
    const result = await verifyChain(client.db);
    if (result.ok) {
      console.log(`security_events chain OK (${result.length} rows)`);
      return;
    }
    console.error(`security_events chain BROKEN at id=${result.brokenAt} (${result.reason})`);
    process.exitCode = 1;
  } finally {
    await client.close();
  }
}

main().catch((err: unknown) => {
  console.error('chain verification failed:', err instanceof Error ? err.message : err);
  process.exit(1);
});
