import { createDbClient } from '../db/client.js';
import { verifyChain } from './verifyChain.js';
import { verifyAnchors, loadAnchorPublicKey } from './anchor.js';

/**
 * Offline tamper-evidence check for the security_events hash chain. Exits 0 when
 * the chain is intact, 1 when a break is detected (or on error) — suitable for
 * cron / post-restore verification (see docs/DISASTER_RECOVERY.md).
 *
 * Required environment:
 *   DATABASE_URL — DSN to read the security_events table (app role is fine).
 * Optional:
 *   AUDIT_ANCHOR_PUBLIC_KEY — Ed25519 public key (PEM). When set, the off-box
 *   signed checkpoints are ALSO verified against the live chain, detecting a
 *   rewrite even by a DB superuser.
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
    if (!result.ok) {
      console.error(`security_events chain BROKEN at id=${result.brokenAt} (${result.reason})`);
      process.exitCode = 1;
      return;
    }
    console.log(`security_events chain OK (${result.length} rows)`);

    const pub = process.env['AUDIT_ANCHOR_PUBLIC_KEY'];
    if (pub) {
      const av = await verifyAnchors(client.db, loadAnchorPublicKey(pub));
      if (!av.ok) {
        console.error(`audit anchors BROKEN at checkpoint=${av.brokenAt} (${av.reason})`);
        process.exitCode = 1;
        return;
      }
      console.log(`audit anchors OK (${av.checked} checkpoints verified)`);
    }
  } finally {
    await client.close();
  }
}

main().catch((err: unknown) => {
  console.error('chain verification failed:', err instanceof Error ? err.message : err);
  process.exit(1);
});
