import { createDbClient } from '../db/client.js';
import { createAnchor, loadAnchorPrivateKey, fileAnchorSink } from './anchor.js';

/**
 * Create a signed off-box checkpoint over the security-event chain. Intended to
 * run on a schedule (cron) on a host that holds the Ed25519 private key. The
 * public key lives elsewhere for verification (see `npm run verify:chain`).
 *
 * Required environment:
 *   DATABASE_URL               DSN (app role is fine — anchors are append-only).
 *   AUDIT_ANCHOR_PRIVATE_KEY   Ed25519 private key in PEM.
 * Optional:
 *   AUDIT_ANCHOR_DIR           Directory to also append the checkpoint to
 *                              (sync this to a write-once / object-lock medium).
 */
async function main(): Promise<void> {
  const url = process.env['DATABASE_URL'];
  const pem = process.env['AUDIT_ANCHOR_PRIVATE_KEY'];
  if (!url || !pem) {
    console.error('DATABASE_URL and AUDIT_ANCHOR_PRIVATE_KEY are required');
    process.exit(1);
  }
  const dir = process.env['AUDIT_ANCHOR_DIR'];
  const client = createDbClient(url, 1);
  try {
    const res = await createAnchor(client.db, loadAnchorPrivateKey(pem), dir ? fileAnchorSink(dir) : undefined);
    console.log(`anchored checkpoint #${res.checkpointSeq} (events=${res.eventCount}, head=${res.chainHash.slice(0, 12)}…)`);
  } finally {
    await client.close();
  }
}

main().catch((err: unknown) => {
  console.error('anchoring failed:', err instanceof Error ? err.message : err);
  process.exit(1);
});
