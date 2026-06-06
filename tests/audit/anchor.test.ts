import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { sql } from 'drizzle-orm';
import { startTestDb, type TestDb } from '../setup/testDb.js';
import { appendSecurityEvent } from '../../src/audit/securityLog.js';
import {
  createAnchor,
  verifyAnchors,
  loadAnchorPrivateKey,
  loadAnchorPublicKey,
  fileAnchorSink,
} from '../../src/audit/anchor.js';

const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
const pubPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
const priv = loadAnchorPrivateKey(privPem);
const pub = loadAnchorPublicKey(pubPem);

let t: TestDb;
beforeAll(async () => {
  t = await startTestDb();
  for (let i = 0; i < 3; i++) {
    await appendSecurityEvent(t.app.db, { orgId: null, eventType: 'test.event', severity: 'info', payload: { i } });
  }
}, 120_000);
afterAll(async () => { await t?.stop(); });

describe('audit anchoring — off-box signed checkpoints', () => {
  it('creates a signed checkpoint over the chain head', async () => {
    const res = await createAnchor(t.app.db, priv);
    expect(res.checkpointSeq).toBe(1);
    expect(res.eventCount).toBe(3);
    expect(res.chainHash).toMatch(/^[0-9a-f]{64}$/);
    expect((await verifyAnchors(t.app.db, pub)).ok).toBe(true);
  });

  it('is a no-op when the chain head is unchanged', async () => {
    const again = await createAnchor(t.app.db, priv);
    expect(again.checkpointSeq).toBe(1); // same checkpoint, not a new one
    const rows = await t.app.db.execute(sql`SELECT count(*)::int AS n FROM audit_anchors`);
    expect(Number((rows as unknown as { n: number }[])[0]?.n)).toBe(1);
  });

  it('advances the checkpoint as new events are appended', async () => {
    await appendSecurityEvent(t.app.db, { orgId: null, eventType: 'test.event', severity: 'info', payload: { i: 99 } });
    const res = await createAnchor(t.app.db, priv);
    expect(res.checkpointSeq).toBe(2);
    expect(res.eventCount).toBe(4);
    expect((await verifyAnchors(t.app.db, pub)).ok).toBe(true);
  });

  it('detects a DB-superuser rewrite of an anchored chain head (hash_mismatch)', async () => {
    // A superuser rewrites history AFTER it was anchored. Because the anchor was
    // signed off-box, the divergence is detectable without trusting the DB.
    await t.admin.db.execute(sql`UPDATE security_events SET hash = repeat('a', 64) WHERE id = (SELECT max(id) FROM security_events)`);
    const v = await verifyAnchors(t.app.db, pub);
    expect(v.ok).toBe(false);
    expect(v.reason).toBe('hash_mismatch');
  });

  it('rejects a forged anchor signature (bad_signature)', async () => {
    const other = generateKeyPairSync('ed25519');
    const wrongPub = loadAnchorPublicKey(other.publicKey.export({ type: 'spki', format: 'pem' }).toString());
    const v = await verifyAnchors(t.app.db, wrongPub);
    expect(v.ok).toBe(false);
    expect(v.reason).toBe('bad_signature');
  });

  it('ships checkpoints to an off-box file sink', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'capy-anchor-'));
    // Fresh org to get a new head so a checkpoint is actually written.
    await appendSecurityEvent(t.app.db, { orgId: null, eventType: 'test.event', severity: 'info', payload: { sink: true } });
    await createAnchor(t.app.db, priv, fileAnchorSink(dir));
    const content = await readFile(join(dir, 'anchors.jsonl'), 'utf8');
    const line = JSON.parse(content.trim().split('\n').pop()!);
    expect(line.signature).toBeTruthy();
    expect(line.chainHash).toMatch(/^[0-9a-f]{64}$/);
  });
});
