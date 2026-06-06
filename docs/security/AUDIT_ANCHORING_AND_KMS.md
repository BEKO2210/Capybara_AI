# Off-box Audit Anchoring, Key Custody & Scale-out Rate Limiting

Post-1.0 hardening that closes three gaps raised in external review: a local-only
audit chain, an env-only master key, and per-instance rate limits.

## 1. Off-box audit anchoring (Ed25519)

The `security_events` log is hash-chained and append-only at the DB-permission
layer, so the *application* cannot rewrite it. A **database superuser**, however,
could rewrite rows and recompute hashes. Anchoring closes that gap: a signed
checkpoint commits to the chain head, and the signature is verified with a
**public key held off the database host** — a rewrite no longer matches the
off-box signature and is detected.

### Setup

```bash
# 1. Generate an Ed25519 keypair (keep the private key OFF the DB host).
openssl genpkey -algorithm ed25519 -out anchor.key
openssl pkey -in anchor.key -pubout -out anchor.pub

# 2. Sign a checkpoint on a schedule (cron) where the private key lives:
AUDIT_ANCHOR_PRIVATE_KEY="$(cat anchor.key)" \
AUDIT_ANCHOR_DIR=/var/lib/capybara/anchors \
DATABASE_URL=postgres://... \
npm run audit:anchor

# 3. Verify chain + anchors anywhere the PUBLIC key is available:
AUDIT_ANCHOR_PUBLIC_KEY="$(cat anchor.pub)" DATABASE_URL=postgres://... \
npm run verify:chain
```

- Checkpoints are stored append-only in `audit_anchors` (UPDATE/DELETE revoked
  for the app role) **and** optionally appended to `${AUDIT_ANCHOR_DIR}/anchors.jsonl`.
- Sync `anchors.jsonl` to a **write-once / object-lock** medium (e.g. S3 Object
  Lock) so the off-box copy is independent of the database.
- `verify:chain` exits non-zero on any break — wire it into monitoring and run it
  post-restore (see `DISASTER_RECOVERY.md`).

> **Threat model:** anchoring is only as strong as private-key custody. Keep the
> signing key on a separate host (or HSM), and the public verifier off the DB.

## 2. Key custody — KMS / secret-manager source

At-rest keys (`ENCRYPTION_KEY`, `DOCUMENT_ENCRYPTION_KEY`, `MASTER_KEK`) can be
sourced two ways via `KEY_SOURCE`:

| `KEY_SOURCE` | Behaviour |
| --- | --- |
| `env` (default) | Read the key strings from environment variables. |
| `file` | Read from `*_FILE` paths — the standard pattern for secrets projected by **Vault Agent**, the **AWS/GCP secret CSI driver**, or **Docker/Kubernetes secrets**, which mount the fetched secret as a tmpfs file. |

```bash
KEY_SOURCE=file
MASTER_KEK_FILE=/run/secrets/master_kek
ENCRYPTION_KEY_FILE=/run/secrets/encryption_key
DOCUMENT_ENCRYPTION_KEY_FILE=/run/secrets/document_encryption_key
```

Fail-closed: a configured `*_FILE` that cannot be read aborts startup (no silent
fallback to a weaker source). This keeps secrets out of the process environment
(where they leak via `/proc`, crash dumps, and child processes) and provides a
clean seam for a future native KMS decrypt client.

## 3. Scale-out rate limiting

In-memory rate limits are **per instance**. For a horizontally scaled deployment,
inject a shared store so one global budget is enforced across replicas:

```ts
import IORedis from 'ioredis'; // operator-provided; not bundled
const app = await buildServer({ config, rateLimitRedis: new IORedis(process.env.REDIS_URL) });
```

We deliberately do **not** bundle a Redis client — the seam accepts any
ioredis-compatible client, keeping the dependency surface minimal. Pair with a
WAF / edge rate limiting for internet-facing deployments and sticky routing for
the per-org streaming-concurrency cap.
