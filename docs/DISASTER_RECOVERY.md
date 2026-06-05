# Disaster Recovery Runbook

This runbook covers backup, restore, and recovery for a self-hosted Capybara_AI
deployment. It is intentionally concrete: copy/paste-able commands, explicit
recovery objectives, and a verification checklist you can run after a restore.

## Recovery objectives

| Objective | Target | Driven by |
| --- | --- | --- |
| **RPO** (max data loss) | ≤ 24h (default daily backup) | backup frequency |
| **RTO** (max downtime) | ≤ 1h for a single-node restore | this runbook |

Tighten RPO by running `backup.sh` more frequently (e.g. hourly) and/or enabling
PostgreSQL WAL archiving / point-in-time recovery (out of scope here but
compatible).

## What is backed up

1. **PostgreSQL database** — all tenants, users, memberships, audit chain,
   security events, AI inventory, encrypted document metadata, and the
   per-org wrapped encryption keys (`encryption_key_versions`).
2. **Document store** (`DOCUMENT_STORAGE_DIR`) — the document blobs, which are
   already AES-256-GCM encrypted at rest (per-tenant subkeys via HKDF).

> **Key material:** `ENCRYPTION_KEY`, `DOCUMENT_ENCRYPTION_KEY`, and `MASTER_KEK`
> are **NOT** in the backups. Store them in a secrets manager / KMS. A database
> backup is useless for decrypting documents without `DOCUMENT_ENCRYPTION_KEY`
> (and `MASTER_KEK` to unwrap rotated DEKs). Back these up **separately and
> securely**, and never in the same location as the data.

## Taking a backup

### Host (full: database + documents)

```bash
DATABASE_URL='postgres://capybara_app:***@db:5432/capybara' \
DOCUMENT_STORAGE_DIR=/data/documents \
BACKUP_DIR=/var/backups/capybara \
BACKUP_RETENTION_DAYS=14 \
./scripts/backup.sh
```

Optional at-rest encryption of the backup medium itself:

```bash
BACKUP_GPG_RECIPIENT=ops@yourco.example ./scripts/backup.sh
# produces *.sql.gz.gpg and *.tar.gz.gpg
```

### Docker (database only, on demand)

```bash
docker compose -f docker/docker-compose.yml --profile backup run --rm backup
# writes into the capy-backups volume; prunes per BACKUP_RETENTION_DAYS
```

### Scheduling

Run daily via cron (host) or your scheduler:

```cron
30 2 * * * cd /opt/capybara && DATABASE_URL='postgres://...' \
  BACKUP_DIR=/var/backups/capybara ./scripts/backup.sh >> /var/log/capy-backup.log 2>&1
```

`/healthz` reports `components.backup = degraded` (HTTP 503) when the newest
backup in `BACKUP_DIR` is missing or older than 48h — wire it to alerting.

## Restoring

> Restores are **destructive** — they overwrite the target database. Restore
> into a fresh/standby database first when possible, verify, then cut over.

1. **Provision** a PostgreSQL 16 instance with the `vector` extension available.
2. **Restore** using the privileged migration DSN (not the app role):

   ```bash
   DATABASE_MIGRATION_URL='postgres://postgres:***@db:5432/capybara' \
   DOCUMENT_STORAGE_DIR=/data/documents \
   ./scripts/restore.sh \
     /var/backups/capybara/capybara-db-20260605-023000.sql.gz \
     /var/backups/capybara/capybara-docs-20260605-023000.tar.gz
   ```

   You will be prompted to type the database name to confirm (or pass `--force`
   for automation). GPG-encrypted artifacts (`*.gpg`) are decrypted inline via
   your gpg agent.

3. **Restore key material** from your secrets manager into the app environment
   (`ENCRYPTION_KEY`, `DOCUMENT_ENCRYPTION_KEY`, `MASTER_KEK`).
4. **Start** the app and run the verification checklist below.

## Post-restore verification checklist

- [ ] `GET /healthz` returns `200` with `db: ok`, `vectorSearch: ok`.
- [ ] A smoke login succeeds (local or SSO).
- [ ] Audit chain intact: run the chain verifier (`npm run verify:chain` or the
      `verifyChain` routine) — it must report `ok: true`.
- [ ] A known document opens and decrypts (proves `DOCUMENT_ENCRYPTION_KEY` +
      any rotated DEKs via `MASTER_KEK` are correct).
- [ ] RAG search returns results for a known query (proves pgvector data).
- [ ] Tenant isolation spot-check: a user from org A cannot see org B's data.

## Failure scenarios

| Scenario | Action |
| --- | --- |
| Corrupt latest backup | Restore the previous artifact; backups are timestamped and retained for `BACKUP_RETENTION_DAYS`. |
| Lost `DOCUMENT_ENCRYPTION_KEY`/`MASTER_KEK` | Document blobs are unrecoverable by design. Recover keys from your KMS/secrets backup. |
| Partial document-store loss | Restore only the docs archive; DB metadata still references the blobs by stable storage path. |
| Suspected tampering | Verify the hash-chained `security_events` log; investigate any break before trusting the restore. |

## Rotation interplay

Key rotation (`POST /api/admin/encryption/rotate`) re-encrypts chunk/message
ciphertext under a new DEK and **retains** old key versions (marked inactive).
A backup taken mid-rotation is still consistent because rotation runs inside a
transaction. After restoring, the active key version in `encryption_key_versions`
is authoritative; `MASTER_KEK` must match the one in force when the backup was
taken.
