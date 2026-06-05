#!/usr/bin/env bash
#
# backup.sh — Capybara_AI encrypted backup (database + document store).
#
# Produces a consistent, timestamped, gzip-compressed PostgreSQL dump and a
# tarball of the (already AES-256-GCM-encrypted) document store. Optionally
# wraps both in GPG for at-rest protection of the backup medium itself.
#
# Fail-closed: any error aborts the whole run (set -euo pipefail). No secrets
# are ever printed; credentials are taken from the environment / DSN.
#
# Required env:
#   DATABASE_URL                Postgres DSN to dump (app or migration role).
# Optional env:
#   BACKUP_DIR                  Destination dir (default: ./backups).
#   DOCUMENT_STORAGE_DIR        Document store to archive (default: /data/documents).
#   BACKUP_RETENTION_DAYS       Prune backups older than N days (default: 14).
#   BACKUP_GPG_RECIPIENT        If set, encrypt artifacts to this GPG recipient.
#
# Usage:
#   DATABASE_URL=postgres://... ./scripts/backup.sh
#
# Cron example (daily 02:30, see DISASTER_RECOVERY.md):
#   30 2 * * * cd /opt/capybara && DATABASE_URL=... ./scripts/backup.sh >> /var/log/capy-backup.log 2>&1

set -euo pipefail

: "${DATABASE_URL:?DATABASE_URL is required}"
BACKUP_DIR="${BACKUP_DIR:-./backups}"
DOCUMENT_STORAGE_DIR="${DOCUMENT_STORAGE_DIR:-/data/documents}"
BACKUP_RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-14}"

ts="$(date -u +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"
# Backups may contain personal data — keep them owner-only.
chmod 700 "$BACKUP_DIR"

db_file="$BACKUP_DIR/capybara-db-$ts.sql.gz"
docs_file="$BACKUP_DIR/capybara-docs-$ts.tar.gz"

log() { printf '[backup %s] %s\n' "$(date -u +%H:%M:%S)" "$1"; }

maybe_encrypt() {
  # Encrypt $1 to $1.gpg if a recipient is configured, then remove the plaintext.
  local f="$1"
  if [ -n "${BACKUP_GPG_RECIPIENT:-}" ]; then
    log "encrypting $(basename "$f") to GPG recipient"
    gpg --batch --yes --trust-model always --encrypt --recipient "$BACKUP_GPG_RECIPIENT" --output "$f.gpg" "$f"
    rm -f "$f"
  fi
}

# 1. Database — consistent dump, compressed. pg_dump uses a single snapshot.
log "dumping database"
pg_dump --no-owner --no-privileges --format=plain "$DATABASE_URL" | gzip -9 > "$db_file"
chmod 600 "$db_file"
maybe_encrypt "$db_file"

# 2. Document store — archive the encrypted-at-rest files (skip if absent).
if [ -d "$DOCUMENT_STORAGE_DIR" ]; then
  log "archiving document store"
  tar -czf "$docs_file" -C "$DOCUMENT_STORAGE_DIR" .
  chmod 600 "$docs_file"
  maybe_encrypt "$docs_file"
else
  log "document store $DOCUMENT_STORAGE_DIR not found — skipping (db-only backup)"
fi

# 3. Retention — prune old artifacts. Never touches anything else.
log "pruning backups older than ${BACKUP_RETENTION_DAYS} days"
find "$BACKUP_DIR" -maxdepth 1 -type f \
  \( -name 'capybara-db-*' -o -name 'capybara-docs-*' \) \
  -mtime "+${BACKUP_RETENTION_DAYS}" -print -delete || true

log "done -> $BACKUP_DIR"
