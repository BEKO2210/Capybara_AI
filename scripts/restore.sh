#!/usr/bin/env bash
#
# restore.sh — Capybara_AI restore from a backup produced by backup.sh.
#
# Restores a gzip (optionally GPG) PostgreSQL dump into a target database and,
# if provided, unpacks the document-store archive. This is DESTRUCTIVE: it
# overwrites the target database's contents. It therefore refuses to run unless
# you confirm — either interactively (typing the database name) or with --force.
#
# Fail-closed: any error aborts (set -euo pipefail). No secrets are printed.
#
# Required env:
#   DATABASE_MIGRATION_URL      Privileged DSN to restore into (NOT the app role).
# Optional env:
#   DOCUMENT_STORAGE_DIR        Where to unpack the docs archive (default: /data/documents).
#   BACKUP_GPG_RECIPIENT        Set when artifacts are .gpg (uses your gpg agent/key).
#
# Usage:
#   DATABASE_MIGRATION_URL=postgres://... ./scripts/restore.sh \
#       backups/capybara-db-YYYYMMDD-HHMMSS.sql.gz \
#       [backups/capybara-docs-YYYYMMDD-HHMMSS.tar.gz] [--force]

set -euo pipefail

: "${DATABASE_MIGRATION_URL:?DATABASE_MIGRATION_URL (privileged) is required}"
DOCUMENT_STORAGE_DIR="${DOCUMENT_STORAGE_DIR:-/data/documents}"

db_archive=""
docs_archive=""
force=0
for arg in "$@"; do
  case "$arg" in
    --force) force=1 ;;
    *.tar.gz|*.tar.gz.gpg) docs_archive="$arg" ;;
    *.sql.gz|*.sql.gz.gpg) db_archive="$arg" ;;
    *) echo "unrecognized argument: $arg" >&2; exit 2 ;;
  esac
done

[ -n "$db_archive" ] || { echo "usage: restore.sh <db.sql.gz> [docs.tar.gz] [--force]" >&2; exit 2; }
[ -f "$db_archive" ] || { echo "no such file: $db_archive" >&2; exit 2; }

log() { printf '[restore %s] %s\n' "$(date -u +%H:%M:%S)" "$1"; }

# Derive the target database name from the DSN for the confirmation prompt.
db_name="$(printf '%s' "$DATABASE_MIGRATION_URL" | sed -E 's#.*/([^/?]+)(\?.*)?$#\1#')"

if [ "$force" -ne 1 ]; then
  echo "WARNING: this OVERWRITES all data in database '$db_name'."
  printf "Type the database name to proceed: "
  read -r confirm
  [ "$confirm" = "$db_name" ] || { echo "aborted." >&2; exit 1; }
fi

# Stream-decrypt (if .gpg) then gunzip into psql.
decrypt_stream() {
  local f="$1"
  if [[ "$f" == *.gpg ]]; then gpg --batch --quiet --decrypt "$f"; else cat "$f"; fi
}

log "restoring database into '$db_name'"
decrypt_stream "$db_archive" | gunzip | psql --quiet --set ON_ERROR_STOP=1 "$DATABASE_MIGRATION_URL"
log "database restore complete"

if [ -n "$docs_archive" ]; then
  [ -f "$docs_archive" ] || { echo "no such file: $docs_archive" >&2; exit 2; }
  log "restoring document store into $DOCUMENT_STORAGE_DIR"
  mkdir -p "$DOCUMENT_STORAGE_DIR"
  decrypt_stream "$docs_archive" | tar -xzf - -C "$DOCUMENT_STORAGE_DIR"
  log "document store restore complete"
fi

log "done. Verify with /healthz and a smoke login before resuming traffic."
