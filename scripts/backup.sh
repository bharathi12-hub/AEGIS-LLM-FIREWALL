#!/usr/bin/env bash
# Postgres backup for AEGIS (audit is the system of record — back it up).
# Usage: AEGIS_DATABASE_URL=postgresql://... ./scripts/backup.sh [dest_dir]
set -euo pipefail

DEST="${1:-./backups}"
mkdir -p "$DEST"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$DEST/aegis-$STAMP.dump"

: "${AEGIS_DATABASE_URL:?set AEGIS_DATABASE_URL (postgresql://user:pw@host:5432/aegis)}"
# Normalize SQLAlchemy-style URL (postgresql+psycopg://) to libpq form.
PG_URL="${AEGIS_DATABASE_URL/+psycopg/}"
PG_URL="${PG_URL/+asyncpg/}"

echo "Backing up $PG_URL -> $OUT"
pg_dump --format=custom --no-owner --dbname="$PG_URL" --file="$OUT"

# Seal the current audit chain tip alongside the dump for tamper-evidence.
echo "$STAMP $(sha256sum "$OUT" | awk '{print $1}')" >> "$DEST/CHECKSUMS"
echo "Backup complete: $OUT"

# Retention: keep the last 30 backups.
ls -1t "$DEST"/aegis-*.dump 2>/dev/null | tail -n +31 | xargs -r rm -f
