#!/usr/bin/env bash
# Restore an AEGIS Postgres backup produced by backup.sh.
# Usage: AEGIS_DATABASE_URL=postgresql://... ./scripts/restore.sh <dump-file>
set -euo pipefail

DUMP="${1:?usage: restore.sh <dump-file>}"
: "${AEGIS_DATABASE_URL:?set AEGIS_DATABASE_URL}"
PG_URL="${AEGIS_DATABASE_URL/+psycopg/}"
PG_URL="${PG_URL/+asyncpg/}"

echo "WARNING: this restores $DUMP into $PG_URL (existing data will be replaced)."
read -r -p "Type 'restore' to continue: " confirm
[ "$confirm" = "restore" ] || { echo "aborted"; exit 1; }

pg_restore --clean --if-exists --no-owner --dbname="$PG_URL" "$DUMP"
echo "Restore complete. Verify audit integrity next:"
echo "  curl -s \$BASE/admin/audit/verify/chain -H \"X-Admin-Key: \$ADMIN\""
