#!/usr/bin/env bash

set -euo pipefail

client_image="${1:?usage: test-postgres-backup-restore.sh POSTGRES_IMAGE}"
: "${PGHOST:?PGHOST is required}"
: "${PGPORT:?PGPORT is required}"
: "${PGUSER:?PGUSER is required}"
: "${PGPASSWORD:?PGPASSWORD is required}"
: "${SOURCE_DATABASE:?SOURCE_DATABASE is required}"
: "${RESTORE_DATABASE:?RESTORE_DATABASE is required}"

if [[ ! "$SOURCE_DATABASE" =~ ^[a-z0-9_]+_test$ ]]; then
  printf 'SOURCE_DATABASE must end in _test and contain only lowercase safe characters.\n' >&2
  exit 1
fi
if [[ ! "$RESTORE_DATABASE" =~ ^[a-z0-9_]+_restore_test$ ]]; then
  printf 'RESTORE_DATABASE must end in _restore_test and contain only lowercase safe characters.\n' >&2
  exit 1
fi

backup_dir="$(mktemp -d)"
cleanup() {
  docker run --rm --network host \
    --env PGPASSWORD \
    "$client_image" dropdb \
    --if-exists \
    --force \
    --host "$PGHOST" \
    --port "$PGPORT" \
    --username "$PGUSER" \
    "$RESTORE_DATABASE" >/dev/null 2>&1 || true
  rm -rf "$backup_dir"
}
trap cleanup EXIT

docker run --rm --network host \
  --env PGPASSWORD \
  --volume "$backup_dir:/backup" \
  "$client_image" pg_dump \
  --host "$PGHOST" \
  --port "$PGPORT" \
  --username "$PGUSER" \
  --format custom \
  --no-owner \
  --no-acl \
  --file /backup/extra-codeowners.dump \
  "$SOURCE_DATABASE"

docker run --rm --network host \
  --env PGPASSWORD \
  "$client_image" createdb \
  --host "$PGHOST" \
  --port "$PGPORT" \
  --username "$PGUSER" \
  "$RESTORE_DATABASE"

docker run --rm --network host \
  --env PGPASSWORD \
  --volume "$backup_dir:/backup:ro" \
  "$client_image" pg_restore \
  --host "$PGHOST" \
  --port "$PGPORT" \
  --username "$PGUSER" \
  --exit-on-error \
  --no-owner \
  --no-acl \
  --dbname "$RESTORE_DATABASE" \
  /backup/extra-codeowners.dump

restore_url="postgresql+psycopg://${PGUSER}:${PGPASSWORD}@${PGHOST}:${PGPORT}/${RESTORE_DATABASE}"
EXTRA_CODEOWNERS_DATABASE_URL="$restore_url" \
  uv run python -m extra_codeowners database check >/dev/null
