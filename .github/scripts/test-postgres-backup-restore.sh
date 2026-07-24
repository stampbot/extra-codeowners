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
if [[ "$SOURCE_DATABASE" == "$RESTORE_DATABASE" ]]; then
  printf 'SOURCE_DATABASE and RESTORE_DATABASE must be different databases.\n' >&2
  exit 1
fi

run_without_libpq_environment() {
  local -a libpq_variables=()
  local variable
  while IFS= read -r variable; do
    if [[ "$variable" == PG* ]]; then
      libpq_variables+=("$variable")
    fi
  done < <(compgen -e)
  (
    unset "${libpq_variables[@]}"
    "$@"
  )
}

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

docker run --rm --interactive --network host \
  --env PGPASSWORD \
  "$client_image" psql \
  --host "$PGHOST" \
  --port "$PGPORT" \
  --username "$PGUSER" \
  --dbname "$SOURCE_DATABASE" \
  --set ON_ERROR_STOP=1 <<'SQL'
BEGIN;
TRUNCATE TABLE
  authority_epochs,
  authority_jobs,
  evaluation_audits,
  evaluation_jobs,
  service_leases,
  shared_head_epochs,
  webhook_deliveries
RESTART IDENTITY;

INSERT INTO evaluation_jobs (
  id, installation_id, repository_full_name, pull_number, head_sha_hint,
  last_delivery_id, reason, generation, authority_generation,
  shared_head_generation, state, attempts, requested_at, available_at,
  lease_owner, lease_until, last_error
) VALUES (
  41, 1701, 'example/backup-contract', 314,
  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'delivery-backup-contract',
  'backup-contract', 7, 3, 11, 'pending', 2,
  '2026-07-14 12:34:56.123456+00', '2026-07-14 12:35:56.654321+00',
  NULL, NULL, 'transient "quoted" error'
);

INSERT INTO shared_head_epochs (
  installation_id, repository_full_name, head_sha, generation,
  invalidated_generation, changed_at, available_at, attempts,
  lease_owner, lease_until, last_error
) VALUES (
  1701, 'example/backup-contract',
  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 11,
  10, '2026-07-14 12:33:53.101112+00',
  '2026-07-14 12:34:53.121314+00', 3, 'head-worker-backup',
  '2026-07-14 12:44:53.151617+00', 'head reset retry'
);

INSERT INTO webhook_deliveries (
  delivery_id, event, received_at, invalidation_required,
  invalidation_completed_at, installation_id, repository_full_name,
  pull_number, head_sha, shared_head_generation
) VALUES (
  'delivery-backup-contract', 'pull_request',
  '2026-07-14 12:33:54.111222+00', TRUE,
  '2026-07-14 12:33:55.333444+00', 1701,
  'example/backup-contract', 314,
  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 11
);

INSERT INTO evaluation_audits (
  id, repository_full_name, pull_number, head_sha, conclusion, details,
  evaluated_at
) VALUES (
  73, 'example/backup-contract', 314,
  'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'success',
  '{"apps":[{"id":123,"slug":"backup-bot"}],"approved":true,"nullable":null,"paths":["src/a.py","docs/space name.md"],"unicode":"caf\u00e9 \u2603"}',
  '2026-07-14 12:36:57.777888+00'
);

INSERT INTO service_leases (name, owner, lease_until) VALUES (
  'backup-contract-reconciler', 'worker-backup',
  '2026-07-14 12:40:00.000001+00'
);

INSERT INTO authority_jobs (
  id, installation_id, scope_key, base_ref, reason, generation, state,
  attempts, requested_at, available_at, lease_owner, lease_until, last_error
) VALUES (
  29, 1701, 'example/backup-contract', 'main', 'backup-contract', 4,
  'in_progress', 1, '2026-07-14 12:31:00.010203+00',
  '2026-07-14 12:32:00.040506+00', 'worker-backup',
  '2026-07-14 12:42:00.070809+00', NULL
);

INSERT INTO authority_epochs (installation_id, generation, changed_at) VALUES (
  1701, 9, '2026-07-14 12:30:00.987654+00'
);

SELECT setval(pg_get_serial_sequence('evaluation_jobs', 'id'), 410, TRUE);
SELECT setval(pg_get_serial_sequence('evaluation_audits', 'id'), 730, TRUE);
SELECT setval(pg_get_serial_sequence('authority_jobs', 'id'), 290, TRUE);
SELECT setval(
  pg_get_serial_sequence('authority_epochs', 'installation_id'),
  2000,
  TRUE
);
COMMIT;
SQL

capture_state() {
  database="$1"
  output="$2"
  docker run --rm --network host \
    --env PGPASSWORD \
    "$client_image" psql \
    --host "$PGHOST" \
    --port "$PGPORT" \
    --username "$PGUSER" \
    --dbname "$database" \
    --no-align \
    --tuples-only \
    --set ON_ERROR_STOP=1 \
    --command "
      SELECT jsonb_build_object(
        'alembic_version', (SELECT jsonb_agg(to_jsonb(t)) FROM alembic_version AS t),
        'authority_epochs', (SELECT jsonb_agg(to_jsonb(t) ORDER BY installation_id) FROM authority_epochs AS t),
        'authority_jobs', (SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM authority_jobs AS t),
        'evaluation_audits', (SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM evaluation_audits AS t),
        'evaluation_jobs', (SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM evaluation_jobs AS t),
        'schema_metadata', (SELECT jsonb_agg(to_jsonb(t) ORDER BY singleton_id) FROM schema_metadata AS t),
        'service_leases', (SELECT jsonb_agg(to_jsonb(t) ORDER BY name) FROM service_leases AS t),
        'shared_head_epochs', (SELECT jsonb_agg(to_jsonb(t) ORDER BY installation_id, repository_full_name, head_sha) FROM shared_head_epochs AS t),
        'webhook_deliveries', (SELECT jsonb_agg(to_jsonb(t) ORDER BY delivery_id) FROM webhook_deliveries AS t),
        'sequences', jsonb_build_object(
          'authority_epochs', (SELECT jsonb_build_object('last_value', last_value, 'is_called', is_called) FROM authority_epochs_installation_id_seq),
          'authority_jobs', (SELECT jsonb_build_object('last_value', last_value, 'is_called', is_called) FROM authority_jobs_id_seq),
          'evaluation_audits', (SELECT jsonb_build_object('last_value', last_value, 'is_called', is_called) FROM evaluation_audits_id_seq),
          'evaluation_jobs', (SELECT jsonb_build_object('last_value', last_value, 'is_called', is_called) FROM evaluation_jobs_id_seq)
        )
      );
    " > "$output"
}

capture_state "$SOURCE_DATABASE" "$backup_dir/source-state.json"

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
  EXTRA_CODEOWNERS_ENVIRONMENT=production \
  run_without_libpq_environment \
  uv run python -m extra_codeowners database check >/dev/null

capture_state "$RESTORE_DATABASE" "$backup_dir/restore-state.json"
if ! cmp --silent "$backup_dir/source-state.json" "$backup_dir/restore-state.json"; then
  printf 'Restored durable rows, JSON, timestamps, or sequence state differ from the source.\n' >&2
  exit 1
fi

next_values="$(
  docker run --rm --network host \
    --env PGPASSWORD \
    "$client_image" psql \
    --host "$PGHOST" \
    --port "$PGPORT" \
    --username "$PGUSER" \
    --dbname "$RESTORE_DATABASE" \
    --no-align \
    --tuples-only \
    --set ON_ERROR_STOP=1 \
    --command "SELECT nextval('evaluation_jobs_id_seq'), nextval('evaluation_audits_id_seq'), nextval('authority_jobs_id_seq'), nextval('authority_epochs_installation_id_seq');"
)"
if [[ "$next_values" != "411|731|291|2001" ]]; then
  printf 'Restored sequences did not generate the exact expected next values.\n' >&2
  exit 1
fi
