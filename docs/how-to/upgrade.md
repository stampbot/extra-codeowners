# Upgrade, back up, and restore

Use this procedure for every package, container, or Helm upgrade. Extra
CODEOWNERS never changes schema during service startup. It starts only when the
database already matches the exact Alembic head bundled with that artifact.

!!! warning
    A changed migration head is a restore boundary. The previous artifact will
    reject the new head even when the SQL change was additive. Helm rollback
    does not run Alembic downgrade.

There is no supported release today. Apply this procedure only to an artifact
whose provenance and compatibility you have reviewed, and keep native GitHub
code-owner enforcement in place.

## Before you begin

Collect:

- immutable digests for the running and proposed application images
- the current chart version and complete values, when using Helm
- the current and target
  [database upgrade notes](../reference/upgrade-notes.md)
- a PostgreSQL role that can alter only the Extra CODEOWNERS database
- tested `pg_dump` and `pg_restore` versions compatible with the
  server
- storage for the backup and a separate test restore
- access to pause webhook ingress and application processes
- repository administration access to restore GitHub's native code-owner rule.

The upgrade notes must name the target revision and say whether the migration
head changes. Stop if they do not.

Run application commands from the current or target artifact named by each
step. Supply database credentials through a secret manager, protected
environment injection, or an operator-controlled `.pgpass`. Never paste a
database URL into shell history or a change record.

## 1. Record the current database state

Run this command from the currently deployed artifact with its normal database
secret:

```bash
extra-codeowners database check
```

For version 0.1.0, a compatible database prints:

```text
Database migration 0002_retry_dead_jobs is compatible.
```

Record the reported revision, current image digest, chart revision, PostgreSQL
major version, and UTC time in the change record. The check reads migration
metadata and table structure. It does not migrate or print the database URL.

Stop if it fails. Don't use an application rollout to repair an unknown
schema.

## 2. Choose the recovery point

Write down the recovery point objective before taking the backup. A
custom-format `pg_dump` is transactionally consistent, but a restore will
not contain events accepted after its snapshot.

For zero event loss at the upgrade snapshot, stop webhook ingress and every
application process first. Otherwise, record the snapshot time. After a
restore, you will need to redeliver later GitHub events and reconcile every
open pull request.

## 3. Create the backup

In a trusted POSIX shell, set libpq connection variables through your approved
secret mechanism. `PGDATABASE` must identify the production Extra
CODEOWNERS database. Then run:

```bash
pg_dump \
  --format=custom \
  --no-owner \
  --no-acl \
  --file=extra-codeowners-before-upgrade.dump \
  --dbname="$PGDATABASE"
```

The command must exit with status zero and create a nonempty dump. Encrypt it
with the approved backup system. Record its checksum, snapshot time, server
major version, retention rule, and access controls.

A successful `pg_dump` is not restore evidence.

## 4. Restore and verify the backup

Create an empty, access-restricted PostgreSQL database outside the production
service path. Point the libpq environment at that database and restore:

```bash
pg_restore \
  --exit-on-error \
  --no-owner \
  --no-acl \
  --dbname="$PGDATABASE" \
  extra-codeowners-before-upgrade.dump
```

Inject `EXTRA_CODEOWNERS_DATABASE_URL` for the isolated database, then run
the current artifact's checks:

```bash
extra-codeowners database check
extra-codeowners queue-status
```

The database check must report the same compatible revision recorded during
the preflight. Queue status prints `pending=N dead=N`. Compare that aggregate
with production, but don't copy repository names, pull-request metadata, or
secrets into the change record.

Keep the isolated restore until the change window closes. Then destroy it
under the approved retention policy.

## 5. Apply the target migration

For a package or container deployment, run exactly one migrator from the
target artifact:

```bash
extra-codeowners database migrate --lock-timeout-seconds 60
```

For version 0.1.0, success prints:

```text
Database is at migration 0002_retry_dead_jobs.
```

The migrator:

- obtains one PostgreSQL session advisory lock and waits no longer than the
  configured lock timeout
- runs each Alembic revision in its own transaction
- limits each PostgreSQL migration statement to 60 seconds
- releases the lock after success, failure, or connection loss
- exits nonzero when the migration does not finish.

Another migrator may wait on the same lock. Application processes do not wait
for it and do not migrate; they fail startup until the exact head exists.

### When Helm runs the migration

The chart enables a `pre-install,pre-upgrade` migration Job by default.
It runs the target image with migration-only database settings. It does not
inherit runtime environment sources, GitHub credential volumes, or App
secrets.

The defaults allow 60 seconds for the advisory lock, set Kubernetes
`backoffLimit` to `0`, and stop the complete Job after 180 seconds.
A failed hook stops Helm before it replaces application pods. Preserve its logs
before the default one-hour Job time-to-live expires.

The old process may still be active while the pre-upgrade hook runs. Every
revision must therefore avoid unbounded table rewrites, destructive operations,
and external API calls during that overlap. This rule protects in-flight work;
it does not promise compatibility between application versions at different
migration heads.

## 6. Deploy and verify

Run `database check` from the target artifact before starting the service.
Then deploy it and confirm:

- `/health/ready` returns HTTP 200 and reports the database, worker, and
  reconciler ready
- the migration Job ran once at the expected revision
- pending queue depth returns to its normal range
- reconciliation records a recent success
- a disposable pull request receives a current-head check from the expected
  App.

If ingress was paused, restore it only after every check passes. Inspect failed
GitHub deliveries after the outage boundary and redeliver them manually.
Confirm that scheduled reconciliation covers every open pull request.

## Roll back the application

First compare the database head from step 1 with the target head.

If the head did not change and the versioned upgrade notes allow it, run the
previous artifact's `database check` against the current database. Restore
the previous image only when that check succeeds.

If the head changed, restore the verified pre-migration backup:

1. Restore native **Require review from Code Owners** on every affected
   repository.
2. Stop webhook ingress and every Extra CODEOWNERS process.
3. Preserve the failed database and sanitized logs.
4. Restore the verified backup into a new empty database.
5. Run `database check` from the previous application artifact.
6. Point the previous deployment at the restored database.
7. Verify current GitHub state. Redeliver every event after the recovery point
   and wait for reconciliation before removing native protection.

Never restore over the only copy of the failed database. Never infer approval
from queue rows recovered from a backup; the worker must fetch current GitHub
evidence.

## Adopt the documented pre-release schema

Builds before Alembic created unversioned tables. They are not a supported
source release, and the migrator rejects them by default.

Only the Extra CODEOWNERS 0.1.0 artifact can adopt the documented pre-Alembic
schema. After taking and testing a backup, read the
[0.1.0 upgrade note](../reference/upgrade-notes.md#010). Establish where the
database came from; matching structure alone cannot prove provenance.

If it is the exact documented baseline, run once from the 0.1.0 artifact:

```bash
extra-codeowners database migrate --adopt-pre-alembic-schema
```

Adoption checks every expected table, column type, length, nullability,
PostgreSQL time-zone mode, server default, owned sequence,
identity or computed behavior, primary key, named unique constraint, plain
index, and compatibility marker. It rejects included columns, expressions,
ordering, predicates, unexpected dialect options, foreign keys, checks, and
additional application tables. On an exact match, it stamps revision 0001 and
runs the remaining 0.1.0 migration.

Later artifacts reject the adoption flag. Never adopt a partial, modified, or
origin-ambiguous database. Restore it, recreate it, or write a separate
reviewed migration for its exact origin.
