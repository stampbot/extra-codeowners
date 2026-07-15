# Upgrade, back up, and restore

Use this procedure for every Extra CODEOWNERS application or chart upgrade. The
service never creates or changes schema during normal startup. It starts only
when PostgreSQL is already at the migration head bundled with that application
version.

## Before you begin

You need:

- the immutable digest of the running and proposed application images
- the current chart version and values, when using Helm
- a dedicated PostgreSQL role that can alter only the Extra CODEOWNERS database
- a tested `pg_dump` and `pg_restore` version compatible with the server
- enough storage for both the backup and an isolated restore
- operator access to restore native GitHub code-owner protection before any
  database restore.

Read the [versioned upgrade notes](../reference/upgrade-notes.md) for both the
current and target releases. Do not continue when the notes do not name the
target database revision and whether the upgrade changes the head.

## 1. Record the current compatibility state

Run the check with the current image or package and its normal database secret:

```shell
extra-codeowners database check
```

Record the reported migration revision, current image digest, chart revision,
PostgreSQL major version, and UTC time in the change record. This command reads
schema metadata and table shape; it does not migrate or display the database
URL.

If the check fails, stop. Do not use an application upgrade to repair an
unknown schema.

## 2. Take a recoverable backup

Choose an explicit recovery point objective. A PostgreSQL custom-format dump is
transactionally consistent, but events accepted after its snapshot will not be
present after restore. For a zero-event-loss upgrade snapshot, stop webhook
ingress and application pods first. Otherwise, record the snapshot time and be
prepared to redeliver later GitHub deliveries and reconcile every open pull
request.

Keep the password out of command arguments and shell history. Use an
operator-controlled `.pgpass`, short-lived environment injection, or your
provider's secret mechanism. Run:

```shell
pg_dump \
  --format=custom \
  --no-owner \
  --no-acl \
  --file=extra-codeowners-before-upgrade.dump \
  EXTRA_CODEOWNERS_DATABASE
```

Encrypt the dump with the approved backup system. Record its checksum, server
major version, retention policy, and access controls. A completed `pg_dump`
process alone is not restore evidence.

## 3. Verify the backup in isolation

Create an empty, access-restricted PostgreSQL database outside the production
service path. Restore and validate it:

```shell
pg_restore \
  --exit-on-error \
  --no-owner \
  --no-acl \
  --dbname=EXTRA_CODEOWNERS_RESTORE_DATABASE \
  extra-codeowners-before-upgrade.dump

EXTRA_CODEOWNERS_DATABASE_URL=postgresql+psycopg://REDACTED_RESTORE_URL \
  extra-codeowners database check
```

Use secret injection for the real restore URL; the placeholder is deliberately
not runnable. Confirm aggregate queue counts against the source without copying
repository names, pull-request metadata, or secrets into the change record.
Destroy the isolated restore according to the data-retention policy after the
change window.

## 4. Apply the migration

For a package or container deployment, run exactly one explicit command from
the target artifact:

```shell
extra-codeowners database migrate --lock-timeout-seconds 60
```

The command:

- obtains a PostgreSQL session advisory lock, retrying only for the bounded
  lock timeout
- runs each Alembic revision in its own transaction
- limits each PostgreSQL migration statement to 60 seconds
- releases the lock on success, failure, or connection loss
- exits nonzero without starting the service when migration is incomplete.

Another migration process may wait on the same lock. Application processes do
not wait or migrate; they fail startup until the database reaches the exact
head.

The Helm chart enables a `pre-install,pre-upgrade` migration Job by default.
The Job uses the target image and migration-only database configuration. It
does not inherit runtime environment sources, GitHub credential volumes, or
App secrets. It has a 60-second lock timeout, no process retry, and a
180-second Kubernetes deadline. Helm does not replace application pods when
that hook fails. Retain the Job logs as change evidence.

Any migration that changes the Alembic head is a restore boundary. The previous
artifact's exact-head check rejects the new revision even when the physical
change is additive. Do not plan an old-image rollback against that database.
Restore the verified pre-migration backup with the procedure below.

The old application process can remain active while the pre-upgrade hook runs.
Do not put an unbounded table rewrite, destructive operation, or external API
operation in an Alembic revision. This protects in-flight work during the hook;
it is not a cross-head compatibility promise.

## 5. Verify and resume

Run `database check` from the target artifact. Then deploy the application and
verify:

- `/health/ready` reports the database, worker, and reconciler ready
- the migration Job completed once at the expected revision
- pending queue depth returns to its normal range
- reconciliation records a recent success
- a disposable pull request receives a current-head check from the expected App.

If ingress was paused, resume it only after those checks. Redeliver GitHub
deliveries after the recorded backup or outage boundary, then confirm scheduled
reconciliation covers all open pull requests.

## Roll back the application

Database migrations are forward-only. Helm rollback and application rollback
never run Alembic downgrade.

Compare the database head recorded in step 1 with the target head. If the head
did not change, the release notes may permit an application-only rollback. Run
the previous artifact's `database check` before resuming traffic.

If the head changed, always restore the verified pre-migration backup. An
additive schema change does not create an exception. Use this sequence:

1. restore native **Require review from Code Owners** on every affected
   repository
2. stop webhook ingress and every Extra CODEOWNERS process
3. preserve the failed database and sanitized logs for investigation
4. restore the verified backup into a new empty database
5. run `database check` from the previous application artifact
6. point the previous deployment at the restored database
7. verify current GitHub state and redeliver every delivery after the recovery
   point before removing native protection.

Never restore over the only copy of the failed database. Never infer approval
from queue rows recovered from a backup; workers must fetch current GitHub
evidence again.

## Adopt a pre-release database

Builds before the first supported release created tables directly and have no
Alembic revision. They are not a supported source version. The migration
command rejects them by default.

After taking and verifying a backup, inspect the
[0.1.0 upgrade note](../reference/upgrade-notes.md#010). If the database came
from that documented pre-release schema, use the Extra CODEOWNERS 0.1.0
artifact and run once:

```shell
extra-codeowners database migrate --adopt-pre-alembic-schema
```

Adoption succeeds only when every expected table, column type, length,
nullability, PostgreSQL time-zone mode, server default, owned sequence,
identity/computed behavior, primary key, named unique constraint, plain index,
and compatibility marker matches the immutable 0001 contract. Included
columns, expressions, ordering, predicates, unexpected dialect options,
foreign keys, checks, and additional application objects are rejected. It
stamps the baseline and then runs the remaining 0.1.0 revision.

Later application artifacts reject this adoption flag. Establish the
database's pre-release provenance before using 0.1.0; structural inspection
cannot prove why an Alembic marker is absent. A partial, modified, or
origin-ambiguous schema is never adopted. Restore, recreate, or write a
separately reviewed migration for its exact origin.
