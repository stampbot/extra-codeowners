# Upgrade, back up, and restore

Use this procedure for every package, container, or Helm upgrade. Extra
CODEOWNERS never changes schema during service startup. It starts only when the
database already matches the Alembic head and `required-release-contract`
bundled with that artifact.

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
step. Supply one `EXTRA_CODEOWNERS_DATABASE_URL` through a secret manager or
protected environment injection. The URL must explicitly contain one host,
database, username, and nonempty password. Percent-encode reserved characters
in the username and password. It must use the exact `postgresql+psycopg`
driver.

Extra CODEOWNERS does not use connection services, `.pgpass`, or ambient libpq
connection variables. Never paste the database URL into shell history or a
change record.

Run this procedure in Bash. Define a helper that removes every `PG*` variable
from application commands, including variables that external PostgreSQL tools
use later in this procedure:

```bash
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
```

Use this helper for every `extra-codeowners` command below. Production
validation fails when a recognized libpq variable is present, even when its
value is empty.

## 1. Record the current database state

Run this command from the currently deployed artifact with its normal database
secret:

```bash
run_without_libpq_environment extra-codeowners database check
```

For version 0.1.0, a compatible database prints:

```text
Database migration 0003_shared_head_epochs is compatible.
```

Record the reported revision, current image digest, chart revision, PostgreSQL
major version, and UTC time in the change record. The check reads migration
metadata and validates the artifact's `required-release-contract`. It does not
migrate or print the database URL.

Stop if it fails. Don't use an application rollout to repair an unknown
schema.

## 2. Choose the recovery point

Write down the recovery point objective before taking the backup. A
custom-format `pg_dump` is transactionally consistent, but a restore will
not contain events accepted after its snapshot.

For zero event loss at the upgrade snapshot, stop webhook ingress and every
application process first. Otherwise, record the snapshot time. After a
restore, you will need to redeliver later GitHub events and reconcile every
open pull request. Treat reconciliation as advisory and independently verify
each current check before relying on it.

Migration `0003_shared_head_epochs` requires the stronger option: stop webhook
ingress and every older worker before migration begins. An old process checks
database compatibility at startup and readiness, not before every queue claim.
Leaving one alive could let it publish without the new shared-head fence.

For an upgrade from `0002_retry_dead_jobs` to
`0003_shared_head_epochs`, keep this order:

1. Stop webhook ingress.
2. Stop every controller that can recreate an old worker, then stop every old
   worker and reconciler. Wait for graceful shutdown and for both the worker
   and reconciler lease periods to pass, so no old request or lease remains
   active.
3. Create and verify the backup in steps 3 and 4.
4. Run the target migration in step 5.
5. Start only code that requires `0003_shared_head_epochs`.
6. Complete the health checks in step 6, then restore ingress.
7. Treat startup reconciliation as advisory. Independently inventory
   accessible open pull requests and verify their current checks while native
   code-owner enforcement remains active.

### Drain a Kubernetes release

Setting a Deployment to zero is not a stable drain while a Horizontal Pod
Autoscaler (HPA) or GitOps controller can change it back. Suspend reconciliation
for the exact Argo CD Application, Flux resource, or other controller before
you alter the workload. Record its previous state. The controller must not
recreate the HPA, change the Deployment replica count, or sync an old image
until the target is ready.

The chart's 30-second termination grace is a pod-wide starting point, not a
reserved margin or shutdown guarantee. The server may finish active HTTP work
before application shutdown begins. The worker finishes its active job before
observing the stop signal, and some worker response streams have inactivity
limits rather than one wall-clock deadline. After the reconciler observes the
signal, its current GitHub request can still use its 20-second deadline, and
database work or local cleanup can add time. Measure worst-case drain in your
environment and set `terminationGracePeriodSeconds` above it.

From a trusted POSIX shell with the intended `kubectl` context, set these
values. Replace `DEPLOYMENT` if the chart uses a name override. Set the two
intervals to the deployed `EXTRA_CODEOWNERS_WORKER_LEASE_SECONDS` and
`EXTRA_CODEOWNERS_RECONCILE_INTERVAL_SECONDS` values:

```bash
NAMESPACE=extra-codeowners
RELEASE=extra-codeowners
DEPLOYMENT=extra-codeowners
WORKER_LEASE_SECONDS=120
RECONCILE_INTERVAL_SECONDS=300
RECONCILER_LEASE_SECONDS=$((RECONCILE_INTERVAL_SECONDS * 2))
if [ "$RECONCILER_LEASE_SECONDS" -lt 300 ]; then
  RECONCILER_LEASE_SECONDS=300
fi
DRAIN_WAIT_SECONDS="$WORKER_LEASE_SECONDS"
if [ "$RECONCILER_LEASE_SECONDS" -gt "$DRAIN_WAIT_SECONDS" ]; then
  DRAIN_WAIT_SECONDS="$RECONCILER_LEASE_SECONDS"
fi
```

After webhook ingress is stopped and GitOps reconciliation is suspended,
remove the HPA and drain the Deployment:

```bash
kubectl --namespace "$NAMESPACE" delete \
  horizontalpodautoscaler "$DEPLOYMENT" --ignore-not-found
kubectl --namespace "$NAMESPACE" scale \
  deployment "$DEPLOYMENT" --replicas=0
kubectl --namespace "$NAMESPACE" wait \
  --for=delete pod \
  --selector="app.kubernetes.io/instance=$RELEASE,app.kubernetes.io/component=application" \
  --timeout=5m
sleep "$DRAIN_WAIT_SECONDS"
```

Verify the drain before migration:

```bash
test "$(
  kubectl --namespace "$NAMESPACE" get deployment "$DEPLOYMENT" \
    --output=jsonpath='{.spec.replicas}'
)" = "0"
test -z "$(
  kubectl --namespace "$NAMESPACE" get pods \
    --selector="app.kubernetes.io/instance=$RELEASE,app.kubernetes.io/component=application" \
    --output=name
)"
if kubectl --namespace "$NAMESPACE" get \
  horizontalpodautoscaler "$DEPLOYMENT" >/dev/null 2>&1; then
  echo "the autoscaler is still active" >&2
  exit 1
fi
```

All three checks are silent on success. If any check fails, stop. Find the
controller that restored the resource, suspend it, and repeat the drain.

## 3. Create the backup

In the trusted Bash shell, set these variables through your approved secret
mechanism:

```bash
: "${PGPASSWORD:?set PGPASSWORD through the approved secret mechanism}"
export PGHOST="db.example.com"
export PGPORT="5432"
export PGUSER="extra_codeowners_backup"
export PGPASSWORD
export PGDATABASE="extra_codeowners"
```

`PGPASSWORD` must already contain the backup role's password without printing
it. The other values must explicitly identify the production Extra CODEOWNERS
database. These variables are for `pg_dump` and `pg_restore` only; the helper
removes them before any application command.

Don't set `PGSERVICE`, `PGSERVICEFILE`, or `PGPASSFILE`, and don't rely on
`.pgpass`. Run:

```bash
pg_dump \
  --host="$PGHOST" \
  --port="$PGPORT" \
  --username="$PGUSER" \
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
service path. Set `RESTORE_DATABASE` to its name, then restore through the same
explicit host, port, and role:

```bash
RESTORE_DATABASE="extra_codeowners_restore"
pg_restore \
  --host="$PGHOST" \
  --port="$PGPORT" \
  --username="$PGUSER" \
  --exit-on-error \
  --no-owner \
  --no-acl \
  --dbname="$RESTORE_DATABASE" \
  extra-codeowners-before-upgrade.dump
```

Inject `EXTRA_CODEOWNERS_DATABASE_URL` for the isolated database, then run
the current artifact's checks:

```bash
run_without_libpq_environment extra-codeowners database check
run_without_libpq_environment extra-codeowners queue-status
```

The database check must report the same compatible revision recorded during
the preflight. Queue status prints `pending=N dead=N`. Compare that aggregate
with production, but don't copy repository names, pull-request metadata, or
secrets into the change record.

Keep the isolated restore until the change window closes. Then destroy it
under the approved retention policy.

After the PostgreSQL client work is complete, remove its credentials from the
shell:

```bash
unset PGHOST PGPORT PGUSER PGPASSWORD PGDATABASE RESTORE_DATABASE
```

Before step 5, replace `EXTRA_CODEOWNERS_DATABASE_URL` with the production URL
through the approved secret mechanism. Verify its target in the deployment
platform without printing it. Stop if the application command would still
reach the isolated restore.

## 5. Apply the target migration

For a package or container deployment, run exactly one migrator from the
target artifact:

```bash
run_without_libpq_environment \
  extra-codeowners database migrate --lock-timeout-seconds 60
```

For version 0.1.0, success prints:

```text
Database is at migration 0003_shared_head_epochs.
```

The migrator:

- obtains one PostgreSQL session advisory lock and waits no longer than the
  configured lock timeout
- runs each Alembic revision in its own transaction
- limits each PostgreSQL migration statement to 60 seconds
- pins `search_path=public`
- validates the target artifact's `required-release-contract` after Alembic,
  including when the database was already at the target head
- releases the lock after success, failure, or connection loss
- exits nonzero when the migration does not finish.

Another migrator may wait on the same lock. Application processes do not wait
for it and do not migrate; they fail startup until the exact head exists.

### When Helm runs the migration

The chart enables a `pre-install,pre-upgrade` migration Job by default.
It runs the target image with migration-only database settings. It does not
inherit runtime environment sources, GitHub credential volumes, or App
secrets.

Before an upgrade to `0003_shared_head_epochs`, complete the Kubernetes drain
in step 2. Confirm that no HPA, old worker, or reconciler remains. The
pre-upgrade hook does not stop existing pods or suspend GitOps for you.

Keep GitOps reconciliation suspended for both Helm updates below. Set
`TARGET_CHART` to the reviewed chart path or immutable OCI reference, and set
`TARGET_VALUES` to a complete reviewed values file. That file must name the
target image by digest and explicitly declare the final autoscaling settings:

```bash
TARGET_CHART=/path/to/reviewed/extra-codeowners-chart
TARGET_VALUES=/path/to/reviewed/target-values.yaml
```

Run the migration upgrade with autoscaling forced off. One target pod starts
after the pre-upgrade hook succeeds:

```bash
helm upgrade "$RELEASE" "$TARGET_CHART" \
  --namespace "$NAMESPACE" \
  --reset-values \
  --values "$TARGET_VALUES" \
  --set autoscaling.enabled=false \
  --set replicaCount=1 \
  --wait \
  --timeout=10m
```

The ten-minute Helm wait is longer than the default five-minute startup budget
and the three-minute migration Job deadline. If you increase either chart
budget, increase the Helm timeout too. Leave enough margin for scheduling and
image startup.

Do not remove the temporary autoscaling override during this first update.
Verify the database head and target pod in step 6 before you restore the final
autoscaling configuration.
If a GitOps platform does not let an operator perform these two ordered Helm
updates while its reconciliation is suspended, stop and write a
platform-specific plan that preserves the same drain, migration, and
verification boundaries.

The defaults allow 60 seconds for the advisory lock, set Kubernetes
`backoffLimit` to `0`, and stop the complete Job after 180 seconds.
A failed hook stops Helm before it replaces application pods. Preserve its logs
before the default one-hour Job time-to-live expires.

Unless an upgrade-ledger entry requires a full drain, the old process may
still be active while the pre-upgrade hook runs. Every revision must avoid
unbounded table rewrites, destructive operations, and external API calls
during that overlap. This rule protects in-flight work; it does not promise
compatibility between application versions at different migration heads.

## 6. Deploy and verify

For a package or container deployment, run
`run_without_libpq_environment extra-codeowners database check` from the
target artifact before you start the service. Start only the target artifact.

For Helm, the first `helm upgrade --wait` in step 5 has already started one
target pod. Verify the hook's exact success message and that pod's rollout
before the second update. Set `CHANGE_RECORD_DIR` to an existing,
access-controlled directory outside the working tree. The second update
deletes the first hook Job and its Kubernetes logs, so preserve that evidence
now:

```bash
CHANGE_RECORD_DIR=/path/to/access-controlled/change-record
FIRST_MIGRATION_LOG="$CHANGE_RECORD_DIR/extra-codeowners-0003-first-migration.log"
test -d "$CHANGE_RECORD_DIR"
test ! -e "$FIRST_MIGRATION_LOG"
kubectl --namespace "$NAMESPACE" wait \
  --for=condition=complete "job/$DEPLOYMENT-migrate" \
  --timeout=5m
(
  umask 077
  kubectl --namespace "$NAMESPACE" logs \
    "job/$DEPLOYMENT-migrate" --container=migrate >"$FIRST_MIGRATION_LOG"
)
grep --fixed-strings --line-regexp \
  'Database is at migration 0003_shared_head_epochs.' \
  "$FIRST_MIGRATION_LOG"
kubectl --namespace "$NAMESPACE" rollout status \
  "deployment/$DEPLOYMENT" --timeout=10m
test "$(
  kubectl --namespace "$NAMESPACE" get deployment "$DEPLOYMENT" \
    --output=jsonpath='{.status.readyReplicas}'
)" = "1"
```

Every command must succeed. The exact migration line proves that the hook
reached the target head and passed the target artifact's
`required-release-contract`. Rollout status proves that the target pod passed
its startup and readiness probes.

The first target pod should acquire the reconciler lease immediately because
the drain waited out the old lease. At INFO level, its
`reconciliation_complete` event is useful liveness evidence. It is not
coverage evidence: the current scan can return a partial count after lease
loss and can skip malformed GitHub records.

Keep native code-owner enforcement active. Use a GitHub-side inventory,
independent of Extra CODEOWNERS, to enumerate every repository available to
the App and every open pull request in those repositories. For each pull
request, verify a current-head check from the expected App. Rerequest a stale
check; for a missing check, redeliver or recreate a mapped trigger. Wait for a
blocking or completed current-head result. If you cannot complete that
inventory, record the gap and retain the fail-closed maintenance posture.

Then confirm:

- `/health/ready` returns HTTP 200 and reports the database, worker, and
  reconciler ready
- the initial migration Job completed at the expected revision
- pending queue depth returns to its normal range
- a disposable pull request receives a current-head check from the expected
  App.

Keep ingress paused after these checks. Restore the reviewed final autoscaling
settings with a second Helm update:

```bash
helm upgrade "$RELEASE" "$TARGET_CHART" \
  --namespace "$NAMESPACE" \
  --reset-values \
  --values "$TARGET_VALUES" \
  --wait \
  --timeout=10m
```

The `before-hook-creation` policy deletes the first migration Job and its
cluster logs before this second hook starts. Preserve and verify the second
hook's evidence too:

```bash
SECOND_MIGRATION_LOG="$CHANGE_RECORD_DIR/extra-codeowners-0003-final-migration.log"
test ! -e "$SECOND_MIGRATION_LOG"
(
  umask 077
  kubectl --namespace "$NAMESPACE" logs \
    "job/$DEPLOYMENT-migrate" --container=migrate >"$SECOND_MIGRATION_LOG"
)
grep --fixed-strings --line-regexp \
  'Database is at migration 0003_shared_head_epochs.' \
  "$SECOND_MIGRATION_LOG"
```

The second migrator takes the same advisory lock and confirms that the database
is already at `0003_shared_head_epochs`. Alembic makes no schema change, but
the migrator still validates the `required-release-contract` before it prints
success.

Verify the target Deployment and final autoscaling state. The HPA must exist
when the reviewed values enable autoscaling and must be absent when they
disable it. Then resume GitOps reconciliation and confirm that it does not
reintroduce the old image, chart, or temporary autoscaling override.

Restore webhook ingress only after those checks pass. Inspect failed GitHub
deliveries after the outage boundary and redeliver them manually. Treat
reconciliation output as advisory until the service reports strict,
per-installation scan outcomes. Keep native enforcement active for any pull
request whose current check you did not verify independently.

## Roll back the application

First compare the database head from step 1 with the target head.

If the head did not change and the versioned upgrade notes allow it, run the
previous artifact's `database check` through
`run_without_libpq_environment`. Restore the previous image only when that
check succeeds.

If the head changed, restore the verified pre-migration backup:

1. Restore native **Require review from Code Owners** on every affected
   repository.
2. Stop webhook ingress and every Extra CODEOWNERS process.
3. Preserve the failed database and sanitized logs.
4. Restore the verified backup into a new empty database.
5. Run `database check` through `run_without_libpq_environment` from the
   previous application artifact.
6. Point the previous deployment at the restored database.
7. Verify current GitHub state. Redeliver every event after the recovery point
   and independently verify every accessible open pull request before removing
   native protection. Reconciliation output alone is not coverage proof.

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
run_without_libpq_environment \
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
