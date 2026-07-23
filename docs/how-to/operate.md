# Operate and recover Extra CODEOWNERS

Use this runbook to monitor the service, investigate a stale check, rotate
credentials, and retire an installation without dropping code-owner
enforcement.

Operate from documentation that matches the deployed commit. Before the first
supported release, operational interfaces may change without a compatibility
period. The [deployment guide](deploy.md) describes the runtime and its current
production blockers.

## Know the healthy baseline

Record a normal value and alerting objective for each signal below. A fixed
threshold is less useful than a baseline because webhook volume varies with
pull-request activity.

| Signal | Healthy condition |
| --- | --- |
| `/health/live` | HTTP 200 on every serving instance |
| `/health/ready` | HTTP 200, with database and configured background tasks ready |
| `extra_codeowners_queue_depth` | Returns to the local baseline after webhook bursts |
| `extra_codeowners_shared_head_invalidation_depth` | Returns to `0`; a sustained value means exact-commit revocations are waiting |
| `extra_codeowners_shared_head_invalidations_total{result="failed"}` | No unexplained increase |
| `extra_codeowners_dead_jobs` | `0` |
| `extra_codeowners_webhook_failures_total` | No unexplained increase |
| `extra_codeowners_reconciliations_total{result!="success"}` | No unexplained increase |
| `extra_codeowners_reconciliation_last_success_timestamp_seconds` | A complete run on at least one replica falls within the reconciliation objective |
| `extra_codeowners_insecure_changes_enabled` | `0` unless an approved exception is active |

Also watch evaluation latency and failures, PostgreSQL latency, repeated GitHub
API `403` or `429` responses, and every unexplained long-lived
`in_progress` check.

A replica that observes another process holding the reconciler lease does not
record an attempt. Shutdown before a scan begins does not record one either.
An election error is a failure. A partial attempt means the process lost its
lease, an active scan was interrupted by graceful shutdown, or the process
could not safely scan an installation or queue its pull requests. This includes
GitHub request failures, invalid GitHub responses, and database errors while
adding queue jobs. Work from healthy installations may still be queued, but a
partial attempt does not refresh the last-success gauge.

A malformed top-level installation response fails the whole attempt before the
service processes any installation. Once that list passes validation, a
malformed repository or open pull request list fails only the affected
installation. Work already queued stays queued, and the reconciler continues
with later installations. Field-level validation logs use fixed reason codes.
If GitHub returns something other than the expected list or includes a
non-object item, the client rejects it before field validation. The service
then logs a fixed reconciliation event and error template instead. Neither path
logs the rejected value.

During graceful shutdown or after lease loss, an active reconciler stops before
the next retention operation, GitHub page or API request, repository scan, and
queue insertion. Neither condition cancels an operation already in progress.
Each reconciliation request has a 20-second wall-clock deadline. PostgreSQL
connect, pool, and statement waits also have fixed limits, but a
multi-statement database operation and local cleanup add to the shutdown time.

Kubernetes applies one grace period to the whole pod. The server may finish
active HTTP work before application shutdown begins, and the worker finishes
an active invalidation, authority, or evaluation job before observing the stop
signal. Some worker response streams have inactivity limits rather than one
wall-clock deadline. Treat the chart's 30-second default as a starting point.
Measure worst-case drain time in your environment and increase
`terminationGracePeriodSeconds` to cover it.

In a deployment with several replicas, compare the newest gauge value across
them. One practical alert expression is
`time() - max(extra_codeowners_reconciliation_last_success_timestamp_seconds)`,
with a threshold equal to your reconciliation objective.

If an instance is meant to run background work, enable both the worker and
reconciler and confirm that both health-response fields are `true`. Keep
the deployment settings in the same check because a disabled task reports as
healthy. Every node also needs an accurate UTC clock. Clock skew can break
GitHub authentication, setup-state expiry, and database leases.

Reconciliation requests work only for open pull requests that do not already
have a queue row. When the response includes a canonical head, the database
advances that head's shared generation in the same transaction that inserts
the row. A reconciled check briefly returns to `in_progress` while the worker
fetches current evidence. Choose an interval that balances that short merge
interruption against stale-evidence exposure, GitHub API use, and your recovery
objective.

The service does not expose remaining GitHub rate-limit quota. Watch API
failures instead, and keep the service limited to disposable repositories
until a deployment-specific rate-limit monitor closes that gap.

## Protect logs and audit data

Accepted-webhook logs include the delivery ID, event, action, available
repository or pull-request context, and whether work was queued. Ignored events
omit repository and pull-request fields because the service does not retain
them. Evaluation failures carry the pull request and last-delivery correlation
fields. Authority failures carry the installation, scope, and reason. An audit
triggered by a direct delivery records its reason and delivery ID.

Treat all of this as private repository metadata. Restrict access and
retention. Logs and audits must never contain installation tokens, private
keys, webhook secrets, authorization headers, complete private payloads, or
file contents.

## Manage delivery and audit retention

`EXTRA_CODEOWNERS_WEBHOOK_DELIVERY_RETENTION_DAYS` defaults to 30 days.
Set it long enough to cover GitHub redelivery and incident investigation, but
don't retain private metadata longer than you can justify.

The elected reconciler prunes expired delivery IDs and logs
`webhook_deliveries_pruned` when it removes any. It also prunes old shared-head
rows, but only after the latest generation was invalidated, no evaluation
references that installation, repository, and head, and no invalidation lease
remains. Those removals use the `shared_head_epochs_pruned` log event.
Both cleanup tasks run before GitHub installation discovery, so a discovery
failure does not postpone them. Disabling reconciliation disables both tasks.

An expired ID may be accepted again if GitHub redelivers it. That does not
restore old authorization evidence. The delivery creates or coalesces a fresh
pull-request job, and the worker reads current GitHub state.

The service retains only the latest evaluation audit for each pull request,
but it does not delete those rows automatically. Back up the database before
an approved retention operation. Direct database changes for any other reason
are unsupported.

## Investigate a missing or stale check

Work through these steps in order. Don't publish a replacement success or edit
queue state to make the symptom disappear.

### 1. Confirm that policy should run

Read repository policy from the pull request's exact base commit. Confirm that
it exists at the effective `EXTRA_CODEOWNERS_POLICY_PATH` and contains
`enabled = true`. The default path is
`.github/extra-codeowners.toml`.

Confirm that the App installation can access both the target repository and
the organization-policy repository, which defaults to `.github`.

An absent repository policy produces no check when the repository has no
previous managed check. An explicitly disabled policy produces a failing
check. The organization-policy repository itself is deliberately excluded
from pull-request evaluation and must use native human code-owner enforcement.

### 2. Trace the GitHub delivery

Open the App's **Advanced** settings and find the delivery. Record its delivery
ID and event type, but don't copy the complete payload into an issue.

- If GitHub never attempted it, check the App subscription and repository
  selection.
- If GitHub received a non-2xx response, find the same delivery ID in ingress
  and service logs.
- If GitHub reports a network failure, check DNS, TLS, ingress routing, and
  readiness.
- If a mapped delivery succeeded, continue to the durable queue.

Mapped events cover pull requests, reviews, check rerequests, pushes, labels,
members, memberships, teams, team additions, organizations, installations,
installation targets, repositories, and installation repository selection.
Unsupported actions are authenticated and acknowledged without durable work.

Pull-request events for the organization-policy repository are also
acknowledged without retention. A relevant push or lifecycle event for that
repository is retained and fans out across the installation. Removal of that
repository, or malformed removal evidence, does the same. A well-formed removal
containing only ordinary target repositories is acknowledged without work
because the App has already lost access to them.

If you see `webhook_durable_acceptance_failed`, ingress could not confirm
durable storage. A database failure can cause this. So can a timeout while an
authority event waits for an in-flight Check Run writer.

PostgreSQL uses fixed limits of 3 seconds to connect, 2 seconds to obtain an
application-pool connection, and 3 seconds for an ordinary statement.
Correlate the error with provider latency, proxy health, pool exhaustion, and
lock contention. Once the dependency is healthy, redeliver the failed event.
GitHub does not retry it automatically.

### 3. Inspect the worker and queue

Check readiness, PostgreSQL connectivity, worker and reconciler task health,
the last successful reconciliation, queue depth, repeated failures, and GitHub
API errors.

Run the queue summary from a reviewed checkout configured with the same
database URL:

```bash
uv run python -m extra_codeowners queue-status
```

Inside the installed runtime image, which does not contain `uv`, run:

```bash
python -m extra_codeowners queue-status
```

The command prints only aggregate counts:

```text
pending=N dead=N
```

`pending` combines exact-head invalidation, pull-request evaluation, and
authority fan-out. `dead` covers only legacy or manually introduced evaluation
and authority rows. Ordinary failures remain pending, so `dead` should be
zero. Migration `0002_retry_dead_jobs` reactivates terminal rows from the
earlier pre-release retry contract. Treat a later terminal row as incompatible
or manually introduced state and investigate it.

Exact-head invalidation runs first, then authority work, then ordinary
pull-request evaluation. Installation-wide authority work splits into
repository fences. Repository-wide work replaces older base-specific rows, and
more than 100 distinct base refs for one repository collapse into a
conservative repository-wide job.

For a mapped pull-request, review, or check-rerequest delivery, ingress stores
the trigger and then makes a bounded attempt to move the managed check to
`in_progress`. If a fast-path API call fails or times out, the service logs
`webhook_check_invalidation_deferred`, increments the webhook failure
counter with reason `invalidation_fast_path`, and still returns `202` because
the exact-head invalidation row remains authoritative.

If the evaluator is unavailable, ingress retains the delivery but returns
`503`. Redeliver after recovery.

The exact-head worker updates an existing managed check by ID and queues every
open pull request that GitHub currently reports on that commit. It does not
create a check for a historical commit. Logs use
`shared_head_invalidation_completed`, `shared_head_invalidation_failed`,
`shared_head_invalidation_superseded`, and
`shared_head_invalidation_lease_lost` to distinguish completion, retry, and
fencing.

Before reading mutable approval evidence, the evaluation worker keeps the
current-head check `in_progress`. It cannot publish until the exact-head
generation finishes. A later trigger, an exception, or unresolved authority
fan-out therefore remains blocking. Invalidation, evaluation, and authority
failures retry forever. Ordinary exponential delay stops growing at
`EXTRA_CODEOWNERS_WORKER_RETRY_MAX_SECONDS`; GitHub rate limits use their
own bounded delay.

An error or cancellation during the completed write is a special case because
GitHub may have applied the result before the client lost its response. The
same uncertainty applies to a database error or cancellation during the
post-publication check. The worker attempts a shielded reset to `in_progress`
while it still holds the head writer guard and then preserves the original
failure for retry. The
`completed_check_blocking_reset_failed` and
`completed_check_blocking_reset_cancelled` events mean the reset request itself
failed or ended cancelled. An ordinary evaluation cancellation that completes
the shielded reset emits neither event. A hard process stop or failed reset can
leave the completed result visible, so keep native enforcement in place and
verify that durable retry or a later trigger restores the blocking check.

A long-lived `in_progress` check with repeated failures needs a database,
network, credential, permission, or GitHub recovery. It does not need a
manufactured result.

### 4. Recover from the cause

If GitHub did not receive a successful response, restore service health and use
**Redeliver**. GitHub doesn't redeliver failures on its own.

A duplicate direct trigger can retry the bounded fast path. Otherwise,
delivery deduplication leaves the committed exact-head invalidation and
evaluation in place. Scheduled reconciliation creates work only when the pull
request has no evaluation row.

Fix the dependency, credential, permission, or policy problem and let pending
work retry. A nonzero exact-head invalidation depth means evaluations cannot
publish at that generation. Don't reset attempts to accelerate a retry storm.
Use `requeue-dead` only for a legacy or manually introduced terminal row.

Never mark work complete in the database or publish a success manually.

### 5. Verify current GitHub state

On the pull request's exact current head, confirm that the expected App
published the check. Read its summary and verify the current labels, approvals,
paths, and owner sets. A successful check on an older commit is not recovery
evidence.

## Respond to a broad GitHub API outage

If requests fail across installations:

1. Keep checks fail closed. If retries threaten GitHub or PostgreSQL, roll a
   controlled configuration with
   `EXTRA_CODEOWNERS_WORKER_ENABLED=false` and
   `EXTRA_CODEOWNERS_RECONCILE_ENABLED=false` on ingress instances.
   Continue durable webhook acceptance if the database can support it.
2. Check GitHub's published status and the service's rate-limit responses.
3. Confirm that GitHub has not suspended the App and that the private key is
   still active.
4. Keep ingress available only while it can store work without exhausting
   capacity. The invalidation fast path may be deferred while mapped triggers
   still receive `202`.
5. Resume workers gradually. Watch queue depth, repeated failures, API error
   rate, and recovery time.
6. Restore both background tasks after recovery. Pruning is paused while the
   reconciler is disabled.

If the outage exceeds the merge-availability objective, restore native human
code-owner enforcement before removing the Extra CODEOWNERS required check.

## Rotate credentials

### Rotate the App private key

Confirm first that the platform can reference a new secret version without
printing it.

1. Generate a second private key in the GitHub App settings.
2. Store it as a new secret-manager version.
3. Roll one test instance with the new key. Verify readiness and a test
   installation API call.
4. Roll the remaining instances.
5. Verify a current-head evaluation and Check Run.
6. Delete the old key in GitHub.
7. Confirm that no instance reports authentication errors from an old mount.

Keep the old key until a new-key instance passes verification, unless the old
key is compromised.

### Rotate the webhook secret

GitHub signs with one webhook secret, so there is no overlap window:

1. Stop or drain public webhook ingress while workers finish queued work.
2. In one maintenance window, update the secret in GitHub and the secret
   manager.
3. Roll every ingress instance.
4. Restore ingress and send a GitHub test delivery.
5. Confirm that invalid-signature counts remain stable after the test.
6. Run reconciliation so events from the transition cannot leave open pull
   requests stale.

If a later version accepts two secrets, replace this procedure with an overlap
and retirement plan documented for that version.

### Rotate the PostgreSQL credential

Use overlapping credentials when the provider supports them:

1. Create a replacement with the same narrow database privileges. Preserve
   `sslmode=verify-full` for a remote route, or the reviewed local proxy
   path.
2. Store the URL as a new secret version without printing it.
3. Roll one instance. Verify readiness, queue access, and a disposable
   evaluation.
4. Roll the remaining instances and confirm none uses the old version.
5. Let old pools drain, then revoke the old credential.

If the provider cannot overlap credentials, drain ingress, finish active work,
rotate the credential, and roll every instance in a maintenance window.
Restore traffic only after readiness and a disposable evaluation succeed.

Never put a database password on a command line or in a support transcript.

## Change repository access safely

### Remove or add selected repositories

Before deselecting an ordinary target:

1. Restore native **Require review from Code Owners** and verify it.
2. Remove the Extra CODEOWNERS required check.
3. Deselect the repository last.

A well-formed `installation_repositories.removed` event containing only
ordinary targets is acknowledged without work. By delivery time, the App can
no longer update those repositories.

Removing the organization-policy repository affects the whole installation.
Restore native enforcement and remove the Extra CODEOWNERS requirement on
every target first. The service treats removal or malformed removal evidence
as conservative policy-source loss, advances the installation authority epoch,
and fans out blocking work to repositories it can still reach. That defense is
not a migration procedure.

Adding repositories schedules installation-wide fan-out. Keep native
enforcement until:

- the App can access both the policy source and target
- installation and authority queues have drained
- current checks are correct
- every positive and negative repository-rule test passes.

### Rename, transfer, archive, or unarchive

Repository rename, transfer, installation-owner rename, and unarchive events
schedule installation-wide reevaluation and advance an authority epoch. Each
queued evaluation carries the epoch from enqueue time, so work under the old
identity cannot publish after the change.

The worker also compares a delayed webhook's repository route with GitHub's
current base repository name. A mismatch logs
`stale_repository_alias_discarded` and stops before policy reads or Check
Run writes.

For a rename or unarchive that preserves App access:

1. Verify ingress, workers, successful reconciliation, and a normal queue
   baseline before the change.
2. Keep merges blocked by existing repository rules during the change.
3. Confirm that GitHub delivered the matching `repository` or
   `installation_target` event. Redeliver a failed delivery.
4. Wait for installation and repository authority work to drain. Confirm every
   open pull request has a current result under the new identity.
5. Repeat the negative tests in
   [Prepare repository rules](prepare-repository-rules.md#3-exercise-the-complete-rule)
   before allowing merges.

If `stale_repository_alias_discarded` continues beyond one reconciliation
interval, inspect delayed deliveries and canonical-name fan-out. The log
contains repository names, so keep it private.

Archived repositories are skipped during fan-out and reconciliation.
`repository.unarchived` schedules work directly, but the result is
eventually consistent. Don't merge until current-state evaluation and negative
tests finish.

If a transfer may leave the installation:

1. Restore and verify native code-owner enforcement.
2. Remove Extra CODEOWNERS as a required check.
3. Transfer the repository.
4. Install Extra CODEOWNERS on the destination policy source and target.
5. Revalidate enrollment, delegation, expected-source selection, and current
   checks.
6. Repeat every positive and negative rule test before disabling native
   code-owner review.

An authority fence cannot revoke a check after GitHub removes App access. If
access was lost too early, keep native enforcement. Don't edit queue tables or
assume GitHub revoked the earlier success.

## Test backup restoration

Follow [Upgrade, back up, and restore](upgrade.md). Reconciliation can rebuild
queue work, but delivery deduplication and audit evidence still help during an
incident.

To test a restore:

1. Restore into an isolated database.
2. Start an instance with public ingress and workers disabled.
3. Run `extra-codeowners database check` from the compatible artifact and
   inspect aggregate queue counts.
4. Enable a worker against a disposable installation only.
5. Confirm that restored jobs fetch current GitHub evidence instead of trusting
   stored hints.

Never run two restored production copies that can both publish checks for the
same App installation.

## Retire the service

!!! warning
    Retire merge authority before infrastructure. After the App loses access,
    it cannot revoke an earlier success. Do not assume GitHub will invalidate
    that result.

1. Restore native **Require review from Code Owners** on every affected
   repository. Verify it with a human-reviewed test pull request.
2. Remove the expected-source Extra CODEOWNERS required check only after the
   native rule applies.
3. Disable or remove repository policy.
4. Uninstall the checker App from target repositories and the
   organization-policy repository.
5. Stop the service. Revoke App private keys and the webhook secret, then
   remove runtime access to them.
6. Retain or destroy database backups and audit metadata under the approved
   incident, legal, and privacy policy.

If you delete the App or service first, a required check may block every merge.
If you remove the check first, code-owner enforcement disappears.

## Respond to insecure mode

Treat `extra_codeowners_insecure_changes_enabled` equal to `1` as an
incident unless an active, documented exception covers it. Find the deployment
configuration, restore the value to `false`, and roll every instance.
Let pending work and one complete reconciliation cycle reevaluate open pull
requests.

Review application-satisfied checks from the exposure window. Include
`CODEOWNERS`, Extra CODEOWNERS and Stampbot policy, workflows, and local
actions.

## Escalate an unresolved incident

Restore native code-owner enforcement before asking others to investigate an
authority failure. Keep the failing service from authorizing merges, preserve
sanitized evidence, and record the deployed source revision.

Report a suspected vulnerability through the project's
[private security process](https://github.com/stampbot/extra-codeowners/security/policy).
Use the
[support process](https://github.com/stampbot/extra-codeowners/blob/main/SUPPORT.md)
for other incidents, without attaching credentials, raw private payloads, or
repository contents.
