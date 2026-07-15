# Operate and recover Extra CODEOWNERS

Monitor a deployment, diagnose stale checks, replay work safely, and rotate credentials with this guide. Use the guide from the deployed commit: no compatibility guarantee covers its operational interfaces before the first supported release. The architecture is defined in the [deployment guide](deploy.md).

## Normal operating state

Watch these conditions:

- `/health/live` and `/health/ready` succeed for serving instances. If an instance runs background work, enable both the worker and reconciler and confirm that both response fields are `true`.
- `extra_codeowners_queue_depth` returns to its usual baseline after bursts of pull-request or authority-change webhooks.
- Evaluation failures and latency stay within your objectives.
- `extra_codeowners_webhook_failures_total` doesn't rise unexpectedly.
- Sustained GitHub API `403` or `429` responses trigger an investigation into permissions, suspension, or rate limits.
- `extra_codeowners_reconciliations_total{result="failure"}` doesn't rise unexpectedly, and `extra_codeowners_reconciliation_last_success_timestamp_seconds` stays within your reconciliation objective.
- Every service node keeps an accurate clock. Significant skew can break GitHub authentication and lease timing.
- `webhook_deliveries_pruned` logs appear when expired IDs exist, and the delivery table doesn't grow unexpectedly.
- `extra_codeowners_insecure_changes_enabled` stays `0` unless an approved exception is active.
- `extra_codeowners_dead_jobs` stays `0`. A nonzero value means a legacy or manually introduced terminal row exists; normal runtime exhaustion doesn't create one.
- Every `in_progress` check has active or pending work and doesn't remain unexplained beyond the retry objective.

Reconciliation reevaluates every idle open pull request. Its check briefly returns to `in_progress`, even when no webhook was missed. Choose an interval that balances stale-evidence exposure, GitHub API usage, evaluation latency, and this short interruption to merge availability.

Accepted-webhook logs include the delivery ID, event, action, available repository or pull-request context, and whether the service queued work. Ignored-event logs omit repository and pull-request fields because they retain no work. Evaluation failures carry safe pull-request and last-delivery correlation fields. Authority fan-out failures carry the installation, scope, and reason. When a direct delivery triggered the latest evaluation, its audit records the trigger reason and delivery ID.

Treat logs and audits as private repository metadata. Restrict their retention and access. They must never contain installation tokens, private keys, secrets, authorization headers, full private payloads, or file contents.

The service doesn't expose remaining GitHub rate-limit quota. Monitor API failures and limit the service to disposable repositories unless deployment-specific rate-limit detection closes that gap.

## Manage delivery and audit retention

Set `EXTRA_CODEOWNERS_WEBHOOK_DELIVERY_RETENTION_DAYS` long enough to cover GitHub redelivery and your incident-investigation window. Don't retain private repository metadata longer than you can justify. The default is 30 days.

On each run, the elected reconciler removes older webhook delivery IDs. If you disable reconciliation, you also disable automatic pruning.

After an ID expires, GitHub can redeliver and the service can accept it again. This doesn't replay stored authorization evidence. The unique pull-request job is created or coalesced, and the worker fetches current GitHub state before deciding.

The service keeps only the latest evaluation audit for each pull request, but doesn't delete those audit rows automatically. If you need database-level retention, review incident, privacy, and recovery needs first. Back up the database before an approved retention operation; other direct database changes are unsupported.

## Diagnose a missing or stale check

### 1. Confirm the policy is meant to run

On the pull request's exact base commit, confirm that repository policy exists at the effective `EXTRA_CODEOWNERS_POLICY_PATH`. The default is `.github/extra-codeowners.toml`. Verify that it sets `enabled = true`.

Confirm that the App installation includes the target repository and the organization-policy repository, which defaults to `.github`.

### 2. Inspect GitHub delivery state

In the GitHub App's **Advanced** settings, find the relevant webhook delivery. Record its delivery ID and event type without copying the full payload into an issue.

- If GitHub never attempted delivery, verify the App's event subscription and repository selection.
- If delivery received a non-successful HTTP response, find the same delivery ID in ingress and service logs.
- If GitHub reports a network failure, verify DNS, TLS, ingress routing, and readiness.
- If a mapped delivery succeeded, continue to the durable queue. Mapped deliveries include pull-request, review, rerequest, push, label, member, membership, team, team-add, organization, installation, installation-target, repository, and repository-selection events.

The service acknowledges ignored actions and pull-request events for the organization-policy repository without storing durable work. It retains a relevant push or lifecycle event for that repository and fans it out across the installation. It does the same when the policy repository is removed from App selection or when removal evidence is malformed. A well-formed removal containing only ordinary target repositories is acknowledged without work because access is already gone.

If you find `webhook_durable_acceptance_failed`, ingress couldn't confirm durable acceptance. A database failure can cause this. So can a timeout while ordering an authority event against an in-flight Check Run.

The service uses fixed timeouts of 3 seconds for a PostgreSQL connection, 2 seconds for application-pool checkout, and 3 seconds for an ordinary statement. Advisory-lock waits use a separate budget for their operation. Correlate the failure with provider latency, proxy health, pool exhaustion, and lock contention. After fixing the dependency or worker problem, manually redeliver the failed GitHub delivery; GitHub won't retry it automatically.

### 3. Inspect the service

Check readiness, database connectivity, worker and reconciler health, reconciliation results, the last-success metric, aggregate queue depth, repeated failures, and GitHub API errors.

If the pending queue grows or stays above its baseline past the retry objective, investigate a dependency, worker, or database problem. Broad authority work runs before base-push work. Repository-wide work replaces older base-specific rows. When one repository accumulates more than 100 distinct base refs, the service collapses them into one repository-wide job.

If the reconciliation timestamp is stale or its failure counter rises, missed-event recovery is unavailable even when the task itself remains alive. Repeated API failures can mean revoked permissions, a suspended installation, rate limiting, or an invalid private key.

For a mapped pull-request, review, or check-rerequest webhook, ingress stores the event durably. It then makes a bounded attempt to create or update the managed check as `in_progress`. If a repository has neither policy nor a previous managed check, the service skips it deliberately.

If that fast path times out or the GitHub API raises an exception, the service logs `webhook_check_invalidation_deferred` and increments the webhook-failure counter with reason `invalidation_fast_path`. It still returns `202`. Investigate these signals: stale success can remain visible until the worker reaches GitHub.

Before reading mutable approval evidence, the worker keeps the current-head check `in_progress`. An exception after that point, a newer trigger, or unresolved authority fan-out therefore stays blocking. Evaluation and authority failures remain pending and retry forever. Exponential backoff stops growing at `EXTRA_CODEOWNERS_WORKER_RETRY_MAX_SECONDS`; GitHub rate limits use a separate bounded `Retry-After`. A long-lived `in_progress` check with repeated failures needs a dependency or permission fix, not a manufactured result.

From a checkout or installed container configured with the same database URL, inspect aggregate queue state:

```bash
uv run python -m extra_codeowners queue-status
```

The command prints only `pending=N dead=N`. These counts combine pull-request evaluations and authority fan-out jobs. Normal failures stay pending, so `dead` should be `0`. The `0002_retry_dead_jobs` migration reactivates terminal rows left by an earlier pre-release retry contract. If a terminal row appears afterward, treat it as incompatible or manually introduced state and investigate it.

### 4. Recover without manufacturing success

If GitHub shows that it didn't accept a delivery, wait until the service is healthy and use **Redeliver**. GitHub doesn't redeliver failures automatically.

If an accepted direct pull-request trigger deferred its bounded invalidation fast path, a duplicate delivery can resume that pending attempt. Otherwise, delivery deduplication leaves committed work in place. If no pull-request job exists, scheduled reconciliation creates one.

Fix the dependency, credential, permission, or policy problem and let pending work retry. Don't reset attempts to accelerate a retry storm. Ordinary exponential delay is capped by `EXTRA_CODEOWNERS_WORKER_RETRY_MAX_SECONDS`, while rate-limit responses follow GitHub's delay. The check stays `in_progress` until the newest database generation can safely publish a result.

Use `requeue-dead` only for a legacy or manually introduced terminal row. It isn't part of normal recovery.

Never publish a success manually or edit the database to mark work complete.

### 5. Verify current state

On the exact current head, confirm that the expected App published the check. Verify that its summary reflects the current labels, approvals, paths, and owner sets. A successful check on an older commit doesn't prove recovery.

## Respond to broad GitHub API failure

If GitHub requests fail across installations:

1. Preserve fail-closed behavior. If a retry storm threatens GitHub or the database, roll a controlled configuration that sets `EXTRA_CODEOWNERS_WORKER_ENABLED=false` and `EXTRA_CODEOWNERS_RECONCILE_ENABLED=false` on ingress instances. Keep durable webhook storage available. This also pauses automatic delivery-ID pruning; restore both tasks after recovery.
2. Check GitHub's published status and the service's rate-limit responses.
3. Confirm that GitHub hasn't suspended the App and that its private key remains active.
4. Keep webhook ingress available if it can store work durably without exhausting storage. The invalidation fast path may be deferred while mapped triggers still return `202`; durable workers continue to retry current evidence under queue policy.
5. Resume workers gradually. Watch pending queue depth, repeated failures, recovery time, and API error rate.

If the outage outlasts the repository's merge-availability objective, restore native human code-owner enforcement before removing the Extra CODEOWNERS check. This preserves human review while App delegation is unavailable.

## Rotate the GitHub App private key

Before rotation, confirm that the deployment can reference a new secret version without printing it.

1. Generate a second private key in the GitHub App settings.
2. Store it as a new secret-manager version.
3. Roll one test instance with the new key, then verify readiness and a test installation API call.
4. Roll the remaining instances.
5. Verify a current-head evaluation and Check Run.
6. Delete the old private key in GitHub.
7. Confirm that no instance reports authentication errors from stale secret mounts.

Don't delete the old key until at least one new-key instance passes verification, unless you know the old key is compromised.

## Rotate the webhook secret

GitHub signs each webhook with one secret, so this rotation has no overlap window. Schedule a short controlled transition:

1. Stop or drain public webhook ingress while workers finish queued work.
2. During the same maintenance window, update the secret in GitHub and in the secret manager.
3. Roll every ingress instance with the new secret.
4. Restore ingress and send a GitHub test delivery.
5. Confirm that invalid-signature counts stay stable after the test.
6. Run reconciliation so events from the transition can't leave open pull requests stale.

If the platform later supports two webhook secrets at once, replace this procedure with overlap and retirement. Document the exact version that adds that support.

## Rotate the database credential

If your PostgreSQL provider supports overlapping credentials, use its tested procedure:

1. Create a replacement credential with the same narrow database privileges. For remote transport, use `sslmode=verify-full`. For a reviewed loopback or Unix-socket proxy, use the same path as before.
2. Store it as a new secret version without printing the database URL.
3. Roll one instance with the new URL. Verify readiness, queue access, and a disposable evaluation.
4. Roll every remaining ingress and worker instance. Confirm that no process uses the old secret version.
5. After old connection pools drain, revoke the old credential.

If your provider can't overlap credentials, schedule a maintenance window. Drain public ingress, let active workers finish, rotate the credential, and roll all instances. Restore traffic only after readiness and a disposable evaluation succeed.

Never put a database password on a command line or in a support transcript.

## Change selected repositories safely

Before deselecting an ordinary target repository, restore native **Require review from Code Owners** and verify it. Then remove the Extra CODEOWNERS required check. Deselect the repository last.

The service acknowledges a well-formed `installation_repositories.removed` event that contains only ordinary targets without scheduling work. By the time it arrives, the App can no longer update those repositories.

Before deselecting the organization-policy repository, restore and verify native enforcement on every target. Then remove the Extra CODEOWNERS requirement from those targets. Removing the policy repository affects the whole installation: the service treats its removal, or malformed removal evidence, as conservative policy-source loss. It advances the installation authority epoch and fans out blocking reevaluation to targets it can still access. That asynchronous defense isn't a safe migration procedure.

Adding repositories back schedules installation-wide fan-out. Keep native enforcement in place until all of these conditions hold:

- the App can access both the policy source and target
- installation-wide fan-out has completed
- authority work has drained
- current checks are correct
- the positive and negative repository-rule tests pass.

## Rename, transfer, archive, or unarchive a repository

Repository rename, transfer, installation-owner rename, and unarchive events schedule installation-wide reevaluation directly. Accepting one advances a persistent installation authority epoch before fan-out. Every evaluation row stores the epoch from enqueue time, so work under the old name can't publish even if a worker claims it after the event.

The worker also rejects a delayed old-name webhook after the epoch changes. It compares the webhook route with GitHub's authoritative base repository full name before reading policy or writing a check. Fan-out discovers current repository names, and the service serializes Check Run writes by installation and head.

If a rename or unarchive preserves App installation access:

1. Before the change, verify webhook readiness, worker health, successful reconciliation, and a normal queue baseline.
2. Keep merges blocked by the repository's existing pull-request rules while making the change.
3. Confirm that GitHub delivered the matching `repository` or `installation_target` event and that the service accepted it. Redeliver any failed delivery manually.
4. Wait for installation and repository authority queues to drain. Confirm that every open pull request has a current result under the current repository identity.
5. Before allowing merges, repeat the negative tests in [Prepare repository rules](prepare-repository-rules.md#3-verify-the-conjunction).

Expect `stale_repository_alias_discarded` when a delayed delivery still names the old route. It means the worker stopped before reading policy or writing a check. If it continues past a full reconciliation interval, inspect webhook redeliveries and canonical-name fan-out. The log includes repository names, so keep it as private metadata.

Archived repositories don't participate in fan-out or reconciliation while they can't merge. `repository.unarchived` triggers work directly, but the Check Runs update remains eventually consistent. Don't allow a merge until current-state evaluation and the negative tests finish.

If a transfer can move the repository beyond the current App installation's access, use this access-removal sequence:

1. Restore native **Require review from Code Owners** and verify it on the repository.
2. After native enforcement applies, remove Extra CODEOWNERS as a required check.
3. Transfer the repository. Install Extra CODEOWNERS on the destination organization-policy repository and the target repository.
4. Revalidate organization enrollment, repository delegation, expected-source selection, and current checks.
5. Before disabling native code-owner review again, repeat every positive and negative repository-rule test.

An epoch fence can't revoke a check after GitHub removes the App's access. If access was lost before you completed the sequence, keep native enforcement in place. Don't edit queue tables to force completion, and don't assume GitHub revoked an earlier success.

## Back up and restore durable state

Follow the [database backup and restore procedure](upgrade.md). Reconciliation
can reconstruct the queue, but delivery deduplication and audit evidence remain
useful during an incident.

To test a restore:

1. Restore into an isolated database.
2. Start an instance with public ingress and workers disabled.
3. Run `extra-codeowners database check` from the compatible application artifact. Inspect queue counts without exposing repository data.
4. Enable a worker against a disposable installation only.
5. Confirm that stale jobs fetch current GitHub evidence instead of trusting stored hints.

Never run two independent production deployments from restored copies while both can publish checks for the same App installation.

## Retire a deployment

!!! warning
    Retire merge authority before infrastructure. Once the App loses access, Extra CODEOWNERS can't revoke an earlier success. GitHub must not be assumed to invalidate it.

1. Restore GitHub's native **Require review from Code Owners** rule on every affected repository. Verify it with a human-reviewed test pull request.
2. After the native rule applies, remove the expected-source Extra CODEOWNERS required check.
3. Set repository policies to `enabled = false` or remove them.
4. Uninstall the checker App from target repositories and the organization-policy repository.
5. Stop the service. Revoke every App private key and webhook secret, and remove runtime access to secrets.
6. Retain or destroy database backups and audit metadata according to the approved incident, legal, and privacy policy.

Don't delete the App or service first. A required check with no publisher blocks merges, while removing the check first silently removes code-owner enforcement.

## Insecure-mode alert

Treat `extra_codeowners_insecure_changes_enabled` equal to `1` as an incident unless an active, documented exception covers it. Find the deployment configuration source and set the value back to `false`. Roll every instance, then let pending work and one full reconciliation cycle reevaluate open pull requests.

Review application-satisfied checks from the exposure window. Include built-in ownership paths, Extra CODEOWNERS and Stampbot policy, workflows, and local actions.
