# Operate and recover Extra CODEOWNERS

Use this guide to monitor a deployment, respond to stale or failed checks, replay work safely, and rotate credentials. It assumes the preview architecture in the [deployment guide](deploy.md); operational interfaces may change before the first supported release.

## Normal operating state

Monitor these conditions:

- `/health/live` and `/health/ready` are successful for serving instances; on instances assigned background work, configuration enables the worker and reconciler and both response fields are `true`.
- `extra_codeowners_queue_depth` returns to its usual baseline after pull-request and authority-change webhook bursts.
- evaluation failure rate and latency remain within locally defined objectives.
- `extra_codeowners_webhook_failures_total` does not increase unexpectedly.
- sustained GitHub API `403` or `429` responses are investigated as permission, suspension, or rate-limit failures.
- `extra_codeowners_reconciliations_total{result="failure"}` does not increase unexpectedly, and `extra_codeowners_reconciliation_last_success_timestamp_seconds` remains within the locally defined reconciliation objective.
- service-node clocks remain synchronized; significant skew can break GitHub authentication and lease timing.
- `webhook_deliveries_pruned` logs appear when expired IDs exist, and the delivery table does not grow unexpectedly.
- `extra_codeowners_insecure_changes_enabled` remains `0` unless an approved exception is active.
- `extra_codeowners_dead_jobs` remains `0`; a nonzero value indicates a legacy or manually introduced terminal row, not ordinary runtime exhaustion.
- an `in_progress` check is paired with active or pending work and does not remain unexplained beyond the retry objective.

An idle open pull request is reevaluated on each reconciliation interval, so its check briefly returns to `in_progress` even when no webhook was missed. Size the interval against acceptable stale-evidence exposure, GitHub API budget, evaluation latency, and this short merge-availability interruption.

Mapped accepted-webhook logs include the delivery ID, event, action, available repository or pull-request context, and whether work was queued. Ignored-event logs omit repository and pull-request fields because no work is retained. Evaluation failures carry safe pull-request and last-delivery correlation fields; authority fan-out failures carry installation, scope, and reason. The latest evaluation audit records its trigger reason and delivery ID when a direct delivery supplied one. Treat logs and audits as private repository metadata and restrict their retention and access. They must not contain installation tokens, private keys, secrets, authorization headers, full private payloads, or file contents.

The preview does not yet expose remaining GitHub rate-limit quota. Monitor GitHub API failures and keep the service limited to disposable repositories unless deployment-specific rate-limit detection closes that gap.

## Manage delivery and audit retention

The elected reconciler removes webhook delivery IDs older than `EXTRA_CODEOWNERS_WEBHOOK_DELIVERY_RETENTION_DAYS` on each run. The default is 30 days. Keep the configured interval long enough to cover GitHub redelivery and your incident-investigation window, but no longer than justified for private repository metadata.

After an ID expires, a redelivery with that ID can be accepted again. It does not replay stored authorization evidence: the unique pull-request job is created or coalesced, and the worker fetches current GitHub state before deciding. If reconciliation is disabled, automatic delivery-ID pruning is also disabled.

The preview retains only the latest evaluation audit for each pull request and does not automatically delete those audit rows. Establish database-level retention only after reviewing incident, privacy, and recovery needs; direct database changes are otherwise unsupported. Back up before any approved retention operation.

## Diagnose a missing or stale check

### 1. Confirm the policy is meant to run

Check that repository policy exists at the deployment's effective `EXTRA_CODEOWNERS_POLICY_PATH` (default `.github/extra-codeowners.toml`) on the pull request's base commit and has `enabled = true`. Confirm the App installation includes both the target repository and the configured organization-policy repository (default `.github`).

### 2. Inspect GitHub delivery state

In the GitHub App's **Advanced** settings, locate the relevant webhook delivery. Record the delivery ID and event type without copying the full payload into an issue.

- If GitHub never attempted delivery, verify the App's event subscription and repository selection.
- If the delivery received a non-successful HTTP response, inspect ingress and service logs for the same delivery ID.
- If GitHub shows a network failure, verify DNS, TLS, ingress routing, and readiness.
- If a mapped pull-request, review, rerequest, push, label, member, membership, team, team-add, organization, installation, installation-target, repository, or repository-selection delivery succeeded, continue to durable queue checks. Ignored actions and pull-request events for the organization-policy repository are acknowledged without durable work. A relevant organization-policy push or lifecycle event, removal of that repository from App selection, or malformed removal evidence is retained for installation-wide fan-out; a well-formed removal containing only ordinary targets is acknowledged without work because access is already gone.

The `webhook_durable_acceptance_failed` log means ingress could not confirm durable acceptance. Causes include a database failure and a timeout waiting to order an authority event against an in-flight Check Run. PostgreSQL connections, application-pool checkout, and ordinary statements have fixed preview timeouts of 3, 2, and 3 seconds respectively; advisory-lock waits use their operation-specific guard budget. Correlate the failure with provider latency, proxy health, pool exhaustion, and lock contention. Correct the dependency or worker problem, then manually redeliver the failed GitHub delivery; GitHub does not retry it automatically.

### 3. Inspect the service

Confirm readiness, database connectivity, worker and reconciler health, the reconciliation result and last-success metrics, aggregate queue depth, repeated failure logs, and GitHub API errors. A pending queue that grows or remains above its baseline beyond the retry objective indicates a dependency, worker, or database problem. Broad authority work is claimed ahead of base pushes; repository-wide work replaces older base-specific rows, and more than 100 distinct base refs for one repository collapse into one repository-wide job. A stale reconciliation timestamp or rising reconciliation-failure counter indicates that the missed-event recovery path is unavailable even when the task remains alive. Repeated API failures may indicate revoked permissions, a suspended installation, rate limiting, or an invalid private key.

For a mapped pull-request, review, or check-rerequest webhook, ingress durably records the event and makes a bounded attempt to create or update the managed check as `in_progress`. A repository with no policy and no prior managed check is deliberately skipped. A fast-path timeout or GitHub API exception is logged as `webhook_check_invalidation_deferred`, increments the webhook-failure counter with reason `invalidation_fast_path`, and still returns `202`; inspect those signals because stale success may remain until the worker reaches GitHub. The worker keeps the current-head check `in_progress` before collecting mutable approval evidence. An exception after that point, a superseding trigger, or unresolved relevant authority fan-out therefore remains blocking. Evaluation and authority exceptions remain pending and retry indefinitely with exponential backoff capped by `EXTRA_CODEOWNERS_WORKER_RETRY_MAX_SECONDS`; rate-limit responses use GitHub's separately bounded `Retry-After`. A long-lived `in_progress` check with repeated failure logs requires dependency or permission remediation, not a manufactured result.

From a checkout or installed container configured with the same database URL, inspect aggregate queue state:

```bash
uv run python -m extra_codeowners queue-status
```

The command prints only `pending=N dead=N`. Counts combine pull-request evaluation and authority fan-out jobs. Normal failures remain pending, so `dead` should be `0`. Database initialization automatically reactivates terminal rows created by an earlier pre-release build; a remaining nonzero value indicates incompatible or manually introduced state and requires investigation.

### 4. Recover without manufacturing success

Use GitHub's **Redeliver** control only for a delivery that GitHub shows as unaccepted after the service is healthy. GitHub does not redeliver failures automatically. For an already accepted direct pull-request trigger whose bounded invalidation fast path was deferred, a duplicate can resume the pending invalidation attempt; otherwise delivery deduplication leaves committed work in place. If no pull-request job exists, scheduled reconciliation creates one.

Correct the underlying dependency, credential, permission, or policy problem and let pending work retry automatically. Do not reset attempts to accelerate a retry storm: ordinary exponential delay is capped by `EXTRA_CODEOWNERS_WORKER_RETRY_MAX_SECONDS`, while GitHub rate limits use the provider's delay. The check remains `in_progress` until the newest database generation safely publishes a completed result. The `requeue-dead` command is retained only for legacy or manually introduced terminal rows and is not part of normal recovery.

Never create a success check manually or edit the database to mark work complete.

### 5. Verify current state

Confirm the check on the exact current head was published by the expected App and its summary reflects current labels, approvals, paths, and owner sets. A successful check on an older commit is not recovery.

## Respond to broad GitHub API failure

When GitHub requests fail across installations:

1. Preserve fail-closed behavior. If a retry storm threatens GitHub or the database, use a controlled configuration rollout to set `EXTRA_CODEOWNERS_WORKER_ENABLED=false` and `EXTRA_CODEOWNERS_RECONCILE_ENABLED=false` on ingress instances while keeping durable webhook storage available. This pauses automatic delivery-ID pruning as well as reconciliation; do not leave the deployment in this state after recovery.
2. Check GitHub's published status and the service's rate-limit responses.
3. Verify the App has not been suspended and its private key remains active.
4. Keep webhook ingress available if it can durably store work without exhausting storage. The invalidation fast path may be deferred while mapped triggers continue to return `202`; durable workers keep retrying current evidence according to queue policy.
5. Resume workers gradually and watch pending queue depth, repeated failure logs, recovery time, and API error rate.

If the outage exceeds the repository's merge-availability objective, restore native human code-owner enforcement before removing the Extra CODEOWNERS check requirement. This preserves human review while temporarily disabling application delegation.

## Rotate the GitHub App private key

Before starting, verify that the deployment can reference a new secret version without printing its contents.

1. Generate a second private key in the GitHub App settings.
2. Store it as a new version in the secret manager.
3. Roll one test instance with the new key and verify readiness and a test installation API call.
4. Roll the remaining instances.
5. Verify a current-head evaluation and Check Run.
6. Delete the old private key in GitHub.
7. Confirm no instance continues to report authentication errors from stale secret mounts.

Do not delete the old key before at least one new-key instance passes verification unless the old key is known to be compromised.

## Rotate the webhook secret

GitHub App webhook-secret rotation has a coordination window because GitHub sends one signature. Schedule a brief controlled transition:

1. Stop or drain public webhook ingress while allowing workers to finish queued work.
2. Update the secret in GitHub and the secret manager within the same maintenance window.
3. Roll all ingress instances with the new secret.
4. Restore ingress and send a GitHub test delivery.
5. Verify invalid-signature counts remain stable after the test.
6. Run reconciliation so events during the transition cannot leave open pull requests stale.

If the platform later supports two simultaneous webhook secrets, replace this procedure with overlap-and-retire rotation and document the exact version that introduced it.

## Rotate the database credential

Use the PostgreSQL provider's tested overlap procedure so old and new credentials can coexist briefly:

1. Create a replacement credential with the same narrowly scoped database privileges and `sslmode=verify-full` for remote transport, or the same reviewed loopback or Unix-socket proxy path.
2. Store it as a new secret version without printing the database URL.
3. Roll one instance with the new URL and verify readiness, queue access, and a disposable evaluation.
4. Roll every remaining ingress and worker instance, then confirm no process uses the old secret version.
5. Revoke the old credential only after old connection pools have drained.

If the provider cannot overlap credentials, schedule a controlled maintenance window: drain public ingress, let active workers finish, rotate the credential, roll all instances, and restore traffic only after readiness and a disposable evaluation succeed. Do not put a database password on a command line or in a support transcript.

## Change selected repositories safely

A well-formed `installation_repositories.removed` event containing only ordinary targets is acknowledged without work: by the time it arrives, the App cannot update those repositories. Before deselecting an ordinary target, restore native **Require review from Code Owners**, verify it, and only then remove the Extra CODEOWNERS required check. Deselect the repository last.

Removing the configured organization-policy repository is installation-wide. The service treats that event—and malformed repository-removal evidence—as a conservative policy-source loss: it advances the installation authority epoch and fans out blocking reevaluation to targets that remain accessible. This is an asynchronous defense, not a safe migration procedure. Before deselecting the policy repository, restore and verify native enforcement on every target, then remove the Extra CODEOWNERS requirement from those targets.

Adding repositories back schedules installation-wide fan-out. Keep native enforcement in place until the policy source and target are both selected, authority work has drained, current checks are correct, and the positive and negative repository-rule tests pass.

## Rename, transfer, archive, or unarchive a repository

Repository rename, transfer, installation-owner rename, and unarchive events directly schedule installation-wide reevaluation. Their acceptance advances a persistent installation authority epoch before fan-out. Because every evaluation row stores the epoch from enqueue time, old-name work cannot publish even if it is first claimed after the event. A delayed old-name webhook received after that bump is also rejected when the worker compares its route with GitHub's authoritative base repository full name, before any check or policy lookup. Fan-out discovers repositories under their current names, and Check Run writes are serialized by installation and head.

For a rename or unarchive that preserves the App installation's access:

1. Verify webhook readiness, worker health, successful reconciliation, and a normal queue baseline before the change.
2. Perform the lifecycle change while merges remain blocked by the repository's existing pull-request rules.
3. Confirm GitHub delivered the corresponding `repository` or `installation_target` event and the service accepted it. Manually redeliver any failed delivery.
4. Wait for installation and repository authority queues to drain, then verify every open pull request has a current result under the current repository identity.
5. Repeat the negative tests in [Prepare repository rules](prepare-repository-rules.md#3-verify-the-conjunction) before allowing merges.

The `stale_repository_alias_discarded` log is expected for delayed deliveries that still use the old route. It means the worker stopped before reading policy or writing a check. Repeated occurrences beyond a complete reconciliation interval warrant checking webhook redeliveries and canonical-name fan-out; the log contains repository names and remains private metadata.

Archived repositories are excluded from fan-out and reconciliation while they cannot merge. `repository.unarchived` is a direct trigger, but the Check Runs update remains eventually consistent; do not permit a merge until its current-state evaluation and the negative tests finish.

A transfer can move the repository outside the current App installation. The epoch fence cannot revoke a check after GitHub removes that capability. Whenever destination access is not already assured, use the access-removal sequence instead:

1. Restore native **Require review from Code Owners** and verify it on the repository.
2. Remove Extra CODEOWNERS as a required check only after native enforcement applies.
3. Perform the transfer and install Extra CODEOWNERS on both the destination organization-policy repository and the target repository.
4. Revalidate organization enrollment, repository delegation, expected-source selection, and current checks.
5. Repeat all positive and negative repository-rule tests before disabling native code-owner review again.

If the App lost access before that sequence completed, keep native enforcement in place. Do not edit queue tables to force completion or assume GitHub revoked an earlier success.

## Back up and restore durable state

Back up PostgreSQL using the operator's tested database procedure. The queue can be reconstructed by reconciliation, but delivery deduplication and audit evidence are useful during incidents.

For a restore test:

1. Restore into an isolated database.
2. Start an instance with workers and public ingress disabled.
3. Verify schema readability and inspect queue counts without exposing repository data.
4. Enable a worker against a disposable installation only.
5. Confirm stale jobs re-fetch current GitHub evidence rather than trusting stored hints.

Never point two independent production deployments at restored copies while both can publish checks for the same App installation.

## Retire a deployment

Retire merge authority before infrastructure. Do not remove repository access, suspend an installation, or uninstall the App until the first two steps are verified: after access is gone, Extra CODEOWNERS cannot revoke an earlier success, and operators must not assume GitHub invalidates it.

1. Restore GitHub's native **Require review from Code Owners** rule on every affected repository and verify it with a human-reviewed test pull request.
2. Remove the expected-source Extra CODEOWNERS required check only after the native rule applies.
3. Set repository policies to `enabled = false` or remove them.
4. Uninstall the checker App from target repositories and the organization-policy repository.
5. Stop the service, revoke every App private key and webhook secret, and remove runtime secret access.
6. Retain or destroy database backups and audit metadata according to the approved incident, legal, and privacy policy.

Do not delete the App or service first: a still-required check with no publisher blocks merges, while removing the check first silently removes code-owner enforcement.

## Insecure-mode alert

An `extra_codeowners_insecure_changes_enabled` value of `1` without an active, documented exception is an incident. Identify the deployment configuration source, set the value back to `false`, roll all instances, and allow pending work plus a full reconciliation cycle to reevaluate open pull requests. Review application-satisfied checks for built-in ownership, Extra CODEOWNERS and Stampbot policy, workflow, and local-action paths during the exposure window.
