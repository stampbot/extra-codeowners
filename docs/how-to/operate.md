# Operate and recover Extra CODEOWNERS

Use this runbook to monitor the service, investigate a stale check, rotate
credentials, and retire an installation without dropping code-owner
enforcement.

Operate from documentation that matches the deployed release. During the alpha
series, operational interfaces may change without a compatibility period. The
[deployment guide](deploy.md) describes the runtime and its current production
blockers.

## Know the healthy baseline

Record a normal value and alerting objective for each signal below. A fixed
threshold is less useful than a baseline because webhook volume varies with
pull-request activity.

| Signal | Healthy condition |
| --- | --- |
| Kubernetes startup probe | `/health/live` succeeds before the configured startup budget expires |
| `/api/runtime-identity` | Every field matches the reviewed deployment record |
| `/health/live` | HTTP 200 on every serving instance |
| `/health/ready` | HTTP 200, with recent exact-App authentication, database access, and configured background tasks ready |
| `extra_codeowners_queue_depth` | Returns to the local baseline after webhook bursts |
| `extra_codeowners_queue_work_class_oldest_age_seconds{kind="evaluation",work_class="interactive"}` | Stays below the direct-event objective; alert before a webhook can wait behind recovery work |
| `extra_codeowners_queue_work_class_depth{work_class="recovery"}` | Can rise during a burst, but must fall between reconciliation passes |
| `extra_codeowners_shared_head_invalidation_depth` | Returns to `0`; a sustained value means exact-commit revocations are waiting |
| `extra_codeowners_shared_head_invalidations_total{result="failed"}` | No unexplained increase |
| `extra_codeowners_dead_jobs` | `0` |
| `extra_codeowners_webhook_failures_total` | No unexplained increase |
| `extra_codeowners_github_api_request_seconds` | Its p95 stays near the provider and network baseline; compare it with worker-attempt time before raising worker concurrency |
| `extra_codeowners_github_rate_limit_events_total` | No sustained increase; a rate limit opens shared backpressure for the affected installation or the App |
| `extra_codeowners_github_physical_requests_total` | Compare `work_class="recovery"` with `interactive` and `authority` to identify who is spending API requests; includes retries and pages |
| `extra_codeowners_github_recovery_budget_deferrals_total` | Recovery pauses near its reserve; sustained growth means its workload exceeds the available quota |
| `extra_codeowners_reconciliations_total{result!="success"}` | No unexplained increase |
| `extra_codeowners_reconciliation_last_success_timestamp_seconds` | A complete run on at least one replica falls within the reconciliation objective |
| `extra_codeowners_trace_exports_total{outcome="failure"}` | `0`; otherwise traces cannot be used as incident evidence |
| `extra_codeowners_insecure_changes_enabled` | `0` unless an approved exception is active |

Also watch evaluation latency and failures, PostgreSQL latency, the durable
rate-limit circuit, repeated GitHub API `403` or `429` responses, and every
check that stays pending or shows a re-evaluation title for too long.

Queue gauges describe the shared database queue, so every replica reports the
same value. Aggregate those gauges with `max`, not `sum`. Evaluation counters
and histograms are local observations and should be aggregated normally across
replicas. Structured `evaluation_started` and `evaluation_completed` logs carry
the durable job ID, generation, repository, pull number, head, work class, and
delivery ID when one exists; use those fields to follow one delayed check
without turning pull requests into Prometheus labels.

## Trace a slow check

Metrics establish which stage is slow; a sampled trace explains the work in
that stage. Enable OTLP tracing only after choosing a telemetry backend with
access control and retention suitable for repository metadata. Keep private
metadata disabled for the normal baseline:

```yaml
extraEnv:
  - name: EXTRA_CODEOWNERS_TRACING_ENABLED
    value: "true"
  - name: EXTRA_CODEOWNERS_TRACING_OTLP_ENDPOINT
    value: http://opentelemetry-collector.observability.svc:4318/v1/traces
  - name: EXTRA_CODEOWNERS_TRACING_SAMPLE_RATIO
    value: "0.1"
  - name: EXTRA_CODEOWNERS_TRACING_INCLUDE_PRIVATE_METADATA
    value: "false"
```

The service creates root spans for webhook acceptance, reconciliation, and
each leased worker attempt. GitHub calls are child spans with a fixed operation
name such as `pull.get`, `content.get`, or `check.update`.

When a verified direct webhook is sampled, Extra CODEOWNERS stores its local
span identity with the retained delivery. The later evaluation starts its own
root span and links back to that webhook span. This still works when another
replica handles the job or the worker retries it, and GitHub's untrusted trace
headers never become a parent. In Tempo, open the linked webhook span from the
worker attempt to see when ingress accepted the work. Recovery work, expired
deliveries, and unsampled acceptance spans have no link; follow their durable
delivery ID in the logs instead.

A sampled span adds `trace_id` and `span_id` to structured logs emitted inside
it. The `webhook_accepted` record repeats the locally generated IDs after the
fast path finishes, so it remains useful when that path took several seconds.

For a short incident window, raise the sample ratio to `1`. Do not turn on
private metadata casually: it adds repositories, pull numbers, delivery IDs,
commit IDs, and API paths to Tempo. It still never exports secrets, request
bodies, authorization headers, or tokens.

Use this order when a check is late:

1. Check `queue_wait_seconds` and oldest interactive queue age. A high value means the job waited before evaluation.
2. Check `work_attempt_seconds`. If it is also high, open a sampled worker trace and follow its webhook link when it has one.
3. Compare the child GitHub spans and `github_api_request_seconds`. Slow API spans point to GitHub or the network; ordinary API spans point to policy work, a database guard, or a local resource limit.

Do not use a trace as the only source of truth. Sampling intentionally omits
some work, and a failed exporter does not affect the approval decision.

Read runtime identity through an operator-only route after every rollout.
Official images report their verified source commit in `build_revision`;
source installations report `null`. Treat the response as a consistency
check. It is an unauthenticated self-report, not proof of source or image
provenance.

A replica that observes another process holding the reconciler lease does not
record an attempt. Shutdown before a scan begins does not record one either.
When shutdown wins during election, the process releases any lease it just
acquired; a database error during acquisition or release is an election
failure. A partial attempt means the process lost its lease, an active scan was
interrupted by graceful shutdown, or the process could not safely scan an
installation or queue its pull requests. This includes GitHub request failures,
invalid GitHub responses, and database errors while adding queue jobs. Work
from healthy installations may still be queued, but a partial attempt does not
refresh the last-success gauge.

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

If an instance is meant to run background work, enable both tasks and confirm
that `worker_enabled`, `reconciler_enabled`, `worker`, and `reconciler` are
`true` in its health responses. The enabled fields report process
configuration; the other two report task health. Every node also needs an
accurate UTC clock. Clock skew can break GitHub authentication, setup-state
expiry, and database leases.

Readiness also requires a recent authenticated `GET /app` response whose
numeric ID matches the configured checker App. The service probes on a
30-second default interval and retains a successful proof for 90 seconds by
default. A transient failure leaves a still-fresh proof in place; readiness
drops after the freshness window and recovers after a successful probe.
Liveness remains independent so an App authentication outage does not create
a restart loop.

The Helm startup probe protects initialization from that ongoing liveness
policy. By default, Kubernetes calls `/health/live` every five seconds with a
three-second timeout and restarts the container after 60 failures. Liveness and
readiness don't begin until startup succeeds, so the defaults provide a
five-minute initialization budget.

Alert on repeated `Startup probe failed` events or restarts before the first
live response. Measure startup through the real database and secret mounts,
then keep `periodSeconds * failureThreshold` above the observed worst case plus
margin. Keep Helm and rollout wait timeouts higher still. Don't use a larger
startup budget to hide a persistent schema, credential, mount, or network
failure.

Each reconciliation scan works through accessible open pull requests. If GitHub
reports a new head, the database advances that head's shared generation and
queues recovery work in one transaction. If the head is unchanged, the service
queues it again only after `EXTRA_CODEOWNERS_RECONCILE_RECHECK_SECONDS` has
elapsed since the last successful evaluation. A current queue row stays put.

Installing the App on a repository does not opt it into evaluation. A PR with no repository policy and no managed check still costs API reads during recovery: the worker must check for enrollment and existing results. When no check exists, invalidation skips shared-commit discovery. An enrolled evaluation bound to an older head generation requeues itself at the current generation, so an unenrolled PR cannot cause its work to be discarded.

Recovery leaves 20% of each installation's observed REST core limit for direct
events and authority work by default. Set
`EXTRA_CODEOWNERS_GITHUB_RECOVERY_RESERVE_PERCENT` to adjust that tradeoff. A
larger reserve gives direct events more headroom but delays missed-webhook
recovery. All replicas charge the shared database budget before each request,
including retries and pagination. A deferred scan saves its last completed
repository and its progress within an unfinished repository. The next scan
finishes that repository first, even on a replica with an empty cache.

Each attempt fetches and validates every open-PR page before processing PRs in
number order. After a PR is queued or confirmed unenrolled, its number becomes
the durable resume point. The next attempt handles higher numbers; completion
clears that point so the next full pass checks all PRs again. A lower-numbered
PR that changes during a partial scan is therefore picked up on the next pass
if its webhook was missed. Incomplete pagination never advances PR progress.
Fresh membership that removes or archives the unfinished repository clears
its partial progress, as does a suspended installation. If access returns,
the next scan starts that repository from its first open PR.

The budget comes from GitHub's response headers, not a configured request
limit. When that evidence is missing or expired, recovery gets one probe per
minute across the installation until valid headers arrive. Direct events do
not wait for that probe. Known quota exhaustion and provider backpressure
still apply to every lane. Other consumers of the installation's quota can
spend the reserve; it is not a separate allocation from GitHub. GraphQL points,
App-authenticated discovery, and secondary limits are separate from this REST
core budget. See [GitHub's rate-limit documentation](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api).

The shared balance is conservative: a late response can lower it, but cannot
refund requests already charged by another replica. A nonzero response with a
later reset time does not extend the active accounting window. The original
deadline still expires, allowing a fresh probe to establish the next budget.
If GitHub explicitly reports zero remaining requests, its full reset deadline
is honored instead. Upgrades preserve existing stored deadlines; don't clear
budget rows to force recovery to resume sooner.

For each repository, reconciliation resolves each PR target branch with GitHub
and reads policy at its current commit, once per branch per scan. The base SHA
in a PR response can be older than the branch tip. When policy is missing,
the reconciler also asks GitHub whether the head has an existing managed check.
Only PRs with neither policy nor a managed check are omitted from the recovery
queue. Both observations are made
again on every scan, so missing a policy-change webhook cannot permanently
prevent enrollment. Disabled or unreadable policy still queues evaluation;
removing policy cannot hide a previously managed check.

Discovery pages, branch references, and empty check listings are cached only
within one process. The 32 MiB total budget is split: 24 MiB for pages and 8 MiB
for the smaller branch and check responses. Large PR listings cannot evict
entries from the smaller partition. Both remove entries idle for one hour;
the [metric reference](../reference/http-api.md#get-metrics) lists their entry limits.

Every entry still needs an authenticated conditional HTTP request before reuse.
A `304 Not Modified` saves the response body transfer, not the physical
request or its possible secondary-limit cost. Watch the GitHub request metric's
`outcome="not_modified"` series separately from local `budget_deferred`
counts. The cache is disposable and is not authority evidence.

Use `extra_codeowners_github_discovery_cache_lookups_total` to distinguish a
cold or churning cache from GitHub returning changed responses. A local hit
doesn't guarantee a `304`. Compare the byte and entry gauges with each
partition's limits, and keep pod identity when graphing them: replicas don't
share this cache. A newly elected replica may need a cold scan.

GitHub's ETags can change when an installation token changes, even if the
response body doesn't. This behavior has a
[published reproduction](https://github.com/orgs/community/discussions/75228).
Installation tokens [expire after one hour](https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app),
so a normal token refresh can turn a local cache hit into a full `200` response
that spends quota. Include token refreshes when measuring cache savings;
don't size the recovery budget from a token-stable sample alone.

`extra_codeowners_reconciliation_unenrolled_skips_total` counts PRs omitted
after those two absence checks; a rising count is expected in a mostly
unenrolled installation. Existing queued jobs still drain normally after an
upgrade; the optimization does not delete them.

An upgrade to `0007_reconciliation_completion` rechecks retained completions from older workers on the next scan, regardless of the recheck interval. Expect additional recovery work once after upgrading. Follow the [controlled upgrade procedure](upgrade.md); a rolling image replacement alone is not sufficient for this database change.

A reconciled check becomes blocking while the worker fetches current evidence.
Existing checks show `failure` with a re-evaluation title; newly created checks
can show `in_progress`. Choose an interval and recheck period that balance that
short merge interruption against stale-evidence exposure, GitHub API use, and
your recovery objective.

GitHub request spans include `queue.work_class`,
`github.quota.core_headers_valid`, and, when valid core headers are present,
`github.quota.limit`, `github.quota.remaining`, and `github.quota.reset_at`
(UTC epoch seconds). These are observations at response time, not live quota
gauges. Compare physical-request counts across lanes and operations before
raising concurrency. `reconciliation_deferred_for_recovery_budget` logs a local
reserve pause; `reconciliation_rate_limited` reports provider backpressure.
Neither means the scan completed. Check the oldest recovery work as well as
direct-event latency when deciding whether the installation is healthy.

## Re-evaluate a check

If a qualifying review has arrived but the Extra CODEOWNERS result has not
changed, open that check's details on the pull request and select
**Re-evaluate**. GitHub sends the action back to the installed App, which
queues a new evaluation for the current head commit. You do not need to push an
empty commit or create another review.

The action does not override policy or approve the pull request. It only asks
the service to fetch the current review, policy, and ownership evidence again.
The check first becomes blocking, then shows either the updated result or the
reason it still cannot pass. If it keeps a re-evaluation title or stays
`in_progress`, use the queue and invalidation metrics above to find the blocked
stage. An interim `failure` is not evidence that the worker has finished.

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

Read repository policy from the current tip of the PR's target branch. Confirm that
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

Exact-head invalidation has a direct-first lane and a recovery-first lane.
Each lane helps with the other class only when its own queue is empty. Authority
fan-out and pull-request evaluation have separate lanes, so a retrying fan-out
cannot starve unrelated pull requests. An evaluation with a relevant authority
fence still waits to publish. Installation-wide authority work splits into
repository fences. Repository-wide work replaces older base-specific rows, and
more than 100 distinct base refs for one repository collapse into a conservative
repository-wide job.

Before queuing follow-up work, authority discovery checks each PR for an existing
managed check and reads policy from the current target branch. If both are absent,
it skips the extra evaluation and invalidation jobs. The repository fence remains
durable during those reads, and existing queued jobs are left alone. A closed PR,
changed head, existing check, present policy, or failed lookup keeps the normal
recovery path; disabled and malformed policies are not treated as absent.

Within the authority lane, installation-wide fences still run first. After
that, a repository fence blocking a queued direct PR event takes priority over
unrelated background work. The fence must finish before the PR can publish;
priority does not bypass it. Each worker uses the older ordering for every
fourth claim so a stream of new PR events still leaves turns for background
fences. Claims remain database-coordinated across replicas.

For a mapped pull-request, review, or check-rerequest delivery, ingress stores
the trigger and then makes a bounded attempt to make the managed check blocking.
Existing checks receive an explicit `failure`. If a fast-path API call fails or times out, the service logs
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
current-head check blocking. It cannot publish a final result until the exact-head
generation finishes. A later trigger, an exception, or unresolved authority
fan-out therefore remains blocking. Invalidation, evaluation, and authority
failures retry forever. Ordinary exponential delay stops growing at
`EXTRA_CODEOWNERS_WORKER_RETRY_MAX_SECONDS`; GitHub rate limits use their
own bounded delay.

An error or cancellation during the completed write is a special case because
GitHub may have applied the result before the client lost its response. The
same uncertainty applies to a database error or cancellation during the
post-publication check. The worker attempts a shielded reset to a blocking result
while it still holds the head writer guard and then preserves the original
failure for retry. The
`completed_check_blocking_reset_failed` and
`completed_check_blocking_reset_cancelled` events mean the reset request itself
failed or ended cancelled. An ordinary evaluation cancellation that completes
the shielded reset emits neither event. A hard process stop or failed reset can
leave the completed result visible, so keep native enforcement in place and
verify that durable retry or a later trigger restores the blocking check.

A check that stays pending or keeps a re-evaluation title with repeated job
failures needs a database, network, credential, permission, or GitHub recovery.
It does not need a manufactured result.

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
   `sslmode=require` for a remote route, or the reviewed local proxy
   path.
2. Store the explicit `postgresql+psycopg` URL as a new secret version without
   printing it. Keep every ambient libpq connection variable out of the
   process environment.
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

A well-formed addition of one ordinary repository queues that repository.
Adding the organization-policy repository, multiple repositories, or ambiguous
addition evidence schedules installation-wide fan-out. Keep native enforcement
until:

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
