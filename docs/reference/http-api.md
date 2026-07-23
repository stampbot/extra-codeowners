# HTTP API reference

Extra CODEOWNERS exposes HTTP routes for GitHub and service operators. It is not a general-purpose public API. FastAPI publishes the current machine-readable schema at `/api/openapi.json`.

The interface is version `0.1`. Paths, payloads, and error envelopes may change incompatibly before `1.0`.

## Routes

The service registers these routes:

| Method | Path | Audience | Authentication and exposure |
| --- | --- | --- | --- |
| `GET` | `/` | Operator or discovery client | No application authentication. Returns the product name, version, and documentation URL. |
| `GET` | `/health/live` | Container orchestrator | No application authentication. Expose only on an operator-controlled health path. |
| `GET` | `/health/ready` | Container orchestrator | No application authentication. Expose only on an operator-controlled health path. |
| `GET` | `/metrics` | Prometheus-compatible scraper | No application authentication. Restrict at the network or proxy layer. |
| `GET` | `/api/docs` | Developer or operator | Swagger UI for routes included in the OpenAPI schema. Restrict outside development environments. |
| `GET` | `/api/openapi.json` | Documentation tooling | OpenAPI for the two health routes and the GitHub webhook route. Restrict outside development environments. |
| `GET` | `/docs/oauth2-redirect` | Swagger UI | FastAPI's OAuth redirect helper. Extra CODEOWNERS does not use end-user OAuth, but Swagger UI registers this route. |
| `POST` | `/webhooks/github` | GitHub webhook delivery | Verifies GitHub's HMAC-SHA256 signature over the raw request body. This is the only route that requires public HTTPS ingress. |
| `GET` | `/setup` | GitHub App administrator | Disabled by default. Returns the development App Manifest setup form when setup mode is configured. |
| `GET` | `/setup/callback` | GitHub App Manifest callback | Disabled by default. Validates short-lived state, exchanges GitHub's one-use code, and displays the returned credentials once. |
| `GET` | `/setup/complete` | GitHub App administrator | Disabled by default. Receives GitHub's post-installation or permission-update redirect. |

Public webhook ingress is not a reason to expose health, metrics, documentation, or setup routes. Route them separately or protect them with an authenticating reverse proxy. The application itself does not enforce a request-rate limit, so public ingress must provide suitable abuse controls.

## `GET /`

Success returns `200 application/json`:

```json
{
  "name": "Extra CODEOWNERS",
  "version": "0.1.0",
  "documentation": "https://extra-codeowners.readthedocs.io/"
}
```

`version` comes from the installed package and may differ from this example.

## `GET /health/live`

Liveness reports whether the process can serve requests and whether the worker and reconciler tasks expected in this process are still running. An orchestrator may restart the container after repeated `503` responses.

Success returns `200 application/json`:

```json
{
  "status": "alive",
  "worker": true,
  "reconciler": true
}
```

If an expected task has stopped, the response is `503`, `status` is `not_alive`, and the corresponding boolean is `false`. A disabled task reports `true`. A task also reports `true` when it is not expected because this process has no GitHub client.

Liveness does not test GitHub credentials, database access, queue progress, or successful reconciliation. It cannot observe a worker or reconciler running in another process. Use readiness and metrics for those conditions.

## `GET /health/ready`

Readiness reports whether this instance has GitHub credentials, a compatible database, and every locally enabled background task. A `503` response should remove the instance from webhook traffic without forcing a restart loop.

The response is `200` when ready and `503` otherwise:

```json
{
  "status": "ready",
  "github_credentials": true,
  "database": true,
  "worker": true,
  "reconciler": true
}
```

`status` becomes `not_ready` if credentials or the database are unavailable, or if an enabled local worker or reconciler task has stopped. A disabled worker or reconciler reports `true`. This endpoint cannot prove that a corresponding task in another process is healthy.

Readiness does not validate every installation or repository policy. Those conditions are evaluated per pull request.

## `GET /metrics`

The endpoint returns Prometheus text format. Extra CODEOWNERS defines these application metrics:

| Metric | Type | Meaning |
| --- | --- | --- |
| `extra_codeowners_webhooks_total` | counter | Verified GitHub deliveries, labeled by event and action. |
| `extra_codeowners_webhook_failures_total` | counter | Rejected or failed deliveries, labeled by reason. |
| `extra_codeowners_evaluations_total` | counter | Completed evaluations, labeled by conclusion. |
| `extra_codeowners_evaluation_seconds` | histogram | Evaluation latency. |
| `extra_codeowners_queue_depth` | gauge | Pending and leased exact-head invalidation, evaluation, and authority fan-out rows. |
| `extra_codeowners_shared_head_invalidation_depth` | gauge | Exact commit generations whose durable Check Run invalidation has not finished. |
| `extra_codeowners_shared_head_invalidations_total` | counter | Durable exact-head invalidation attempts, labeled by `completed`, `failed`, `rate_limited`, or `superseded`. |
| `extra_codeowners_dead_jobs` | gauge | Legacy or manually introduced terminal rows. Runtime failures remain pending, so this should remain `0`. |
| `extra_codeowners_insecure_changes_enabled` | gauge | `1` while built-in non-delegable paths are disabled; otherwise `0`. |
| `extra_codeowners_reconciliations_total` | counter | Reconciliation outcomes, labeled with `result="success"`, `result="partial"`, or `result="failure"`. A process that observes another lease owner does not increment the counter. An election error counts as a failure. |
| `extra_codeowners_reconciliation_last_success_timestamp_seconds` | gauge | Unix timestamp of the most recent complete reconciliation by this process. A partial or failed attempt does not update it. |

Prometheus also publishes generated counter and histogram series, plus Python runtime and process collectors. Metric labels must never contain repository names, pull-request titles, actor names, paths, or delivery IDs. Those values would create unbounded cardinality and disclose private repository metadata.

`success` means the elected process completed the scan of every visible,
unsuspended installation and validated every repository and open pull request
returned by GitHub. `partial` means the process lost its lease or could not
safely scan at least one installation or queue its pull requests. If graceful
shutdown interrupts an elected attempt, that attempt is also partial and does
not advance the last-success timestamp. An idle or unelected shutdown records
no attempt.

Per-installation failures include GitHub request errors, malformed payloads,
and database errors while adding queue jobs. Work queued before that failure
remains durable, and the scan continues with later installations while it
still owns the lease. `failure` means the attempt stopped before it could
return a scan result. This includes a malformed top-level installation list;
the service validates that whole list before processing any installation.

Reconciliation accepts installation IDs and pull-request numbers only as
positive JSON integers. It rejects booleans, strings, nulls, zero, and negative
values. `suspended_at` must be null or a timezone-aware ISO 8601 timestamp, and
`archived` must be a JSON boolean. Every open pull request must contain an
object-valued `head` with a full 40- or 64-character lowercase hexadecimal
commit ID. Field-level validation failures log a fixed reason code and omit the
rejected value. If GitHub returns something other than the expected list or
includes a non-object item, the client rejects it before field validation. The
service then logs a fixed reconciliation event and error template; it still
omits the rejected value.

The last-success gauge belongs to one service process. For a deployment with
several replicas, alert on the newest value across all replicas.

## `POST /webhooks/github`

GitHub sends a JSON body with these headers:

| Header | Constraint and purpose |
| --- | --- |
| `X-Hub-Signature-256` | Required `sha256=...` HMAC signature. The service compares it with a digest of the exact raw body and the configured webhook secret. |
| `X-GitHub-Event` | Required event name, at most 128 characters. It selects the scheduling handler. |
| `X-GitHub-Delivery` | Required delivery ID, at most 128 characters. Retained mapped events use it for replay-safe deduplication. |

The service verifies the signature before parsing JSON. The JSON root must be an object, and `action`, when present, must be a string. An authenticated mapped delivery is recorded in the same database transaction as its evaluation or authority fan-out work.

For a direct pull-request, review, or rerequest trigger, the signed payload must
identify the head as exactly 40 or 64 lowercase ASCII hexadecimal characters.
Ingress advances that head's shared generation and makes its exact-head
invalidation pending in the same transaction as the delivery and pull-request
job. The delivery stores that exact generation token. A malformed identifier
returns `400`; the service does not create a partial fence.

Ingress then makes one bounded attempt to fetch the current pull request. It
updates an existing managed check on the accepted head as `in_progress`. It
creates one only when that head is still current on an open pull request and
repository policy exists. A historical head with no managed check is skipped.
If the pull request already moved, ingress records separate durable work for
the live head.

Every newly accepted direct delivery attempts fast invalidation. A retained
duplicate retries that path only when an earlier invalidation remains pending;
the accepted head and its stored shared-generation token do not change. If the
retry discovers that the pull request now points to a different head, it
separately advances the live head's shared and evaluation generations and
queues that head for invalidation.

Full evaluation happens asynchronously. A `202` response for a mapped trigger means the service stored durable work, not that the pull request passed or that the fast-path Check Run update reached GitHub.

| `202` response field | Meaning |
| --- | --- |
| `accepted` | `true` if this request recorded the mapped delivery. An already retained delivery returns `false`. Unmapped deliveries return `true` because they are acknowledged but not retained. |
| `queued` | `true` when this request accepted new mapped work, its duplicate fast-path attempt reset a check, or that attempt separately queued a newly observed live head. This field is not a live queue-depth check. |

For example, a duplicate direct pull-request delivery may return
`{"accepted":false,"queued":true}` after resetting its accepted head or
discovering and queuing a newer live head. The retained delivery still refers
to its original head and generation. Other duplicate mapped deliveries leave
existing work unchanged. Once retention pruning removes a delivery ID,
redelivery can create or coalesce new work, but workers still fetch current
GitHub evidence.

An authenticated event or action with no mapping returns `{"accepted":true,"queued":false}`. It is neither retained nor deduplicated. Pull-request work for the configured organization-policy repository is handled this way because that repository stays under native human enforcement.

The following policy-source and repository-lifecycle events are retained as installation-wide fan-out work:

- a relevant organization-policy push to its default branch
- an organization-policy repository deletion, rename, transfer, or default-branch change
- a target-repository rename, transfer, or unarchive
- removal of the configured organization-policy repository from App selection
- missing or malformed `repositories_removed` evidence, which is treated as possible loss of the policy source.

A well-formed removal containing only ordinary target repositories is acknowledged without work because the App has already lost access.

### Webhook failure responses

Webhook failures use these status codes:

| Condition | Status | Result |
| --- | --- | --- |
| Missing or malformed `X-Hub-Signature-256`, or a signature mismatch | `401` | Reject before parsing JSON. |
| Missing or overlong delivery or event header; invalid `Content-Length`; malformed JSON; non-object JSON; invalid payload for a mapped event | `400` | Reject the request. |
| Body larger than 10 MiB | `413` | Reject whether or not `Content-Length` is present. The service enforces the limit while streaming; ingress should enforce the same limit. |
| No configured webhook secret | `503` | Reject because the receiver is not configured. |
| Retained direct trigger with no configured evaluator | `503` | Store the trigger, but report that synchronous check revocation is unavailable. |
| Database failure while accepting mapped work | `503` | Do not acknowledge successful ingestion. |
| Timeout or database failure while ordering an authority event against an in-flight Check Run | `503` | Do not record the delivery. Restore the service, then use GitHub's **Redeliver** control. GitHub does not retry automatically. |

After durable acceptance of a direct trigger, a GitHub API error or expiry of
`EXTRA_CODEOWNERS_WEBHOOK_INVALIDATION_TIMEOUT_SECONDS` leaves exact-head
invalidation pending and still returns `202`. The durable invalidation worker
resets an existing managed check and fans out evaluation to current open pull
requests on that commit. Manual redelivery can retry the fast path.

Authority acceptance uses the same timeout to wait for an in-flight final Check Run under the installation publication guard. Its transaction advances a persistent installation authority epoch and records fan-out. Every evaluation row records the epoch current when it was enqueued, so work from before the authority change cannot publish even after fan-out finishes.

The authority worker then:

1. Splits installation-wide work into repository fences when needed.
2. Lists affected open pull requests.
3. Supersedes each evaluation generation.
4. Makes a bounded attempt to invalidate each managed check.

Installation-wide and repository-wide work is claimed before base-specific push work. Repository-wide work removes older base-specific rows. A 101st distinct base ref for one installation and repository collapses those rows into one repository-wide job.

Exact-head invalidation, evaluation, and authority failures remain pending and
retry indefinitely with bounded ordinary backoff. GitHub rate limits use a
separately bounded provider delay. GitHub [requires webhook responses within 10
seconds and does not automatically redeliver failed
deliveries](https://docs.github.com/en/webhooks/using-webhooks/handling-failed-webhook-deliveries),
so synchronous work is bounded. A direct-trigger fast-path failure does not
undo durable acceptance; an authority-guard timeout prevents acceptance and
requires redelivery.

GitHub describes its signature contract in [Validating webhook deliveries](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries).

## App Manifest setup routes

Setup mode requires all three settings:

- `EXTRA_CODEOWNERS_SETUP_ENABLED=true`
- an HTTPS `EXTRA_CODEOWNERS_PUBLIC_URL` that contains only an origin
- `EXTRA_CODEOWNERS_SETUP_STATE_SECRET` containing at least 32 bytes.

When setup is disabled, all three setup routes return `404` and the other two settings are optional. When setup is enabled, missing or invalid setup settings prevent configuration from loading. The setup-state secret signs the short-lived setup exchange and is separate from the webhook secret.

### `GET /setup`

The optional `organization` query parameter selects where GitHub creates the App. With a value, the form targets that organization's App settings. Without it, the form targets the administrator's personal App settings.

The route returns `200 text/html`, or `404` when setup is disabled. Its response includes no-store, no-referrer, content-type, and restrictive content-security headers.

### `GET /setup/callback`

GitHub redirects the one-use `code` and signed `state` query parameters to this route. Both are required. The service validates the state's signature, audience, and expiry before exchanging the code, then displays the complete App Manifest conversion response with no-store headers.

The response contains the App ID and secret credential material:

- the private key
- the webhook secret
- any client secret returned by GitHub.

Callback outcomes use these status codes:

| Condition | Status |
| --- | --- |
| Successful exchange | `200 text/html` |
| Invalid or expired state, rejected exchange, or incomplete credential response | `400` |
| Missing `code` or `state` | `422` |
| Setup disabled, with both required query parameters present | `404` |

The service does not retain the returned credentials. Copy them directly into a secret manager before closing the page. The callback query and result must not appear in proxy access logs, screenshots, browser synchronization, support tickets, terminal transcripts, or logs.

### `GET /setup/complete`

GitHub redirects here after installation or a permission update. The route returns `200 text/html` with a configuration pointer while setup is enabled, and `404` otherwise. It also uses no-store response headers.

### Manifest defaults

The setup flow creates a private App with these permissions:

| Permission | Access |
| --- | --- |
| Checks | Write |
| Commit statuses (`statuses`) | Write |
| Contents | Read |
| Metadata | Read |
| Members | Read |
| Pull requests | Read |

Commit statuses makes the App selectable as an expected source in organization-level rulesets. Runtime installation tokens omit `statuses`. The [GitHub permissions reference](github-permissions.md#webhook-subscriptions) lists the explicit subscriptions and the automatically delivered installation events.

Keep setup mode disabled when operators do not register Apps through this service.

## Errors, retries, and compatibility

Clients must use HTTP status codes rather than matching response text. The JSON error envelope and OpenAPI compatibility policy may change before `1.0`; release notes will identify those changes.

Mapped webhook deliveries are idempotent while their delivery IDs remain in the deduplication table. The service does not offer client-controlled retries, pagination, or an HTTP version-negotiation header.
