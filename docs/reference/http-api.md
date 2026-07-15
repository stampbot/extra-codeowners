# HTTP API reference

Extra CODEOWNERS exposes an HTTP interface for GitHub and operators. It is not a general-purpose public API. FastAPI publishes the current schema at `/api/openapi.json`. The API is version 0.1 and may make incompatible changes before 1.0.

## Routes

| Method | Path | Audience | Authentication and exposure |
| --- | --- | --- | --- |
| `GET` | `/` | Operator or discovery client | No application authentication. Returns product name, version, and documentation URL. |
| `GET` | `/health/live` | Container orchestrator | No application authentication. Expose only through an operator-controlled health path. |
| `GET` | `/health/ready` | Container orchestrator | No application authentication. Expose only through an operator-controlled health path. |
| `GET` | `/metrics` | Prometheus-compatible scraper | No application authentication. Restrict at the network or proxy layer. |
| `GET` | `/api/docs` | Developer or operator | Interactive Swagger UI for the schema-listed routes. Restrict outside development environments. |
| `GET` | `/api/openapi.json` | Documentation tooling | OpenAPI document for schema-listed routes. Restrict outside development environments. |
| `GET` | `/docs/oauth2-redirect` | Swagger UI | Framework-provided OAuth redirect helper. Extra CODEOWNERS does not use end-user OAuth, but FastAPI registers this route with Swagger UI. |
| `POST` | `/webhooks/github` | GitHub App webhook delivery | Authenticated by GitHub's HMAC-SHA256 signature over the raw request body. Public HTTPS ingress is required. |
| `GET` | `/setup` | GitHub App administrator | Disabled by default. Starts the development App setup flow only when setup mode and its state secret are configured. |
| `GET` | `/setup/callback` | GitHub App Manifest callback | Disabled by default. Exchanges GitHub's single-use setup code after validating short-lived state. |
| `GET` | `/setup/complete` | GitHub App administrator | Disabled by default. Receives GitHub's post-install setup redirect. |

Do not expose health, metrics, or setup routes merely because the webhook route must be public. Use ingress routing or an authenticating reverse proxy to limit them.

## `GET /`

A successful response is `200 application/json`:

```json
{
  "name": "Extra CODEOWNERS",
  "version": "0.1.0",
  "documentation": "https://extra-codeowners.readthedocs.io/"
}
```

The version reflects the installed package and may differ from this example.

## `GET /health/live`

Liveness reports whether the process can serve requests. It also reports whether its configured in-process worker and reconciler tasks are running. An orchestrator may restart the container after repeated liveness failures.

Liveness is not proof that GitHub credentials, the durable store, queue processing, or reconciliation are operating correctly. Use readiness and service metrics for those checks.

A successful response is `200 application/json`:

```json
{
  "status": "alive",
  "worker": true,
  "reconciler": true
}
```

If either expected background task has stopped, the response is `503`. The `status` is `not_alive`, and that task's field is `false`.

A disabled task reports `true`. A task that is not expected because this instance lacks GitHub processing configuration also reports `true`. The endpoint cannot prove that a worker or reconciler in another process is healthy.

## `GET /health/ready`

Readiness answers whether the instance has the runtime configuration and dependencies required to accept work. A non-successful response should remove the instance from webhook traffic without repeatedly restarting it.

Readiness does not assert that every GitHub installation is authorized or that every repository policy is valid; those are per-evaluation results.

The response is `200` when ready or `503` otherwise:

```json
{
  "status": "ready",
  "github_credentials": true,
  "database": true,
  "worker": true,
  "reconciler": true
}
```

Each boolean identifies the corresponding local readiness condition. The status is `not_ready` when credentials or the database are unavailable. It is also `not_ready` when a configured local background task has stopped.

A disabled worker or reconciler reports `true`. Readiness cannot prove that a corresponding task in another process is healthy.

## `GET /metrics`

The service exposes Prometheus text format. Application metrics include:

| Metric | Type | Meaning |
| --- | --- | --- |
| `extra_codeowners_webhooks_total` | counter | Verified GitHub deliveries by event and action. |
| `extra_codeowners_webhook_failures_total` | counter | Rejected or failed deliveries by reason. |
| `extra_codeowners_evaluations_total` | counter | Completed policy evaluations by conclusion. |
| `extra_codeowners_evaluation_seconds` | histogram | Evaluation latency. |
| `extra_codeowners_queue_depth` | gauge | Pending durable pull-request evaluation and authority fan-out jobs. |
| `extra_codeowners_dead_jobs` | gauge | Legacy or manually introduced terminal rows. Normal runtime failures remain pending and retry indefinitely, so this should stay `0`. |
| `extra_codeowners_insecure_changes_enabled` | gauge | `1` whenever built-in non-delegable paths are disabled. |
| `extra_codeowners_reconciliations_total` | counter | Completed reconciliation attempts labeled by `result="success"` or `result="failure"`. |
| `extra_codeowners_reconciliation_last_success_timestamp_seconds` | gauge | Unix timestamp of the latest successful open-pull-request reconciliation. |

Prometheus runtime and process collectors may add metrics beyond this table. Metric labels must not contain repository names, pull-request titles, actor names, paths, or delivery IDs. Those values create unbounded cardinality and can disclose private metadata.

## `POST /webhooks/github`

GitHub sends a JSON payload with these required headers:

| Header | Purpose |
| --- | --- |
| `X-Hub-Signature-256` | HMAC-SHA256 signature verified against the configured webhook secret. |
| `X-GitHub-Event` | Event name used to select a scheduling handler. |
| `X-GitHub-Delivery` | Unique delivery identifier used for replay-safe deduplication. |

The service verifies the signature against the exact raw bytes before parsing JSON. An authenticated, relevant delivery is recorded in the same transaction as its pull-request evaluation or authority fan-out work.

For a direct pull-request, review, or rerequest trigger, ingress makes a bounded attempt to fetch the current pull request and policy. It creates or updates the managed current-head check as `in_progress` when policy exists. When policy is absent, it updates an existing managed check. A repository with neither policy nor a managed check is skipped.

After a delivery ID is pruned, redelivery can create or coalesce fresh work. That work fetches current GitHub evidence again.

Full evaluation is asynchronous. For a mapped trigger, a successful webhook response means the service recorded durable work. It does not mean that the pull request passed or that an invalidation reached GitHub.

| `202` response field | Meaning |
| --- | --- |
| `accepted` | `false` for an already recorded mapped delivery; otherwise `true`. |
| `queued` | `true` when this request accepted new mapped work. For a direct pull-request trigger, it is also `true` when the request resumed pending invalidation and requested a superseding generation. This is not a live queue-state indicator. |

A duplicate pull-request redelivery can return `accepted: false, queued: true`. Other duplicate redeliveries leave existing work unchanged.

An authenticated but unmapped event or action returns `{"accepted":true,"queued":false}`. It is not retained or deduplicated. Pull-request events for the configured organization-policy repository are also ignored because that repository remains under native human enforcement.

These events are retained and create installation-wide fan-out work:

- a relevant organization-policy push to the default branch
- an organization-policy repository lifecycle event
- a target-repository rename, transfer, or unarchive
- removal of the configured organization-policy repository from App selection
- missing or malformed `repositories_removed` evidence, treated as loss of the policy source.

A well-formed removal containing only ordinary targets is acknowledged without work because App access is already gone.

| Condition | Status | Behavior |
| --- | --- | --- |
| Missing or malformed `X-Hub-Signature-256`, or a signature mismatch | `401` | Reject the request before parsing JSON. |
| Missing or malformed `X-GitHub-Delivery` or `X-GitHub-Event`, or malformed JSON | `400` | Reject the request. |
| Body larger than 10 MiB | `413` | Reject the request, with or without `Content-Length`. The service enforces the limit while streaming the body. Ingress should enforce the same limit. |
| No configured webhook secret | `503` | Reject the request. |
| Retained direct pull-request trigger with no configured evaluator | `503` | Store the trigger, but report that revocation could not be attempted. |
| Durable-store failure for mapped work | `503` | Do not acknowledge successful ingestion. |
| Timeout or durable-store failure while ordering an authority event against an in-flight Check Run | `503` | Do not record the delivery. Restore the service and use GitHub's **Redeliver** control; GitHub does not retry automatically. |

After durable acceptance of a direct pull-request trigger, a GitHub API failure or `EXTRA_CODEOWNERS_WEBHOOK_INVALIDATION_TIMEOUT_SECONDS` expiry leaves the invalidation marker pending. The response remains `202`. The durable job performs the authoritative blocking evaluation, and manual redelivery can retry the fast path.

Authority-change acceptance uses the same timeout while waiting for an in-flight final Check Run under the installation publication guard. The acceptance transaction advances a persistent installation authority epoch for an installation-wide event. It records the fan-out job in the same transaction. Every evaluation row stores the epoch from enqueue time. Work queued before the authority change therefore cannot publish, even after fan-out completes.

The authority worker performs these operations:

1. Split installation scope into repository fences when needed.
2. Enumerate affected open pull requests.
3. Supersede each evaluation generation.
4. Attempt bounded invalidation.

Installation-wide and repository-wide work is claimed before base-specific push work. Repository-wide work replaces older base-specific rows. A 101st distinct base-ref row for one installation and repository collapses the set into one conservative repository-wide job.

Evaluation and authority failures remain pending and retry indefinitely with bounded ordinary backoff. GitHub rate limits use their separately bounded provider delay. GitHub [requires a response within 10 seconds and does not automatically redeliver failures](https://docs.github.com/en/webhooks/using-webhooks/handling-failed-webhook-deliveries), so synchronous work is bounded. A direct-trigger fast-path failure does not undo durable acceptance. An authority-guard timeout prevents acceptance and requires manual redelivery.

GitHub documents signature validation in [Validating webhook deliveries](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries).

## App Manifest setup routes

Setup mode requires all three settings:

- `EXTRA_CODEOWNERS_SETUP_ENABLED=true`
- an HTTPS `EXTRA_CODEOWNERS_PUBLIC_URL`
- `EXTRA_CODEOWNERS_SETUP_STATE_SECRET` containing at least 32 bytes.

When `EXTRA_CODEOWNERS_SETUP_ENABLED` is `false`, the setup routes return `404` and the other two settings are not required. When it is `true`, missing or invalid setup settings prevent the service configuration from loading. The state secret protects the short-lived setup exchange and is independent of the GitHub webhook secret.

`GET /setup` accepts an optional `organization` query parameter. When supplied, GitHub creates the App under that organization; otherwise GitHub uses the administrator's personal App settings. The route returns `200 text/html`, or `404` when setup is disabled.

GitHub redirects the one-time conversion `code` and signed `state` query parameters to `GET /setup/callback`. Both are required. The service validates state and exchanges the code. It displays the complete App Manifest conversion response once with no-store response headers.

The response contains the App ID and sensitive credential material:

- the private key
- the webhook secret
- any client secret returned by GitHub.

| Callback condition | Status |
| --- | --- |
| Invalid, expired, or rejected exchange | `400` |
| Missing required query parameter | `422` |
| Setup disabled, with both query parameters otherwise valid | `404` |

GitHub uses `GET /setup/complete` after installation or permission updates. It returns a `200` configuration pointer only while setup mode is enabled, and `404` otherwise.

The service does not retain the one-time credentials. They must be copied directly into a secret manager before the result page is closed. Reverse proxies must omit callback query strings from access logs because the conversion code is sensitive. The result page must not appear in screenshots, browser synchronization, support tickets, terminal transcripts, or logs.

The setup flow creates a private App by default. It requests these permissions:

| Permission | Access |
| --- | --- |
| Checks | Write |
| Statuses | Write |
| Contents | Read |
| Metadata | Read |
| Members | Read |
| Pull requests | Read |

Statuses is required for expected-source selection in organization-level rulesets. Runtime installation tokens omit it. The App's explicit subscriptions and automatically delivered installation events appear in the [GitHub permissions reference](github-permissions.md#webhook-subscriptions).

Operators who do not need to register Apps through this service should keep setup mode disabled.

## Errors and compatibility

Clients must interpret HTTP status codes rather than response text. The JSON error envelope and OpenAPI compatibility policy may change before 1.0. Such changes appear in release notes. Repeated or manually redelivered webhooks are idempotent while the delivery ID remains in the deduplication store.
