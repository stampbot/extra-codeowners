# HTTP API reference

Extra CODEOWNERS exposes a small service surface for GitHub and operators. It is not a general-purpose public API. FastAPI generates the current schema at `/api/openapi.json`; the application and schema remain pre-1.0.

## Routes

| Method | Path | Audience | Authentication and exposure |
| --- | --- | --- | --- |
| `GET` | `/` | Operator or discovery client | No application authentication. Returns product name, version, and documentation URL. |
| `GET` | `/health/live` | Container orchestrator | No application authentication. Expose only through an operator-controlled health path. |
| `GET` | `/health/ready` | Container orchestrator | No application authentication. Expose only through an operator-controlled health path. |
| `GET` | `/metrics` | Prometheus-compatible scraper | No application authentication in the initial service. Restrict at the network or proxy layer. |
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

Liveness answers whether the process can serve requests and whether its configured in-process worker and reconciler tasks are still running. An orchestrator may restart the container after repeated liveness failures.

Liveness is not proof that GitHub credentials, the durable store, queue processing, or reconciliation are operating correctly. Use readiness and service metrics for those checks.

A successful response is `200 application/json`:

```json
{
  "status": "alive",
  "worker": true,
  "reconciler": true
}
```

If either expected background task has stopped, the response is `503`, `status` is `not_alive`, and that task's field is `false`. A disabled task, or one that is not expected because this instance lacks GitHub processing configuration, reports `true`; this endpoint cannot prove that a worker or reconciler running in another process is healthy.

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

Each boolean identifies the corresponding local readiness condition. The status is `not_ready` if credentials or the database are unavailable, or if either configured local background task has stopped. A deliberately disabled worker or reconciler reports `true`; readiness cannot prove that a corresponding task in another process is healthy.

## `GET /metrics`

The service exposes Prometheus text format. Initial application metrics include:

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

Prometheus runtime and process collectors may add metrics beyond this table. Avoid labels containing repository names, pull-request titles, actor names, paths, or delivery IDs because those create unbounded cardinality and can disclose private metadata.

## `POST /webhooks/github`

GitHub sends a JSON payload with these required headers:

| Header | Purpose |
| --- | --- |
| `X-Hub-Signature-256` | HMAC-SHA256 signature verified against the configured webhook secret. |
| `X-GitHub-Event` | Event name used to select a scheduling handler. |
| `X-GitHub-Delivery` | Unique delivery identifier used for replay-safe deduplication. |

The service verifies the signature against the exact raw bytes before parsing JSON. An authenticated, relevant delivery is recorded transactionally with either pull-request evaluation work or broader authority fan-out work. For a direct pull-request, review, or rerequest trigger, ingress then makes a bounded attempt to fetch the current pull request and policy. It creates or updates the managed current-head check as `in_progress` when policy exists, and updates an already managed check when policy is absent. A repository with neither policy nor a managed check is deliberately skipped. Once a delivery ID is pruned, a redelivery can create or coalesce fresh work, which re-fetches current GitHub evidence.

Full evaluation remains asynchronous. For a mapped trigger, a successful webhook response means durable work was recorded, not that a pull request passed or an invalidation reached GitHub. A `202` JSON response contains `accepted`, which is `false` for an already recorded mapped delivery. `queued` is `true` when this request either newly accepted mapped work or, for a direct pull-request trigger, successfully resumed pending invalidation and requested a superseding generation. A duplicate pull-request redelivery can therefore return `accepted: false, queued: true`; `queued` is not a live queue-state indicator. A duplicate redelivery otherwise leaves existing work unchanged.

An authenticated but unmapped event or action is acknowledged as `{"accepted":true,"queued":false}` without durable retention or deduplication. Pull-request events for the configured organization-policy repository are also ignored because that repository remains under native human enforcement. A relevant default-branch organization-policy push, organization-policy repository lifecycle event, target-repository rename, transfer, or unarchive event, or removal of the configured organization-policy repository from App selection is retained and creates installation-wide fan-out work. Missing or malformed `repositories_removed` evidence is handled as conservative policy-source loss and also fans out; a well-formed removal containing only ordinary targets is acknowledged without work because App access is already gone. Malformed JSON or headers return `400`, signature failures return `401`, and a body larger than 10 MiB returns `413` whether or not `Content-Length` was supplied. A receiver without a webhook secret returns `503`; a retained direct pull-request trigger also returns `503` after storage when no evaluator is configured to attempt revocation. A durable-store failure or timeout while ordering an authority event against an in-flight Check Run returns `503` before the delivery is recorded. Restore the service, then use GitHub's **Redeliver** control; GitHub does not retry it automatically. The service bounds the streamed body as it reads it; ingress should enforce the same limit as an additional control. Durable-store failures for mapped work are not acknowledged as successful ingestion.

After durable acceptance of a direct pull-request trigger, a GitHub API failure or `EXTRA_CODEOWNERS_WEBHOOK_INVALIDATION_TIMEOUT_SECONDS` expiry leaves the invalidation marker pending but returns `202`; the durable job performs the authoritative blocking evaluation, and manual redelivery can retry the fast path. Authority-change acceptance uses that same timeout while it waits for an in-flight final Check Run to finish under the installation publication guard. In the acceptance transaction, an installation-wide event advances a persistent installation authority epoch and records the fan-out job. Because every evaluation row stores the epoch from enqueue time, work queued before the change cannot publish even after fan-out completes. The authority worker then splits installation scope into repository fences when needed, enumerates affected open pull requests, supersedes each evaluation generation, and attempts bounded invalidation. Installation-wide and repository-wide work is claimed before base-specific push work; repository-wide work replaces older base-specific rows, and a 101st distinct base-ref row for one installation and repository collapses the set into one conservative repository-wide job. Evaluation and authority failures remain pending and retry indefinitely with a bounded ordinary backoff, while GitHub rate limits use their separately bounded provider delay. GitHub [requires a response within 10 seconds and does not automatically redeliver failures](https://docs.github.com/en/webhooks/using-webhooks/handling-failed-webhook-deliveries), so synchronous work is bounded; a direct-trigger fast-path failure does not undo durable acceptance, while an authority-guard timeout deliberately prevents acceptance and requires manual redelivery.

GitHub documents signature validation in [Validating webhook deliveries](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries).

## App Manifest setup routes

Setup mode is disabled unless `EXTRA_CODEOWNERS_SETUP_ENABLED=true`, an HTTPS `EXTRA_CODEOWNERS_PUBLIC_URL` is configured, and `EXTRA_CODEOWNERS_SETUP_STATE_SECRET` contains at least 32 bytes. The state secret protects the short-lived setup exchange and is independent of the GitHub webhook secret.

`GET /setup` accepts an optional `organization` query parameter. When supplied, GitHub creates the App under that organization; otherwise GitHub uses the administrator's personal App settings. The route returns `200 text/html`, or `404` when setup is disabled.

GitHub redirects the one-time conversion `code` and signed `state` query parameters to `GET /setup/callback`. Both are required. The service validates state, exchanges the code, and displays the complete App Manifest conversion response once with no-store response headers. That response includes the App ID and sensitive credential material such as the private key, webhook secret, and any client secret GitHub returns. The route returns `400` for an invalid, expired, or rejected exchange, `422` when a required query parameter is absent, and `404` when setup is disabled and both query parameters are otherwise valid.

GitHub uses `GET /setup/complete` after installation or permission updates. It returns a `200` configuration pointer only while setup mode is enabled, and `404` otherwise.

Copy the one-time credentials directly into a secret manager, then close the result page. The service does not retain them. Configure reverse proxies to omit callback query strings from access logs because the conversion code is sensitive. Do not capture the result page in screenshots, browser synchronization, support tickets, terminal transcripts, or logs.

The setup flow creates a private App by default and requests Checks write, Statuses write, Contents read, Metadata read, Members read, and Pull requests read. Statuses is required for expected-source selection in organization-level rulesets but is removed from runtime installation tokens. The App's explicit subscriptions and the automatically delivered installation events it handles are listed in the [GitHub permissions reference](github-permissions.md#webhook-subscriptions).

Operators who do not need to register Apps through this service should keep setup mode disabled.

## Errors and compatibility

Clients must interpret HTTP status codes rather than response text. The JSON error envelope and OpenAPI compatibility policy are pre-1.0 and may change with release notes. Repeated or manually redelivered webhooks are idempotent while the delivery ID remains in the deduplication store.
