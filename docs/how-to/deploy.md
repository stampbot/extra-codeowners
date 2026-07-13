# Deploy the GitHub App service

Extra CODEOWNERS does not yet have a supported production release or hosted service. Successful `main` CI builds are configured to publish signed, attested multi-architecture preview containers, but no tagged release or versioned chart exists until a release workflow succeeds. This guide defines the deployment requirements and a preview path for reviewers. Do not use a preview artifact to authorize production merges.

## Prerequisites

You need:

- a reviewed Extra CODEOWNERS commit;
- Docker for a local source build, or current GitHub CLI and Cosign releases for verifying a CI-published preview;
- a GitHub App registered with the [documented permissions and events](../reference/github-permissions.md);
- a public HTTPS origin with a valid certificate;
- PostgreSQL with hostname-verified TLS for remote connections, or an operator-controlled local proxy or Unix socket, plus backup and restricted credentials;
- a secret manager for the App private key and webhook secret;
- outbound HTTPS access to the configured GitHub API;
- reliable UTC clock synchronization on every service node, for GitHub App JWTs, setup-state expiry, and durable leases; and
- monitoring access to readiness and Prometheus metrics.

SQLite is for a single-process development installation only. It is not an acceptable production durable queue.

## 1. Select an immutable preview image

After a successful build on `main`, CI publishes `ghcr.io/stampbot/extra-codeowners:main` and a commit-specific `sha-*` tag. The `main` tag is mutable. For a disposable review deployment, select the commit-specific tag, resolve it to a registry digest, and record the source commit. Replace the digest placeholder below, then verify both GitHub provenance and the keyless workflow signature:

```bash
export IMAGE='ghcr.io/stampbot/extra-codeowners@sha256:REPLACE_WITH_DIGEST'
gh attestation verify "oci://${IMAGE}" -R stampbot/extra-codeowners
cosign verify \
  --certificate-identity-regexp='^https://github\.com/stampbot/extra-codeowners/\.github/workflows/ci\.yml@refs/heads/main$' \
  --certificate-oidc-issuer='https://token.actions.githubusercontent.com' \
  "$IMAGE"
```

Both commands must succeed, and the attested source repository and commit must match the reviewed revision. See GitHub's [artifact-attestation verification guide](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations) and Sigstore's [Cosign verification guide](https://docs.sigstore.dev/quickstart/quickstart-cosign/) for tool installation and trust details. If the preview package is not yet available, build from the reviewed source as shown below.

From the repository root, build the image from the reviewed commit:

```bash
docker build --tag extra-codeowners:preview .
```

Record the resulting image digest. A local source build is not signed or attested merely because the repository workflow can produce those artifacts. Do not deploy a mutable tag without recording its digest and source commit. The checked-in tag-release pipeline is configured to publish signed, attestable versioned images, but none exists until the first successful release.

## 2. Provision durable state

Create a dedicated PostgreSQL database and role. The role should own only the Extra CODEOWNERS database and should not have cluster-administrator or unrelated-database privileges.

Supply a SQLAlchemy URL using the psycopg driver, for example:

```text
postgresql+psycopg://DB_USER:DB_PASSWORD@DB_HOST:5432/DB_NAME?sslmode=verify-full
```

Replace every uppercase placeholder and percent-encode reserved characters in URL components. For a remote database, retain `sslmode=verify-full` and add the provider's CA parameters, such as `sslrootcert`, when required. The `require` and `verify-ca` modes are rejected because neither verifies the database hostname. Query-string routing cannot bypass this check: `host` takes precedence over the URL authority, and any `hostaddr` or `service` override requires `verify-full`. Treat the complete URL as a secret. Before upgrading, back up the database and review release notes for schema compatibility; a migration and rollback contract will be added before the first supported release.

The preview deliberately fails fast after 3 seconds while connecting to PostgreSQL, 2 seconds while waiting for its application connection pool, or 3 seconds for an ordinary statement. These budgets are not configurable. Test the complete service-to-database path, including a proxy when used, under expected peak latency and concurrency. Do not deploy it as merge infrastructure when normal operation approaches those limits; a timeout blocks or retries work rather than inferring approval.

## 3. Mount secrets

Mount the GitHub App private key and webhook secret as read-only files readable only by the container's runtime user. Configure:

```text
EXTRA_CODEOWNERS_GITHUB_PRIVATE_KEY_FILE=/run/secrets/github-private-key
EXTRA_CODEOWNERS_GITHUB_WEBHOOK_SECRET_FILE=/run/secrets/github-webhook-secret
```

Do not bake secrets into the image, place them in command-line arguments, or commit them to an environment file. Supply the database URL through the platform's secret-injection mechanism.

## 4. Configure the service

Set at least:

```text
EXTRA_CODEOWNERS_ENVIRONMENT=production
EXTRA_CODEOWNERS_GITHUB_APP_ID=123456
EXTRA_CODEOWNERS_GITHUB_PRIVATE_KEY_FILE=/run/secrets/github-private-key
EXTRA_CODEOWNERS_GITHUB_WEBHOOK_SECRET_FILE=/run/secrets/github-webhook-secret
EXTRA_CODEOWNERS_DATABASE_URL=postgresql+psycopg://DB_USER:DB_PASSWORD@DB_HOST:5432/DB_NAME?sslmode=verify-full
EXTRA_CODEOWNERS_WORKER_RETRY_MAX_SECONDS=60
EXTRA_CODEOWNERS_WEBHOOK_DELIVERY_RETENTION_DAYS=30
```

Replace the example App ID and database placeholders. Production startup rejects SQLite and other non-PostgreSQL database URLs, non-local database connections without `sslmode=verify-full`, webhook secrets shorter than 32 UTF-8 bytes, and non-HTTPS GitHub API origins. An effective `localhost`, `127.0.0.1`, `::1`, or Unix-socket database proxy may omit `sslmode`; `hostaddr` and `service` overrides never qualify for that exception. The operator remains responsible for authenticating and protecting a local proxy's upstream connection. Keep `EXTRA_CODEOWNERS_ALLOW_INSECURE_CHANGES=false`. Setup mode is disabled by default and should remain disabled after App registration. `EXTRA_CODEOWNERS_PUBLIC_URL` is required only for a separate setup-mode process, where it must use HTTPS.

Choose a delivery-ID retention period that covers GitHub redelivery and the operator's incident-investigation window. Automatic pruning runs as part of the elected reconciler, so keep reconciliation enabled or provide an independently reviewed retention procedure. Pruning a delivery ID permits that old ID to be accepted again, but it can only coalesce a fresh evaluation that re-fetches current GitHub evidence.

Evaluation and authority failures retry indefinitely because abandoned revocation work could leave a stale success visible. `EXTRA_CODEOWNERS_WORKER_RETRY_MAX_SECONDS` caps the ordinary exponential delay, not the number of attempts. GitHub rate-limit responses use the provider's separate bounded `Retry-After` delay. Alert on a pending queue that remains above its normal baseline and repeated failure logs; do not use manual requeue as normal recovery.

The full settings table and bounds are in the [configuration reference](../reference/configuration.md#runtime-settings).

## 5. Configure ingress

Route public GitHub traffic only to `POST /webhooks/github`. Preserve the raw body and the `X-Hub-Signature-256`, `X-GitHub-Event`, and `X-GitHub-Delivery` headers.

Apply:

- TLS termination with current protocols;
- a request-body limit of 10 MiB, or a lower limit only after testing legitimate delivery sizes, enforced before request buffering;
- rate limiting that allows normal GitHub bursts and redeliveries; and
- no response caching.

Disable query-string logging for `/setup/callback`; its single-use App Manifest conversion code is sensitive. Keep application setup disabled in normal service operation so the route returns `404`.

Keep `/metrics`, `/health/live`, `/health/ready`, and `/setup` on operator-controlled routes. If the ingress cannot route by path, require network or proxy authentication for everything except `/webhooks/github`.

## 6. Verify before receiving production events

Verify liveness and readiness from the same network used by the orchestrator:

```bash
curl --fail-with-body https://operator-endpoint.example.com/health/live
curl --fail-with-body https://operator-endpoint.example.com/health/ready
```

Verify the metrics scraper can read `/metrics` and that `extra_codeowners_insecure_changes_enabled` is `0`.

Confirm this deployment enables the worker and reconciler, and that both fields are `true` in each health response. After the initial reconciliation, verify `extra_codeowners_reconciliations_total{result="success"}` increased and `extra_codeowners_reconciliation_last_success_timestamp_seconds` contains a recent Unix timestamp.

Send a GitHub test delivery, confirm it is accepted exactly once, and confirm a test repository receives a check from the expected App source. Complete every negative test in [Prepare repository rules](prepare-repository-rules.md#3-verify-the-conjunction) before changing a production ruleset.

## Roll back or mitigate

If a rollout produces incorrect results:

1. Stop routing new webhook traffic to the bad version.
2. Restore the previous image by recorded digest without rolling the database backward.
3. Confirm the old version's readiness and queue processing.
4. Redeliver deliveries that were never accepted, then allow pending work to retry and reconciliation to enqueue open pull requests with no existing job.
5. Verify current-head checks in a test repository.

If the previous version cannot safely use the current database, stop application delegation: restore native **Require review from Code Owners** on affected repositories before removing the Extra CODEOWNERS required check. Preserve database and logs for investigation.

The preview Helm chart defaults to a `Recreate` Deployment strategy because this pre-1.0 service has no mixed-version database compatibility contract. That avoids old and new application versions running together, but creates a brief webhook-processing outage. GitHub does not automatically redeliver failed webhooks: after the service is ready, inspect failed deliveries, manually redeliver them, and confirm scheduled reconciliation is converging open pull requests. Keep one replica and do not switch to `RollingUpdate` until the versions, schema, and lease behavior have been tested together. The chart's [preview installation and recovery guide](https://github.com/stampbot/extra-codeowners/blob/main/charts/extra-codeowners/README.md) provides the complete Kubernetes procedure.

## Release and planned supported paths

Initial Helm chart source is available at `charts/extra-codeowners`. A successful exact semantic-version tag release is configured to publish:

- a signed multi-architecture image at `ghcr.io/stampbot/extra-codeowners:<version>`;
- a signed OCI chart at `oci://ghcr.io/stampbot/charts/extra-codeowners`, versioned with the release number;
- Python wheel and source artifacts; and
- build provenance and software-bill-of-material attestations.

Artifact existence follows successful CI or a successful GitHub release; workflow source alone is not proof that an artifact was published. There is no supported release until one is announced in the repository. Tested chart upgrade guarantees and a reproducible Google Cloud deployment guide remain planned; their workload-identity behavior will be documented from published artifacts rather than inferred here.
