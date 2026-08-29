# Deploy an alpha in shadow mode

Use this guide to deploy the self-hosted GitHub App with PostgreSQL and the
published Helm chart. The current releases are alpha software. Run the check as
non-required evidence while you test it; don't let it authorize a production
merge.

!!! danger
    Keep GitHub's native **Require review from Code Owners** rule on production
    repositories. The commit-scoped Check Run behavior still has an open
    provider contract in
    [issue #1](https://github.com/stampbot/extra-codeowners/issues/1). Do not
    deploy, mirror, or redistribute legacy preview images: `:main` and its
    `sha-*` and `sha256-*` companion tags. They are unsupported and unsafe for
    deployment because they predate the immutable release pipeline.

## Choose one release

On a push to `main`, the release job runs after required CI succeeds and
publishes one immutable release. Use the same version everywhere:

- container image: `ghcr.io/stampbot/extra-codeowners:VERSION`
- Helm chart: `oci://ghcr.io/stampbot/charts/extra-codeowners`
- Python wheel, source distribution, signatures, and scan reports: the matching
  GitHub release.

You don't need the raw per-platform distribution inventories to deploy the
App. New releases include them in the matching GitHub release for component
review. They are not a notice package or a source offer; see
[project status](../reference/project-status.md) for their scope and limits.

If the release contains a reviewed VEX claim, the same release includes
`extra-codeowners-VERSION.openvex.json` and its Sigstore bundle. Its OpenVEX
attestation binds that statement to the multi-platform image digest. Use that
asset with the released digest, not a statement from a newer source checkout.

Replace `VERSION` with an exact value such as `0.1.0-alpha.8`. Don't use a
floating tag. Resolve and record the multi-platform image digest before you
change the cluster; the chart also accepts that digest through `image.digest`.

The released chart sets its `appVersion` to the same version and uses it as the
default image tag. Confirm that before installation:

```bash
export VERSION='0.1.0-alpha.8'
helm show chart \
  oci://ghcr.io/stampbot/charts/extra-codeowners \
  --version "$VERSION"
```

The output must show `version` and `appVersion` equal to `VERSION`. Check the
matching GitHub release before continuing. The release workflow signs and
attests the image, chart, and Python artifacts, but verification is still the
operator's job. A workflow file by itself does not prove that publication
finished.

Require GitHub to report the release as published and immutable:

```bash
test "$(
  gh api "repos/stampbot/extra-codeowners/releases/tags/v$VERSION" \
    --jq '.draft == false and .immutable == true'
)" = true
```

The command exits silently on success. Stop if it prints an error or exits
nonzero.

Resolve the image digest and verify that GitHub recorded provenance from this
repository's release workflow:

```bash
export IMAGE_REPOSITORY='ghcr.io/stampbot/extra-codeowners'
export IMAGE_DIGEST="$(
  docker buildx imagetools inspect "$IMAGE_REPOSITORY:$VERSION" |
    awk '$1 == "Digest:" {print $2; exit}'
)"
printf '%s\n' "$IMAGE_DIGEST" | grep -Eq '^sha256:[0-9a-f]{64}$'
gh attestation verify "oci://$IMAGE_REPOSITORY@$IMAGE_DIGEST" \
  --repo stampbot/extra-codeowners \
  --signer-workflow stampbot/extra-codeowners/.github/workflows/release.yml
```

Every command must exit zero. Keep `IMAGE_DIGEST` in the deployment record and
pass it as the chart's `image.digest`. The `README.md` inside the matching
chart archive contains the chart verification and install commands.

For a source review or local image test, the Dockerfile installs the runtime
graph from `uv.lock` and rejects dependency source builds. Release builds run
natively on `amd64` and `arm64`, scan each image, and assemble the
multi-platform tag only after both builds pass. The
[runtime-base explanation](../explanation/runtime-base.md) records the exact
base and residual risk.

## Prerequisites

Before scheduling a deployment, obtain:

- an Extra CODEOWNERS alpha image, verified and pinned by platform digest
- the exact chart source associated with that image
- a GitHub App with the
  [required permissions and events](../reference/github-permissions.md)
- a public HTTPS origin with a valid certificate
- PostgreSQL that accepts TLS with `sslmode=require`, or an operator-controlled
  local proxy or Unix socket
- tested PostgreSQL backups and a database credential restricted to this
  service
- a secret manager for the App private key and webhook secret
- outbound HTTPS access to the configured GitHub API
- reliable UTC clock synchronization on every node
- access to the health endpoints, logs, and Prometheus metrics
- the Helm 3.x version pinned in
  [the repository's `mise.toml`](https://github.com/stampbot/extra-codeowners/blob/main/mise.toml),
  Docker Buildx, and a current GitHub CLI on the administration host.

Clock accuracy matters because GitHub App JSON Web Tokens, setup-state expiry,
and database leases use wall-clock time.

Use SQLite only for a single-process development installation. It is not a
production queue.

## Provision PostgreSQL

Create one database and one role for Extra CODEOWNERS. Let that role own only
the application database; don't grant PostgreSQL cluster administration or
access to unrelated databases.

Use a SQLAlchemy URL through the exact `postgresql+psycopg` driver:

```text
postgresql+psycopg://DB_USER:DB_PASSWORD@DB_HOST:5432/DB_NAME?sslmode=require
```

Replace every uppercase placeholder. The host, database, username, and
nonempty password must all appear in the URL. Percent-encode reserved
characters in the username and password, then treat the complete URL as a
secret. An explicit port must be between 1 and 65535; omit it only when port
5432 is correct.

Use `sslmode=require` for a remote database. It encrypts the connection but
does not verify the database certificate or hostname. The application prevents
libpq from loading its default root certificate, so a file in the process
account does not change that behavior. Keep the database route on a private
network you control and restrict the database role to this service.

Use one route. A query-string `host` may supply the host only when the URL
authority omits it. An explicit `hostaddr` also requires that host and
`sslmode=require`, even when the host looks local. Only `localhost`,
`127.0.0.1`, `::1`, or a Unix-socket path may use an operator-controlled local
transport without TLS. Hostless and comma-separated routes are rejected. You
must authenticate and secure a local proxy's upstream connection.

Only `host`, `hostaddr`, and `sslmode` query parameters are supported.
Connection-service URLs, `PGSERVICE`, `PGSERVICEFILE`, `.pgpass`, and
`PGPASSFILE` are not. Keep every ambient libpq connection variable out of the
application and migrator environments; production validation fails even when
one is present with an empty value. Both processes disable GSSAPI encryption
so it cannot bypass the required SSL transport, and pin `search_path=public`.
Use `sslmode=require` or `sslmode=disable`; certificate-verification modes are
unsupported.

Normal service startup checks the Alembic head and the
`required-release-contract`. It never creates or changes schema. Follow
[Upgrade, back up, and restore](upgrade.md) before the first startup and every
upgrade.

Database operations have fixed fail-fast limits:

| Operation | Limit |
| --- | ---: |
| Connect to PostgreSQL | 3 seconds |
| Obtain an application-pool connection | 2 seconds |
| Run an ordinary statement | 3 seconds |
| Wait for the default migration advisory lock | 60 seconds |
| Run one migration statement | 60 seconds |

The Helm migration Job has separate Secret, environment, volume, mount, and
ServiceAccount settings. Give it the database URL and only the authority
needed to change this schema. Its Secret must not contain ambient libpq
variables. Never mount the GitHub private key or webhook secret into the
migration Job.

Test the complete application-to-database path, including any proxy, under the
expected peak latency and concurrency. If normal operations approach these
limits, don't use the service as merge infrastructure. A timeout blocks or
retries work; it never infers approval.

## Mount credentials

Don't bake credentials into the image, pass them as command-line arguments, or
commit them to an environment file.

Mount the private key and webhook secret as read-only files that only the
container's runtime user can read. Configure:

```text
EXTRA_CODEOWNERS_GITHUB_PRIVATE_KEY_FILE=/run/secrets/github-private-key
EXTRA_CODEOWNERS_GITHUB_WEBHOOK_SECRET_FILE=/run/secrets/github-webhook-secret
```

Inject the database URL through the platform's secret mechanism. Don't add
libpq `PG*` connection variables to the same process environment.

## Configure the process

Set at least these values:

```text
EXTRA_CODEOWNERS_ENVIRONMENT=production
EXTRA_CODEOWNERS_GITHUB_APP_ID=123456
EXTRA_CODEOWNERS_GITHUB_PRIVATE_KEY_FILE=/run/secrets/github-private-key
EXTRA_CODEOWNERS_GITHUB_WEBHOOK_SECRET_FILE=/run/secrets/github-webhook-secret
EXTRA_CODEOWNERS_DATABASE_URL=postgresql+psycopg://DB_USER:DB_PASSWORD@DB_HOST:5432/DB_NAME?sslmode=require
EXTRA_CODEOWNERS_WORKER_RETRY_MAX_SECONDS=60
EXTRA_CODEOWNERS_WEBHOOK_DELIVERY_RETENTION_DAYS=30
```

Replace the App ID and database placeholders. Keep
`EXTRA_CODEOWNERS_ALLOW_INSECURE_CHANGES=false`.

Setup mode is disabled by default. Keep it off after App registration. Set
`EXTRA_CODEOWNERS_PUBLIC_URL` only for a separate setup process, and use an
HTTPS origin.

Production startup rejects:

- SQLite and every URL that does not use the exact `postgresql+psycopg` driver
- a URL without one explicit host, database, username, and nonempty password
- remote PostgreSQL without `sslmode=require`
- connection-service URLs, unknown query parameters, and ambient libpq
  connection variables
- a webhook secret shorter than 32 UTF-8 bytes
- a non-HTTPS GitHub API origin
- missing App ID, private key, or webhook secret.

Choose a webhook delivery-ID retention period that covers GitHub redelivery
and your incident investigation window. The elected reconciler removes expired
IDs. Keep reconciliation enabled or create a separately reviewed pruning
procedure. Once an ID expires, GitHub may redeliver it and the service may
accept it again, but the worker still fetches current GitHub evidence.

Evaluation and authority failures retry indefinitely. The
`EXTRA_CODEOWNERS_WORKER_RETRY_MAX_SECONDS` setting caps the ordinary
exponential delay, not the attempt count. GitHub rate-limit responses use a
separate provider-supplied delay bounded to one day. Alert on a queue that
stays above its normal baseline and on repeated failure logs. Don't use manual
requeue as routine recovery.

See the [runtime settings reference](../reference/configuration.md#runtime-settings)
for every setting, default, and bound.

## Size the Kubernetes startup probe

The Helm chart enables a startup probe on `/health/live`. It runs every five
seconds, waits up to three seconds for each response, and allows 60 failures.
That gives initialization a five-minute budget before Kubernetes restarts the
container.

Keep the startup probe separate from the other two probes. Kubernetes doesn't
run liveness or readiness probes until startup succeeds. After that point,
liveness detects a stuck process or failed local task, while readiness removes
an instance from webhook traffic when its database, App identity, worker, or
reconciler is unavailable.

Measure initialization with the production database path and secret mounts.
Set `periodSeconds * failureThreshold` above the slowest expected startup plus
operational margin, and set `timeoutSeconds` above the normal `/health/live`
response time. Keep Helm and rollout wait timeouts above that startup budget.
Increasing the startup allowance does not weaken ongoing liveness or readiness
checks.

## Expose only the webhook

Route unauthenticated GitHub traffic only to `POST /webhooks/github`. The
proxy must preserve the raw body and these headers:

- `X-Hub-Signature-256`
- `X-GitHub-Event`
- `X-GitHub-Delivery`.

Use current TLS protocols, disable response caching, and reject request bodies
larger than 10 MiB before buffering. Use a lower limit only after testing real
delivery sizes. Rate limits must still accommodate normal GitHub bursts and
manual redelivery.

Disable query-string logging for `/setup/callback`. Its one-use App
Manifest conversion code is sensitive. With setup disabled, `/setup` returns
`404`. A callback request that includes
its required `code` and `state` parameters also returns `404`.

Use path-level access control even when every route shares one HTTPS origin.
Keep `/`, `/api/runtime-identity`, `/api/docs`, `/api/openapi.json`,
`/docs/oauth2-redirect`, `/metrics`, both `/health` routes, and every `/setup`
route behind operator-controlled routing. If the proxy cannot enforce that
split, require network or proxy authentication everywhere except the exact
webhook path.

## Verify the deployment

Run these checks from the orchestrator network. Replace the example hostname
with an operator-only endpoint:

```bash
curl --fail-with-body https://operator-endpoint.example.com/health/live
curl --fail-with-body https://operator-endpoint.example.com/health/ready
curl --fail-with-body \
  https://operator-endpoint.example.com/api/runtime-identity
```

All three requests must return HTTP 200. Compare every runtime-identity field
with the reviewed deployment settings. An official image must report its full
verified source commit in `build_revision`; a source installation reports
`null`. The endpoint is a deployment self-report, not independent provenance
evidence.

If the instance runs background work, confirm that `worker_enabled`,
`reconciler_enabled`, `worker`, and `reconciler` are `true` in both health
responses. The first two fields confirm that the process is configured to run
those tasks. The other two report task health.

Confirm the metrics scraper can read `/metrics` and that
`extra_codeowners_insecure_changes_enabled` is `0`.

After reconciliation runs, verify that at least one scraped replica reports an
increase in `extra_codeowners_reconciliations_total{result="success"}`. At
least one replica's
`extra_codeowners_reconciliation_last_success_timestamp_seconds` must contain a
recent timestamp. Investigate any `partial` or `failure` result before treating
reconciliation as healthy.

Then use a disposable repository with test policy:

1. Open a pull request that changes an owned path.
2. In the App's **Advanced** settings, confirm a successful
   `pull_request.opened` delivery.
3. Confirm that the expected App publishes the check on the current head.
4. Redeliver the same delivery and confirm it does not create duplicate work.
5. Complete every negative test in
   [Prepare repository rules](prepare-repository-rules.md#3-exercise-the-complete-rule).

Passing these checks does not close the commit-scoped Check Run limitation.
Do not use the result to authorize production merges.

## Roll back or mitigate

Restore repository enforcement before changing traffic or processes:

1. Restore GitHub's native **Require review from Code Owners** rule on every
   affected repository.
2. Wait until GitHub shows the rule as active.
3. Remove the `Extra CODEOWNERS / approval` requirement if the service's
   decisions are suspect or the service will remain offline.
4. Stop routing new webhook traffic.

This order applies to an authorization defect, a same-schema application
rollback, and a database restore. It prevents an earlier Extra CODEOWNERS
success from remaining the only code-owner gate while the service is stopped.

If you have a previously verified compatible image, compare the current database
head with that artifact's required head:

1. If the head is unchanged, deploy the previous image by its recorded digest
   and run `extra-codeowners database check` before restoring traffic.
2. If the head changed, stop every Extra CODEOWNERS process, preserve the
   failed database, and restore the verified pre-migration backup into a new
   empty database. Validate the restored database with the previous artifact.
3. Redeliver deliveries that the service never accepted. Let pending work
   retry, and let reconciliation enqueue open pull requests with no job.
4. Verify current-head checks in a disposable repository.

Every Alembic head change requires the restore in step 2. An additive physical
change does not make an old exact-head artifact compatible.

If you don't have a previously verified compatible image, keep native
code-owner enforcement in place and preserve the database and sanitized logs
for investigation.

The Helm chart runs a bounded pre-upgrade migration Job. The default Deployment
strategy is still `Recreate`, but the reviewed two-replica preset uses a
`RollingUpdate`. A rolling workload protects a pod or node failure; it does
not make an old application compatible with a new Alembic head. Before any
release whose upgrade notes require a drain, route webhook traffic away and
scale the old Deployment to zero. An HPA or GitOps controller can undo that
scale operation, so suspend reconciliation and remove the HPA first. Follow
the [controller-safe drain procedure](upgrade.md#drain-a-kubernetes-release),
wait for termination and both the worker and reconciler lease periods, and
then start the upgrade.

Expect a webhook interruption. GitHub does not automatically redeliver failed
deliveries, so inspect and redeliver them after readiness returns.
Reconciliation output is advisory; independently inventory accessible open
pull requests and retain native enforcement for any current check you did not
verify.

For a PostgreSQL deployment, enable the chart's `highAvailability` preset once
you have two schedulable nodes. The database coordinates competing claims and
the singleton reconciler lease across replicas. Use
`charts/extra-codeowners/README.md` from the same reviewed checkout; don't
jump to a mutable default-branch copy.

## What a release publishes

Each successful release workflow publishes:

- a signed multi-architecture image at
  `ghcr.io/stampbot/extra-codeowners:VERSION`
- a signed OCI chart at
  `oci://ghcr.io/stampbot/charts/extra-codeowners`
- Python wheel and source distribution as GitHub release assets
- signed raw distribution inventories for `amd64` and `arm64`, each bound to
  its image child digest
- a signed OpenVEX release asset, bound to the multi-platform image digest
- BuildKit provenance and software bill of materials for each native image
- GitHub provenance attestations and Sigstore signatures for published
  artifacts
- native vulnerability reports.

A published, immutable GitHub release is the pipeline's completion record.
Verify the release, GHCR image, and OCI chart before using them. The Python
artifacts are not published to the Python Package Index (PyPI).

Environment-specific chart upgrade evidence and a reproducible Google Cloud
deployment guide are still planned. Their workload-identity behavior will be
documented from published artifacts, not inferred from source.
