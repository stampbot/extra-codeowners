# Prepare a future deployment

Use this guide to design the database, secrets, network boundary, probes, and
rollback plan for a future Extra CODEOWNERS deployment. The project does not
have a supported production release, public image, OCI chart, hosted service,
or Marketplace Action, so you cannot complete a supported installation yet.

!!! danger
    Do not deploy the old `ghcr.io/stampbot/extra-codeowners:main` image,
    mirror it, or build a substitute from the current Dockerfile. Keep GitHub's
    native **Require review from Code Owners** rule on production repositories.
    The release pipeline and the commit-scoped Check Run behavior both have
    open blockers. [Issue #1](https://github.com/stampbot/extra-codeowners/issues/1)
    tracks the Check Run gap, and
    [issue #30](https://github.com/stampbot/extra-codeowners/issues/30) tracks
    the old image.

## Understand the current release block

The main-branch publication job has been removed. Tagged publication is also
stopped before any job with package, signing, attestation, or release
authority can run.

Four open issues define the remaining release work:

- [#18](https://github.com/stampbot/extra-codeowners/issues/18) expands native
  wheel and embedded software bill of materials (SBOM) components into the
  notice, license, and corresponding-source evidence delivered to recipients.
- [#28](https://github.com/stampbot/extra-codeowners/issues/28) separates
  untrusted archive parsing from publication credentials and signing
  authority.
- [#32](https://github.com/stampbot/extra-codeowners/issues/32) completes the
  hash-pinned application build and retains its selected proof for release
  consumers.
- [#25](https://github.com/stampbot/extra-codeowners/issues/25) makes the first
  GitHub release draft-first and immutable after its complete artifact set is
  verified.

Current continuous integration (CI) builds the Python distribution twice on
each native architecture. It selects one byte-identical five-file proof across
`amd64` and `arm64`, then passes that directory to the Dockerfile as a
read-only `verified-python` build context. The Dockerfile also requires the
source revision, application-wheel SHA-256, and selection-record SHA-256. It
fails when any input is missing or changed.

The manual **Python distribution proof** workflow can create that proof for the
commit resolved from a chosen ref. It has repository-read permission only. The
tagged candidate scan creates and verifies a fresh proof in the same workflow
run. Neither path publishes an image or gives an operator a supported way to
build one.

CI also records CPython as a top-level runtime component. The evidence binds
the interpreter to exact platform identity files and retains the pinned build
recipe, source archive, source-carried license, and historical ineffective
Python `RECORD` ownership. Greenlet also has closed-world wheel, source,
component, and notice coverage on both platforms. MarkupSafe has exact wheel,
sdist, and single-payload coverage, with explicit empty SBOM and component
sets. Five other native-wheel owners remain incomplete, so an SBOM and
provenance alone do not satisfy the release contract.

A future deployment procedure must name all of these values before the steps
below become runnable:

- image repository and platform digest
- source revision
- application-wheel and selection-record digests
- signature and provenance verification commands
- platform-specific notices and corresponding-source archive
- chart source from the same reviewed release.

The [runtime base image decision](../explanation/runtime-base.md) records the
selected base, architecture evidence, vulnerability dispositions, update
contract, and residual risk. The
[container evidence release contract](../reference/container-evidence-release-contract.md)
defines what a future release must deliver.

## Prerequisites for a future deployment

Before scheduling a deployment, obtain:

- a supported Extra CODEOWNERS image, verified and pinned by platform digest
- the exact chart source associated with that image
- a GitHub App with the
  [required permissions and events](../reference/github-permissions.md)
- a public HTTPS origin with a valid certificate
- PostgreSQL with hostname-verified TLS, or an operator-controlled local proxy
  or Unix socket
- tested PostgreSQL backups and a database credential restricted to this
  service
- a secret manager for the App private key and webhook secret
- outbound HTTPS access to the configured GitHub API
- reliable UTC clock synchronization on every node
- access to the health endpoints, logs, and Prometheus metrics.

Clock accuracy matters because GitHub App JSON Web Tokens, setup-state expiry,
and database leases use wall-clock time.

Use SQLite only for a single-process development installation. It is not a
production queue.

## Provision PostgreSQL

Create one database and one role for Extra CODEOWNERS. Let that role own only
the application database; don't grant PostgreSQL cluster administration or
access to unrelated databases.

Use a SQLAlchemy URL through the psycopg driver:

```text
postgresql+psycopg://DB_USER:DB_PASSWORD@DB_HOST:5432/DB_NAME?sslmode=verify-full
```

Replace every uppercase placeholder and percent-encode reserved characters in
URL components. Treat the complete URL as a secret.

Keep `sslmode=verify-full` for a remote database. Add provider CA options
such as `sslrootcert` when needed. Extra CODEOWNERS rejects
`sslmode=require` and `sslmode=verify-ca` because neither verifies the
database hostname.

The effective libpq route decides whether a connection is local. A query-string
`host` overrides the URL authority. Any `hostaddr` or `service`
override requires `verify-full`, even if the authority looks local. Only
`localhost`, `127.0.0.1`, `::1`, a Unix-socket path, or an
omitted host may use an operator-controlled local transport without TLS. You
must authenticate and secure that proxy's upstream connection.

Normal service startup checks the exact Alembic head and table structure. It
never creates or changes schema. Follow
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
needed to change this schema. Never mount the GitHub private key or webhook
secret into the migration Job.

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

Inject the database URL through the platform's secret mechanism.

## Configure the process

Set at least these values:

```text
EXTRA_CODEOWNERS_ENVIRONMENT=production
EXTRA_CODEOWNERS_GITHUB_APP_ID=123456
EXTRA_CODEOWNERS_GITHUB_PRIVATE_KEY_FILE=/run/secrets/github-private-key
EXTRA_CODEOWNERS_GITHUB_WEBHOOK_SECRET_FILE=/run/secrets/github-webhook-secret
EXTRA_CODEOWNERS_DATABASE_URL=postgresql+psycopg://DB_USER:DB_PASSWORD@DB_HOST:5432/DB_NAME?sslmode=verify-full
EXTRA_CODEOWNERS_WORKER_RETRY_MAX_SECONDS=60
EXTRA_CODEOWNERS_WEBHOOK_DELIVERY_RETENTION_DAYS=30
```

Replace the App ID and database placeholders. Keep
`EXTRA_CODEOWNERS_ALLOW_INSECURE_CHANGES=false`.

Setup mode is disabled by default. Keep it off after App registration. Set
`EXTRA_CODEOWNERS_PUBLIC_URL` only for a separate setup process, and use an
HTTPS origin.

Production startup rejects:

- SQLite and every non-PostgreSQL database URL
- remote PostgreSQL without `sslmode=verify-full`
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
Manifest conversion code is sensitive. With setup disabled, `/setup` and
`/setup/complete` return `404`. A callback request that includes
its required `code` and `state` parameters also returns `404`.

Keep `/metrics`, `/health/live`, `/health/ready`, and
`/setup` behind operator-controlled routing. If the proxy cannot route by
path, require network or proxy authentication everywhere except the webhook.

## Verify the deployment

Run these checks from the orchestrator network. Replace the example hostname
with an operator-only endpoint:

```bash
curl --fail-with-body https://operator-endpoint.example.com/health/live
curl --fail-with-body https://operator-endpoint.example.com/health/ready
```

Both requests must return HTTP 200. If the instance runs background work,
confirm `worker` and `reconciler` are `true` in both responses.
Also confirm that `EXTRA_CODEOWNERS_WORKER_ENABLED` and
`EXTRA_CODEOWNERS_RECONCILE_ENABLED` are true; the health payload treats
an intentionally disabled task as healthy.
Confirm the metrics scraper can read `/metrics` and that
`extra_codeowners_insecure_changes_enabled` is `0`.

After reconciliation runs, verify that
`extra_codeowners_reconciliations_total{result="success"}` increased and
`extra_codeowners_reconciliation_last_success_timestamp_seconds` contains a
recent Unix timestamp.

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

If you have a previously verified supported image, compare the current database
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

No project-supported previous image exists today. If you don't have a
previously verified compatible image, keep native code-owner enforcement in
place and preserve the database and sanitized logs for investigation.

The Helm chart runs a bounded pre-upgrade migration Job and uses a `Recreate`
Deployment strategy. The old process may remain active while the hook runs,
but old and new application pods do not overlap after the hook. Expect a short
webhook interruption. GitHub does not automatically redeliver failed
deliveries, so inspect and redeliver them after readiness returns. Then confirm
that reconciliation is converging every open pull request.

Keep one replica and `Recreate` until you have tested the selected versions,
database schema, leases, and termination behavior together. Use
`charts/extra-codeowners/README.md` from the same reviewed checkout;
don't jump to a mutable default-branch copy.

## Planned release artifacts

After issues #18, #25, #28, and #32 close and the evidence path passes review,
the intended semantic-version release contains:

- a signed multi-architecture image at
  `ghcr.io/stampbot/extra-codeowners:VERSION`
- a signed OCI chart at
  `oci://ghcr.io/stampbot/charts/extra-codeowners`
- Python wheel and source distributions
- provenance and SBOM attestations
- signed notices and corresponding-source evidence for each platform digest.

A workflow file is not evidence that an artifact was published. Verify every
future artifact in GHCR or the GitHub release before using it.

Environment-specific chart upgrade evidence and a reproducible Google Cloud
deployment guide are still planned. Their workload-identity behavior will be
documented from published artifacts, not inferred from source.
