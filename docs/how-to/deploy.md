# Deploy the GitHub App service

Extra CODEOWNERS has no supported production release or hosted service. The
`main` publication job has been removed, and tagged publication is blocked
while two container source-completeness gaps, handoff of the selected build
proof, and publication isolation remain incomplete. The current Dockerfile
requires the application proof selected from both architectures, but no
supported release or ad-hoc path provides that proof to an operator. You cannot
complete this guide today.

The remaining sections record the runtime requirements for the future supported
image path. Don't improvise an image input or let the current check authorize
production merges.

## Prerequisites

You need:

- a supported Extra CODEOWNERS image, pinned by platform digest and built from
  the reviewed application proof; no such image exists yet
- the exact chart source that belongs to that image version
- a GitHub App with the [documented permissions and events](../reference/github-permissions.md)
- a public HTTPS origin with a valid certificate
- PostgreSQL with hostname-verified TLS for remote connections, or an operator-controlled local proxy or Unix socket
- PostgreSQL backups and restricted database credentials
- a secret manager for the App private key and webhook secret
- outbound HTTPS access to the configured GitHub API
- reliable UTC clock synchronization on every service node, which GitHub App JWTs, setup-state expiry, and durable leases need
- monitoring access to readiness and Prometheus metrics.

Use SQLite only for a single-process development installation. It isn't a production durable queue.

## 1. Obtain a supported image (currently blocked)

An older public `ghcr.io/stampbot/extra-codeowners:main` image may still exist.
It predates the publication block, is unsupported, and does not have complete
CPython, native-wheel, embedded-SBOM, or historical `RECORD` evidence. Do not
deploy or mirror it.

Pull-request CI builds a hash-pinned PEP 517 proof twice on each native
architecture, selects one byte-identical five-file proof, and passes it to the
Dockerfile as the read-only `verified-python` build context. The Dockerfile
also requires the exact source revision, application-wheel SHA-256, and
selection-record SHA-256. It fails closed when any input is absent or changed.

Issue [`#32`](https://github.com/stampbot/extra-codeowners/issues/32) tracks a
bounded, authenticated way for release and ad-hoc builds to consume that
selected proof. Until that path exists, don't replace it with a generic ZIP
extractor, an unverified wheel, empty build arguments, or a build of the project
from the ambient Docker context. Stop here.

Once issue #32 closes, this section must identify the exact supported image
reference, platform digest, source revision, wheel digest, selection-record
digest, signature, and provenance verification command before the deployment
steps below become runnable.

The checked-in tag-release workflow is structurally disabled before every
publication job. Source-completeness issue
[`#18`](https://github.com/stampbot/extra-codeowners/issues/18) and
privilege-separation issue
[`#28`](https://github.com/stampbot/extra-codeowners/issues/28), plus
build-proof issue
[`#32`](https://github.com/stampbot/extra-codeowners/issues/32), must all be
resolved before it can publish a versioned image. A policy approval change
alone cannot enable it.

Issue #18 covers CPython top-level normalization plus native-wheel and
embedded-SBOM component/source expansion. Current candidates also retain
historical ineffective Python `RECORD` replay as attribution evidence.
The [runtime base image decision](../explanation/runtime-base.md) records the
selected upstream image, architecture evidence, vulnerability dispositions,
update contract, and residual risk.

A future tagged release must also provide a platform-specific notice and source
archive that satisfies the
[container evidence release contract](../reference/container-evidence-release-contract.md).
Image provenance and a software bill of materials do not replace that archive.
Current pull-request CI evidence is unsigned and intended only for maintainer
review; it explicitly reports both remaining source-completeness gaps.

## 2. Provision durable state

Create a dedicated PostgreSQL database and role. Give the role ownership only of the Extra CODEOWNERS database; don't grant cluster-administrator or unrelated-database privileges.

Supply a SQLAlchemy URL through the psycopg driver:

```text
postgresql+psycopg://DB_USER:DB_PASSWORD@DB_HOST:5432/DB_NAME?sslmode=verify-full
```

Replace every uppercase placeholder and percent-encode reserved characters in URL components. Treat the complete URL as a secret.

For a remote database, keep `sslmode=verify-full`. Add provider CA parameters such as `sslrootcert` when needed. Extra CODEOWNERS rejects `require` and `verify-ca` because neither verifies the database hostname. Query routing can't bypass this rule: `host` takes precedence over the URL authority, and a `hostaddr` or `service` override requires `verify-full`.

Before first startup or every upgrade, follow the [database upgrade, backup,
restore, and rollback procedure](upgrade.md). Normal service startup validates
the exact migration head and table shape but never creates or changes schema.

The service stops a database operation after these fixed budgets:

- 3 seconds to connect to PostgreSQL
- 2 seconds to obtain a connection from the application pool
- 3 seconds for an ordinary statement.

The separate migration command waits at most 60 seconds for its PostgreSQL
advisory lock by default and limits each migration statement to 60 seconds.
The Helm migration Job has separate Secret, environment, volume, mount, and
ServiceAccount values. Give it the database URL and schema-change authority;
do not attach the GitHub App private key or webhook secret.

Test the entire path from service to database, including any proxy, under expected peak latency and concurrency. If normal operation approaches those limits, don't use this service as merge infrastructure. A timeout blocks or retries work; it never infers approval.

## 3. Mount secrets

Don't bake secrets into the image, put them in command-line arguments, or commit them to an environment file.

Mount the GitHub App private key and webhook secret as read-only files. Only the container's runtime user should be able to read them. Configure:

```text
EXTRA_CODEOWNERS_GITHUB_PRIVATE_KEY_FILE=/run/secrets/github-private-key
EXTRA_CODEOWNERS_GITHUB_WEBHOOK_SECRET_FILE=/run/secrets/github-webhook-secret
```

Supply the database URL through the platform's secret-injection mechanism.

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

Replace the example App ID and database placeholders. Keep `EXTRA_CODEOWNERS_ALLOW_INSECURE_CHANGES=false`. Leave setup mode disabled after App registration; it is disabled by default. Set `EXTRA_CODEOWNERS_PUBLIC_URL` only for a separate setup process, and use HTTPS.

Production startup rejects:

- SQLite and every other non-PostgreSQL database URL
- a non-local database connection without `sslmode=verify-full`
- a webhook secret shorter than 32 UTF-8 bytes
- a non-HTTPS GitHub API origin.

An effective `localhost`, `127.0.0.1`, `::1`, or Unix-socket database proxy may omit `sslmode`. A `hostaddr` or `service` override never qualifies for this exception. Authenticate and protect the local proxy's upstream connection yourself.

Choose a delivery-ID retention period that covers GitHub redelivery and your incident-investigation window. The elected reconciler prunes expired IDs. Keep reconciliation enabled, or provide a separately reviewed retention procedure. Once pruned, an old delivery ID may be accepted again, but it can only coalesce a fresh evaluation that fetches current GitHub evidence.

Evaluation and authority failures retry indefinitely because abandoned revocation work could leave a stale success visible. `EXTRA_CODEOWNERS_WORKER_RETRY_MAX_SECONDS` caps the normal exponential delay, not the attempt count. GitHub rate-limit responses use a separate bounded `Retry-After` delay from the provider. Alert when the pending queue stays above its normal baseline and when failure logs repeat. Don't use manual requeue as normal recovery.

See the [configuration reference](../reference/configuration.md#runtime-settings) for every setting and bound.

## 5. Configure ingress

Route public GitHub traffic only to `POST /webhooks/github`. Preserve the raw body and these headers:

- `X-Hub-Signature-256`
- `X-GitHub-Event`
- `X-GitHub-Delivery`.

Apply current TLS protocols and disable response caching. Limit request bodies to 10 MiB before buffering. You may use a lower limit only after testing legitimate delivery sizes. Rate-limit requests without blocking normal GitHub bursts or redeliveries.

Disable query-string logging for `/setup/callback` because its one-use App Manifest conversion code is sensitive. Keep setup disabled during normal operation so that route returns `404`.

Keep `/metrics`, `/health/live`, `/health/ready`, and `/setup` on operator-controlled routes. If the ingress can't route by path, require network or proxy authentication everywhere except `/webhooks/github`.

## 6. Verify before receiving production events

Treat these as deployment acceptance checks. Passing them doesn't resolve the commit-scoped Check Run limitation, so they don't make this deployment suitable for production merge authorization.

From the orchestrator's network, verify liveness and readiness:

```bash
curl --fail-with-body https://operator-endpoint.example.com/health/live
curl --fail-with-body https://operator-endpoint.example.com/health/ready
```

Confirm that each health response reports `worker` and `reconciler` as `true`, and that the deployment enables both tasks. Verify that the metrics scraper can read `/metrics` and `extra_codeowners_insecure_changes_enabled` is `0`.

After the first reconciliation, confirm that `extra_codeowners_reconciliations_total{result="success"}` increased. Verify that `extra_codeowners_reconciliation_last_success_timestamp_seconds` contains a recent Unix timestamp.

In a disposable repository covered by test policy, open a pull request that changes an owned path. In the App's **Advanced** settings, confirm that **Recent deliveries** shows a successful `pull_request` delivery for the `opened` action. Verify that the repository receives a check from the expected App source. Redeliver the same delivery and confirm that deduplication does not create duplicate work. Complete every negative test in [Prepare repository rules](prepare-repository-rules.md#3-verify-the-conjunction) before changing a production ruleset.

## Roll back or mitigate

If a rollout produces incorrect results and the operator has a previously
verified supported image that is compatible with the current database:

1. Stop routing new webhook traffic to the bad version.
2. Compare the current database head with the previous artifact's required
   head.
3. If the head is unchanged, restore the previous image by its recorded digest
   and run its `database check`.
4. If the head changed, restore native **Require review from Code Owners** on
   every affected repository, stop every application process, preserve the
   failed database, and restore the verified pre-migration backup into a new
   empty database. Validate it with the previous artifact before routing
   traffic.
5. Redeliver deliveries that the service never accepted. Let pending work
   retry, and let reconciliation enqueue open pull requests that have no
   existing job.
6. Verify current-head checks in a test repository.

Every Alembic head change requires the restore in step 4. An additive physical
change does not let an old exact-head artifact use the migrated database.

No project-supported previous image currently exists. If the operator has no
previously verified image, or that image cannot safely use the current
database, restore native **Require review from Code Owners** on every affected
repository. Only then remove the Extra CODEOWNERS required check. Preserve the
database and logs for investigation.

The Helm chart runs a bounded pre-upgrade migration Job and uses a `Recreate`
Deployment strategy. The old process may remain active while the hook runs, so
migrations avoid destructive or unbounded operations during that interval.
This does not make the old artifact valid at the new head. Recreate prevents
old and new application pods from overlapping after the hook, but briefly
interrupts webhook processing. GitHub doesn't automatically redeliver failed
webhooks. Once the service is ready, inspect failed deliveries, redeliver them
manually, and confirm that scheduled reconciliation is converging open pull
requests.

Keep one replica. Don't switch to `RollingUpdate` until you've tested the
versions, schema, and lease behavior together. Follow
`charts/extra-codeowners/README.md` from the same exact reviewed checkout for
the complete Kubernetes procedure; do not jump to a mutable default-branch
copy.

## Release and planned supported paths

The initial Helm chart source lives at `charts/extra-codeowners`. Tagged
publication is currently blocked by source-completeness issue `#18`,
privilege-separation issue `#28`, and build-proof issue `#32`; the workflow
cannot publish the items below. After all three are resolved and the evidence
pipeline is reviewed, the intended exact semantic-version release contract is:

- a signed multi-architecture image at `ghcr.io/stampbot/extra-codeowners:<version>`
- a signed OCI chart at `oci://ghcr.io/stampbot/charts/extra-codeowners`, using the release version
- Python wheel and source artifacts
- build provenance and software-bill-of-material attestations
- signed, attested notice and corresponding-source evidence for each platform
  digest.

Workflow source does not prove an artifact was published, especially while its
publication jobs are unreachable. Confirm each artifact on the registry or
GitHub release after a successful future release. Until the repository
announces a supported release, none exists.

Environment-specific chart upgrade evidence and a reproducible Google Cloud
deployment guide remain planned. Their workload-identity behavior will be
documented from published artifacts rather than inferred here.
