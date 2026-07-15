# Deploy the GitHub App service

Extra CODEOWNERS has no supported production release or hosted service. The
`main` publication job has been removed, and tagged publication is blocked
while three container source-completeness gaps, hash-pinned build isolation,
and publication isolation remain incomplete. Use this guide only for a
disposable source-built review deployment, and don't let the current check
authorize production merges.

## Prerequisites

You need:

- a reviewed Extra CODEOWNERS commit
- Docker for a local source build
- a GitHub App with the [documented permissions and events](../reference/github-permissions.md)
- a public HTTPS origin with a valid certificate
- PostgreSQL with hostname-verified TLS for remote connections, or an operator-controlled local proxy or Unix socket
- PostgreSQL backups and restricted database credentials
- a secret manager for the App private key and webhook secret
- outbound HTTPS access to the configured GitHub API
- reliable UTC clock synchronization on every service node, which GitHub App JWTs, setup-state expiry, and durable leases need
- monitoring access to readiness and Prometheus metrics.

Use SQLite only for a single-process development installation. It isn't a production durable queue.

## 1. Build the reviewed source

An older public `ghcr.io/stampbot/extra-codeowners:main` image may still exist.
It predates the publication block, is unsupported, and does not have complete
CPython, native-wheel, embedded-SBOM, or historical `RECORD` evidence. Do not
deploy or mirror it.

The current `[build-system]` dependency range is not hash-locked by `uv.lock`.
Issue [`#32`](https://github.com/stampbot/extra-codeowners/issues/32) must pin
the isolated PEP 517 environment and bind installation to its exact wheel. This
source build is suitable only for disposable review; it is not reproducible
distribution evidence.

The Dockerfile and source at that commit execute during the build, with network
access to base-image and package registries. Build only on a disposable host or
VM with no production credentials, cloud metadata access, mounted secrets, or
Docker access to other workloads. Destroy the builder after recording the
result. Build from a fresh detached worktree at one explicit full commit. Set
`TARGET_ARCH` to the architecture of the node that will run this image. This
procedure requires a native builder of that architecture; QEMU and `binfmt`
emulation are outside its reviewed boundary:

```bash
set -euo pipefail
export REPOSITORY_ROOT="$(git rev-parse --show-toplevel)"
export SOURCE_REVISION='REPLACE_WITH_REVIEWED_40_CHARACTER_COMMIT'
export TARGET_ARCH='amd64'
export GIT_NO_REPLACE_OBJECTS=1

case "$SOURCE_REVISION" in (*[!0-9a-f]*|'') exit 1 ;; esac
test "${#SOURCE_REVISION}" -eq 40
case "$TARGET_ARCH" in (amd64|arm64) ;; (*) exit 1 ;; esac
case "$(docker info --format '{{.Architecture}}')" in
  (amd64|x86_64) BUILDER_ARCH=amd64 ;;
  (arm64|aarch64) BUILDER_ARCH=arm64 ;;
  (*) exit 1 ;;
esac
test "$BUILDER_ARCH" = "$TARGET_ARCH"
test "$(git -C "$REPOSITORY_ROOT" rev-parse --verify "${SOURCE_REVISION}^{commit}")" = \
  "$SOURCE_REVISION"

WORKTREE_PARENT="$(mktemp -d)"
WORKTREE="$WORKTREE_PARENT/source"
cleanup() {
  git -C "$REPOSITORY_ROOT" worktree remove --force "$WORKTREE" \
    >/dev/null 2>&1 || true
  rm -rf -- "$WORKTREE_PARENT"
}
trap cleanup EXIT

git -C "$REPOSITORY_ROOT" worktree add --detach "$WORKTREE" "$SOURCE_REVISION"
test "$(git -C "$WORKTREE" rev-parse HEAD)" = "$SOURCE_REVISION"
test -z "$(git -C "$WORKTREE" -c core.fsmonitor=false \
  status --porcelain=v1 --untracked-files=all)"

IMAGE="extra-codeowners:review-${SOURCE_REVISION}-${TARGET_ARCH}"
docker buildx build \
  --platform "linux/${TARGET_ARCH}" \
  --build-arg "VCS_REF=${SOURCE_REVISION}" \
  --build-arg VERSION=0.0.0-review \
  --load \
  --tag "$IMAGE" \
  "$WORKTREE"

test -z "$(git -C "$WORKTREE" -c core.fsmonitor=false \
  status --porcelain=v1 --untracked-files=all)"
IMAGE_CONFIG_DIGEST="$(docker image inspect --format '{{.Id}}' "$IMAGE")"
IMAGE_SOURCE_REVISION="$(docker image inspect \
  --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$IMAGE")"
IMAGE_ARCHITECTURE="$(docker image inspect --format '{{.Architecture}}' "$IMAGE")"
[[ "$IMAGE_CONFIG_DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]]
test "$IMAGE_SOURCE_REVISION" = "$SOURCE_REVISION"
test "$IMAGE_ARCHITECTURE" = "$TARGET_ARCH"
printf 'config=%s source=%s architecture=%s\n' \
  "$IMAGE_CONFIG_DIGEST" "$IMAGE_SOURCE_REVISION" "$IMAGE_ARCHITECTURE"
```

Record the resulting local image configuration digest and source commit. A
local build is not signed, attested, or approved for redistribution merely
because repository workflows contain future publication steps. Load it
directly into a disposable local cluster when possible. If your cluster needs a
registry, use an access-restricted, non-public temporary repository. Do not
grant anonymous pull access. Delete the deployment and every registry copy of
the review image after testing, then verify that its digest is no longer
pullable.

The checked-in tag-release workflow is structurally disabled before every
publication job. Source-completeness issue
[`#18`](https://github.com/stampbot/extra-codeowners/issues/18) and
privilege-separation issue
[`#28`](https://github.com/stampbot/extra-codeowners/issues/28), plus
build-isolation issue
[`#32`](https://github.com/stampbot/extra-codeowners/issues/32), must all be
resolved before it can publish a versioned image. A policy approval change
alone cannot enable it.

Issue #18 covers CPython top-level normalization, native-wheel and embedded-SBOM
component/source expansion, and historical ineffective Python `RECORD` replay.
The [runtime base image decision](../explanation/runtime-base.md) records the
selected upstream image, architecture evidence, vulnerability dispositions,
update contract, and residual risk.

A future tagged release must also provide a platform-specific notice and source
archive that satisfies the
[container evidence release contract](../reference/container-evidence-release-contract.md).
Image provenance and a software bill of materials do not replace that archive.
Current pull-request CI evidence is unsigned and intended only for maintainer
review; it explicitly reports all three source-completeness gaps.

## 2. Provision durable state

Create a dedicated PostgreSQL database and role. Give the role ownership only of the Extra CODEOWNERS database; don't grant cluster-administrator or unrelated-database privileges.

Supply a SQLAlchemy URL through the psycopg driver:

```text
postgresql+psycopg://DB_USER:DB_PASSWORD@DB_HOST:5432/DB_NAME?sslmode=verify-full
```

Replace every uppercase placeholder and percent-encode reserved characters in URL components. Treat the complete URL as a secret.

For a remote database, keep `sslmode=verify-full`. Add provider CA parameters such as `sslrootcert` when needed. Extra CODEOWNERS rejects `require` and `verify-ca` because neither verifies the database hostname. Query routing can't bypass this rule: `host` takes precedence over the URL authority, and a `hostaddr` or `service` override requires `verify-full`.

Before upgrading, back up the database and review release notes for schema compatibility. A migration and rollback contract will be added before the first supported release.

The service stops a database operation after these fixed budgets:

- 3 seconds to connect to PostgreSQL
- 2 seconds to obtain a connection from the application pool
- 3 seconds for an ordinary statement.

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
recorded source-built review image that is compatible with the current
database:

1. Stop routing new webhook traffic to the bad version.
2. Restore the previous image by its recorded digest without rolling back the database.
3. Confirm the previous version's readiness and queue processing.
4. Redeliver deliveries that the service never accepted. Let pending work retry, and let reconciliation enqueue open pull requests that have no existing job.
5. Verify current-head checks in a test repository.

No project-supported previous image currently exists. If the operator has no
previously recorded source build, or that build cannot safely use the current
database, restore native **Require review from Code Owners** on every affected
repository. Only then remove the Extra CODEOWNERS required check. Preserve the
database and logs for investigation.

The Helm chart uses a `Recreate` Deployment strategy because this pre-1.0 service has no mixed-version database compatibility contract. This prevents old and new versions from running together, but briefly interrupts webhook processing. GitHub doesn't automatically redeliver failed webhooks. Once the service is ready, inspect failed deliveries, redeliver them manually, and confirm that scheduled reconciliation is converging open pull requests.

Keep one replica. Don't switch to `RollingUpdate` until you've tested the
versions, schema, and lease behavior together. Follow
`charts/extra-codeowners/README.md` from the same exact reviewed checkout for
the complete Kubernetes procedure; do not jump to a mutable default-branch
copy.

## Release and planned supported paths

The initial Helm chart source lives at `charts/extra-codeowners`. Tagged
publication is currently blocked by source-completeness issue `#18`,
privilege-separation issue `#28`, and build-isolation issue `#32`; the workflow
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

Tested chart upgrade guarantees and a reproducible Google Cloud deployment guide remain planned. Their workload-identity behavior will be documented from published artifacts rather than inferred here.
