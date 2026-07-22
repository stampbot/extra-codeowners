# Extra CODEOWNERS Helm chart

This chart deploys the self-hosted Extra CODEOWNERS GitHub App service. The
repository contains chart source only.

> [!CAUTION]
> There is no supported image, OCI chart, production release, hosted service,
> or Marketplace Action. Do not install the old
> `ghcr.io/stampbot/extra-codeowners:main` image or use this chart to
> authorize production merges. Keep GitHub's native **Require review from Code
> Owners** rule in place.

The current Check Run design has a documented commit-to-pull-request
inheritance window, tracked in
[issue #1](https://github.com/stampbot/extra-codeowners/issues/1). The release
pipeline is also blocked by
[source-completeness issue #18](https://github.com/stampbot/extra-codeowners/issues/18),
[immutable-release issue #25](https://github.com/stampbot/extra-codeowners/issues/25),
[publication-isolation issue #28](https://github.com/stampbot/extra-codeowners/issues/28),
and [application build-proof issue #32](https://github.com/stampbot/extra-codeowners/issues/32).

The procedures below record the chart's operator contract for review and
future releases. They are not a supported installation path today.

Read the
[deployment guide](https://extra-codeowners.readthedocs.io/en/latest/how-to/deploy/),
[configuration reference](https://extra-codeowners.readthedocs.io/en/latest/reference/configuration/),
and [upgrade procedure][upgrade] before evaluating the chart.

## Compatibility and prerequisites

| Requirement | Contract |
| --- | --- |
| Kubernetes | 1.27 or later, enforced by `Chart.yaml` |
| Helm | 3.19.0, the version pinned and tested by this repository |
| Application image | A future supported image pinned by platform digest |
| Database | PostgreSQL configured under the application's production transport rules |
| GitHub | An installed Extra CODEOWNERS App |
| Ingress | Public HTTPS access to only the webhook endpoint |

You also need:

- registry access from the cluster, with a repository-scoped read-only pull
  credential when required
- separate Kubernetes Secrets for runtime settings, the database URL, and
  mounted GitHub credential files
- PostgreSQL backups with a tested isolated restore
- an ingress controller and TLS issuer, or equivalent externally managed
  routing.

The chart does not create application Secrets, PostgreSQL, an ingress
controller, TLS certificates, backups, or restore automation.

## What the chart creates

With default values, Helm renders:

- a bounded `pre-install,pre-upgrade` migration Job
- one `Recreate` Deployment
- one ClusterIP Service
- a dedicated runtime ServiceAccount
- a NetworkPolicy that selects both application and migration pods
- a Helm test Pod that checks `/health/live`.

The application and migration pods set `enableServiceLinks: false`.
Without that setting, Kubernetes can inject an
`EXTRA_CODEOWNERS_PORT` Service variable containing a URL, which conflicts
with the application's integer port setting. Use Kubernetes DNS for service
discovery.

The application does not call the Kubernetes API, so the chart creates no
Role, ClusterRole, or binding. Its dedicated ServiceAccount has token
automounting disabled. The migration Job also disables token automounting; set
`migrations.serviceAccountName` only when an external database identity
needs a particular pre-existing ServiceAccount.

The chart sets `EXTRA_CODEOWNERS_ENVIRONMENT=production`. The runtime
Secret must replace the image's development-only SQLite default with a
production PostgreSQL URL. Chart validation prevents `extraEnv` from
overriding the environment or insecure-mode settings.

Security-sensitive defaults also run as UID and GID 65532, drop every Linux
capability, disable privilege escalation, use a read-only root filesystem, and
select the runtime-default seccomp profile. The Deployment uses
`Recreate`, the insecure override is off, and credential inputs remain
outside chart-managed resources.

## Obtain an image (currently blocked)

The Dockerfile does not build the application from its ambient source tree. It
requires a read-only `verified-python` context containing the exact
five-file Python distribution proof selected across `amd64` and `arm64`.
It also checks the source revision, application-wheel SHA-256, and
selection-record SHA-256.

Pull-request CI supplies and verifies those inputs. No supported operator path
does. Do not replace the proof with a generic artifact extractor, an
unverified wheel, empty build arguments, or a build from the ambient Docker
context.

Until the project publishes an image-verification procedure, treat the
remaining sections as the chart's future operator contract, not as a current
installation path. That procedure must identify the repository, platform
digest, source revision, wheel digest, selection-record digest, signature,
provenance, notices, and corresponding source. When a supported image exists,
use the central
[deployment guide](https://extra-codeowners.readthedocs.io/en/latest/how-to/deploy/)
and [upgrade procedure][upgrade] for task steps; use this README for
chart-specific inputs, defaults, and review constraints.

## Prepare a future source-chart installation

The examples use `extra-codeowners` for both the Helm release and
namespace. Run them in a POSIX-compatible Bash shell from an
operator-controlled cluster-administration host.

Keep the reviewed source in a clean detached worktree. Define the future image
coordinates and verify the checkout before creating cluster resources:

```bash
set -euo pipefail
umask 077

export SOURCE_REVISION='REPLACE_WITH_REVIEWED_40_CHARACTER_COMMIT'
export CHART_SOURCE='/path/to/clean-detached-extra-codeowners-worktree'
export IMAGE_REPOSITORY='registry.example.com/stampbot/extra-codeowners'
export IMAGE_DIGEST='sha256:REPLACE_WITH_64_LOWERCASE_HEX_CHARACTERS'
export TARGET_ARCH='amd64'
export GIT_NO_REPLACE_OBJECTS=1

printf '%s\n' "$SOURCE_REVISION" | grep -Eq '^[0-9a-f]{40}$'
printf '%s\n' "$IMAGE_DIGEST" | grep -Eq '^sha256:[0-9a-f]{64}$'
case "$TARGET_ARCH" in
  amd64|arm64) ;;
  *) exit 1 ;;
esac

test "$(git -C "$CHART_SOURCE" rev-parse \
  --verify "$SOURCE_REVISION^{commit}")" = "$SOURCE_REVISION"
test "$(git -C "$CHART_SOURCE" rev-parse HEAD)" = "$SOURCE_REVISION"
test -z "$(git -C "$CHART_SOURCE" -c core.fsmonitor=false \
  status --porcelain=v1 --untracked-files=all)"
```

Every command must exit zero. The image digest must belong to
`linux/$TARGET_ARCH`, and the chart source must belong to the same reviewed
release.

## Create narrowly scoped Secrets

Prepare four files outside version control with mode `0600` or stricter:

- `RUNTIME_ENV_FILE` contains non-database runtime settings, including the App ID
- `DATABASE_ENV_FILE` contains only the database URL
- `GITHUB_PRIVATE_KEY_FILE` contains the App PEM private key
- `GITHUB_WEBHOOK_SECRET_FILE` contains the webhook secret.

Use a webhook secret generated for this App. After the application removes one
terminal line ending, the value must contain at least 32 bytes and match the
secret configured in GitHub.

The runtime file must include the numeric App ID and these mounted paths:

```text
EXTRA_CODEOWNERS_GITHUB_APP_ID=REPLACE_WITH_NUMERIC_APP_ID
EXTRA_CODEOWNERS_GITHUB_PRIVATE_KEY_FILE=/run/secrets/extra-codeowners/github-private-key
EXTRA_CODEOWNERS_GITHUB_WEBHOOK_SECRET_FILE=/run/secrets/extra-codeowners/github-webhook-secret
```

The database file contains:

```text
EXTRA_CODEOWNERS_DATABASE_URL=postgresql+psycopg://DB_USER:DB_PASSWORD@DB_HOST:5432/DB_NAME?sslmode=verify-full
```

Replace the App ID and every database placeholder. Percent-encode reserved URL
characters. For remote PostgreSQL, keep `sslmode=verify-full` and add the
provider's CA settings when needed. Treat the complete URL as a secret.

Export only file paths:

```bash
export RUNTIME_ENV_FILE="$HOME/.config/extra-codeowners/runtime.env"
export DATABASE_ENV_FILE="$HOME/.config/extra-codeowners/database.env"
export GITHUB_PRIVATE_KEY_FILE="$HOME/.config/extra-codeowners/private-key.pem"
export GITHUB_WEBHOOK_SECRET_FILE="$HOME/.config/extra-codeowners/webhook-secret"

test -r "$RUNTIME_ENV_FILE"
test -r "$DATABASE_ENV_FILE"
test -r "$GITHUB_PRIVATE_KEY_FILE"
test -r "$GITHUB_WEBHOOK_SECRET_FILE"
```

Create the namespace before any Secret:

```bash
kubectl create namespace extra-codeowners \
  --dry-run=client -o yaml | kubectl apply -f -
```

If the image registry requires authentication, create a pull Secret with a
dedicated read-only credential:

```bash
export REGISTRY_HOST='registry.example.com'
export REGISTRY_PULL_USER='REPLACE_WITH_READ_ONLY_PULL_USER'
test -n "$REGISTRY_PULL_TOKEN"

PULL_DOCKER_CONFIG="$(mktemp -d)"
cleanup_pull_config() {
  docker --config "$PULL_DOCKER_CONFIG" logout "$REGISTRY_HOST" \
    >/dev/null 2>&1 || true
  rm -rf -- "$PULL_DOCKER_CONFIG"
  unset REGISTRY_PULL_TOKEN
}
trap cleanup_pull_config EXIT

printf '%s' "$REGISTRY_PULL_TOKEN" |
  docker --config "$PULL_DOCKER_CONFIG" login "$REGISTRY_HOST" \
    --username "$REGISTRY_PULL_USER" --password-stdin

kubectl --namespace extra-codeowners create secret generic \
  extra-codeowners-registry \
  --type=kubernetes.io/dockerconfigjson \
  --from-file=.dockerconfigjson="$PULL_DOCKER_CONFIG/config.json"

cleanup_pull_config
trap - EXIT
```

The namespaced Secret keeps the pull credential so pods can reschedule. Remove
its local plaintext source after creation. To rotate it, replace the Secret,
prove a new pod can pull, and then revoke the old credential.

Create separate runtime, database, and GitHub Secrets:

```bash
kubectl --namespace extra-codeowners create secret generic \
  extra-codeowners-runtime \
  --from-env-file="$RUNTIME_ENV_FILE"
kubectl --namespace extra-codeowners create secret generic \
  extra-codeowners-database \
  --from-env-file="$DATABASE_ENV_FILE"
kubectl --namespace extra-codeowners create secret generic \
  extra-codeowners-github \
  --from-file=github-private-key="$GITHUB_PRIVATE_KEY_FILE" \
  --from-file=github-webhook-secret="$GITHUB_WEBHOOK_SECRET_FILE"
```

The migration Job receives only `extra-codeowners-database`. It never
inherits runtime `existingSecret`, `extraEnvFrom`,
`extraEnv`, `extraVolumes`, or `extraVolumeMounts`.

## Configure and preflight the release

Save this non-secret configuration as `deployment-values.yaml`:

```yaml
existingSecret: extra-codeowners-runtime
extraEnvFrom:
  - secretRef:
      name: extra-codeowners-database
imagePullSecrets:
  - name: extra-codeowners-registry
nodeSelector:
  kubernetes.io/arch: amd64
extraVolumes:
  - name: github-credentials
    secret:
      secretName: extra-codeowners-github
      defaultMode: 0440
extraVolumeMounts:
  - name: github-credentials
    mountPath: /run/secrets/extra-codeowners
    readOnly: true
migrations:
  existingSecret: extra-codeowners-database
```

Change `kubernetes.io/arch` to the recorded `TARGET_ARCH`. A
single-platform digest must never be scheduled on the other architecture.
If the registry permits anonymous pulls, omit `imagePullSecrets` and do
not create `extra-codeowners-registry`.

Lint and render before installation:

```bash
helm lint "$CHART_SOURCE/charts/extra-codeowners" \
  --values deployment-values.yaml \
  --set-string image.repository="$IMAGE_REPOSITORY" \
  --set-string image.digest="$IMAGE_DIGEST"

RENDERED_MANIFEST="$(mktemp)"
trap 'rm -f "$RENDERED_MANIFEST"' EXIT
helm template extra-codeowners \
  "$CHART_SOURCE/charts/extra-codeowners" \
  --namespace extra-codeowners \
  --values deployment-values.yaml \
  --set-string image.repository="$IMAGE_REPOSITORY" \
  --set-string image.digest="$IMAGE_DIGEST" \
  >"$RENDERED_MANIFEST"
test -s "$RENDERED_MANIFEST"
rm -f "$RENDERED_MANIFEST"
trap - EXIT
```

Helm validates `values.schema.json` during lint and template. Review the
rendered Deployment, migration Job, Service, ServiceAccount, and NetworkPolicy
before continuing. Secret values must not appear because the chart references
existing Secrets by name.

Never pass a secret with `--set`. Shell history and Helm release metadata
may retain it.

## Install and verify

When a supported image exists, install the reviewed image and source chart:

```bash
helm install extra-codeowners \
  "$CHART_SOURCE/charts/extra-codeowners" \
  --namespace extra-codeowners \
  --values deployment-values.yaml \
  --set-string image.repository="$IMAGE_REPOSITORY" \
  --set-string image.digest="$IMAGE_DIGEST"
```

The migration hook must complete before Helm creates the Deployment. The
application then remains unready until its GitHub and database settings are
valid.

Wait for rollout and run the live-endpoint test:

```bash
kubectl --namespace extra-codeowners rollout status \
  deployment/extra-codeowners --timeout=5m
helm test extra-codeowners --namespace extra-codeowners
kubectl --namespace extra-codeowners get \
  jobs,pods,service,serviceaccount,networkpolicy
kubectl --namespace extra-codeowners logs \
  job/extra-codeowners-migrate
```

The rollout and Helm test must exit zero. Preserve the migration Job logs with
the change record before its time-to-live expires.

The test Pod does not inherit `nodeSelector`. In a mixed-architecture
cluster, do not run `helm test` with a single-platform digest unless the
scheduler can place that Pod on `TARGET_ARCH`. The Deployment and migration
Job do inherit the configured selector.

If rollout fails, inspect events and bounded logs:

```bash
kubectl --namespace extra-codeowners describe \
  deployment/extra-codeowners
kubectl --namespace extra-codeowners logs \
  deployment/extra-codeowners --all-pods --tail=100
```

Sanitize output before sharing it. App keys, webhook secrets, installation
tokens, database URLs, and private webhook payloads must not appear in an
issue.

## Expose the webhook

Ingress requires an installed controller and TLS issuer. Replace the example
hostname, and create `extra-codeowners-tls` with a certificate valid for
that host:

```yaml
ingress:
  enabled: true
  className: nginx
  hosts:
    - host: extra-codeowners.example.com
      paths:
        - path: /webhooks/github
          pathType: Exact
  tls:
    - secretName: extra-codeowners-tls
      hosts:
        - extra-codeowners.example.com
```

Save it as `ingress-values.yaml` and apply it:

```bash
helm upgrade extra-codeowners \
  "$CHART_SOURCE/charts/extra-codeowners" \
  --namespace extra-codeowners \
  --reset-then-reuse-values \
  --values ingress-values.yaml
```

Expose only `/webhooks/github` publicly. Keep `/metrics`,
`/health/live`, `/health/ready`, and setup routes behind an
authenticated operator path or use port forwarding.

The default NetworkPolicy permits ingress to the named HTTP port from any peer,
which works with ingress controllers across common cluster layouts. Restrict
`networkPolicy.ingressFrom` when the controller namespace and pod labels
are stable.

The policy selects application and migration pod labels. The Service and
PodDisruptionBudget select only the application component. On first install,
the pre-install migration hook runs before Helm creates ordinary resources,
including this NetworkPolicy. If the first migration needs network isolation,
apply a namespace default-deny policy or equivalent before `helm install`.
On upgrade, the existing chart policy already selects the new migration pod.

## Upgrade and roll back

Complete the
[backup and isolated restore procedure][upgrade] before every upgrade. Keep
`migrations.enabled: true` unless a separate controlled process has
already applied the exact target head.

Migration defaults are:

- a 60-second PostgreSQL advisory-lock wait
- no Kubernetes retry after process failure
- a 180-second Job deadline
- a one-hour completed-Job time-to-live.

The target migration Job stops Helm before the Deployment changes if it fails.
Use migration-only Secret, environment, volume, and mount values for database
authentication or CA material. Never attach runtime App credentials.

The default `Recreate` strategy avoids overlap between old and new
application pods, but webhook processing pauses briefly. GitHub does not
automatically redeliver failed deliveries. Inspect and redeliver them after
readiness returns, then confirm reconciliation converges every open pull
request.

Before a future upgrade, obtain and verify the next supported image, record its
platform digest, and use the chart from the matching reviewed release:

```bash
helm upgrade extra-codeowners \
  "$CHART_SOURCE/charts/extra-codeowners" \
  --namespace extra-codeowners \
  --reset-then-reuse-values \
  --set-string image.repository="$IMAGE_REPOSITORY" \
  --set-string image.digest="$IMAGE_DIGEST"
kubectl --namespace extra-codeowners rollout status \
  deployment/extra-codeowners --timeout=5m
```

`--reset-then-reuse-values` starts with the new chart defaults and then
applies existing overrides. Plain `--reuse-values` can silently miss new
safety defaults. Review `helm get values` and the new `values.yaml`
before every upgrade.

If health checks fail, compare the database head with the previous artifact's
[required head][upgrade-notes]. If the head did not change and the upgrade
notes permit application rollback:

```bash
helm history extra-codeowners --namespace extra-codeowners
helm rollback extra-codeowners REVISION \
  --namespace extra-codeowners --wait
```

Replace `REVISION` with the known-good revision from `helm history`.
Helm rollback does not reverse database changes.

If the head changed, do not start the old image against the migrated database.
Restore native GitHub code-owner enforcement, stop the service, preserve the
failed database, and restore the verified backup into a new empty database.
Validate that restore with the old artifact before rolling the Deployment
back. Additive SQL does not create an exception.

## Scaling and disruption

The application serves webhooks and executes leased work in the same process.
PostgreSQL leases prevent duplicate ownership, but high availability has not
been validated.

Use these settings until your environment passes concurrency and failure
tests:

```yaml
replicaCount: 1
autoscaling:
  enabled: false
podDisruptionBudget:
  enabled: false
```

Validation must cover reconciliation, PostgreSQL capacity, webhook routing,
leases, and termination behavior.

With one replica, `podDisruptionBudget.minAvailable: 1` can block
voluntary node maintenance. The CPU autoscaler also needs a working metrics API
and meaningful CPU requests.

The application has no separate worker command, so this chart creates one
Deployment. Separate ingress and worker Deployments are not supported.

Do not select `RollingUpdate` until the overlapping application versions,
database head, leases, and shutdown behavior have been tested together.

## Understand the insecure policy override

`allowInsecureChanges: true` sets
`EXTRA_CODEOWNERS_ALLOW_INSECURE_CHANGES=true` for every application service
pod in the release. It removes the built-in non-delegable list, so an enrolled
App may satisfy changes to:

- supported `CODEOWNERS` files
- Extra CODEOWNERS policy
- `/stampbot.toml`
- workflows under `.github/workflows/`
- local actions under `.github/actions/`.

Organization guardrails and normal delegation matching still apply. This is a
deployment-wide authority change, not a repository override. The default is
`false`, and Helm notes print a security warning when it is true.

## Configure egress policy

Egress isolation is disabled by default because the application needs GitHub,
PostgreSQL, DNS, and possibly telemetry. GitHub API addresses are not a stable
Kubernetes CIDR contract.

Clusters with an egress proxy or gateway may set
`networkPolicy.egressEnabled: true` and provide complete rules in
`networkPolicy.egress`. An empty list then denies all egress, so readiness
and the migration Job fail. The migration pod still receives no GitHub
credentials even when a shared rule permits GitHub traffic.

## Uninstall without dropping enforcement

> [!WARNING]
> Restore repository enforcement before stopping the check publisher. After
> the App loses access, it may be unable to revoke an earlier success.

For every repository that depends on Extra CODEOWNERS:

1. Re-enable GitHub's native **Require review from Code Owners** rule.
2. Confirm that GitHub reports the native rule as active. Then open a test pull
   request for a path delegated to an App, let the allowed App review make
   `Extra CODEOWNERS / approval` succeed, and leave it without human code-owner
   approval. Verify that the native rule is the remaining blocker.
3. Only after that verification, remove `Extra CODEOWNERS / approval` and its
   expected App source from the ruleset or branch protection.

Only then uninstall:

```bash
helm uninstall extra-codeowners --namespace extra-codeowners
kubectl --namespace extra-codeowners delete secret \
  extra-codeowners-registry --ignore-not-found
```

Keep the App installation and repository access until native enforcement has
been restored and verified. The project does not assume GitHub invalidates an
old success automatically.

Helm uninstall does not delete externally created runtime, database, GitHub,
registry, or TLS Secrets. It also does not delete PostgreSQL or external
infrastructure. Remove each only after confirming that no other deployment
uses it and after satisfying audit-retention requirements.

Revoke the registry credential after the last pod stops. If the deployment
used an operator-owned temporary image copy, delete exactly
`IMAGE_REPOSITORY@IMAGE_DIGEST`, confirm that a pull by digest fails, and
then remove any remaining tag. Never delete a shared upstream release artifact.

## Values reference

`values.schema.json` rejects unknown top-level properties and validates
the constraints below during `helm lint`, `helm template`,
`helm install`, and `helm upgrade`. The checked-in
`values.yaml` repeats the default descriptions.

| Value | Type | Default | Constraints and effect |
| --- | --- | --- | --- |
| `replicaCount` | integer | `1` | At least 1; ignored when autoscaling is enabled. |
| `revisionHistoryLimit` | integer | `3` | At least 0 old ReplicaSets. |
| `deploymentStrategy.type` | enum | `Recreate` | `Recreate` or `RollingUpdate`. |
| `deploymentStrategy.rollingUpdate.maxUnavailable` | integer or percentage | unset | Nonnegative; valid only with `RollingUpdate`. |
| `deploymentStrategy.rollingUpdate.maxSurge` | integer or percentage | unset | Nonnegative; valid only with `RollingUpdate`. |
| `image.repository` | string | `example.invalid/stampbot/extra-codeowners` | Nonempty, intentionally non-pullable placeholder. |
| `image.pullPolicy` | enum | `IfNotPresent` | `Always`, `IfNotPresent`, or `Never`. |
| `image.tag` | string | empty | Uses chart `appVersion` when empty. |
| `image.digest` | string | empty | Empty or `sha256:` plus 64 lowercase hex characters; overrides the tag. |
| `imagePullSecrets` | array | `[]` | Objects containing a nonempty `name`. |
| `nameOverride` | string | empty | Replaces the chart-name portion of resource names. |
| `fullnameOverride` | string | empty | Replaces the complete generated resource name. |
| `serviceAccount.create` | boolean | `true` | Creates the dedicated runtime account. |
| `serviceAccount.automountServiceAccountToken` | boolean | `false` | Mounts a Kubernetes API token when true. |
| `serviceAccount.annotations` | string map | `{}` | Adds ServiceAccount annotations. |
| `serviceAccount.name` | string | empty | Created-account override, or existing account when creation is false. |
| `podAnnotations` | string map | `{}` | Adds application pod annotations. |
| `podLabels` | string map | `{}` | Adds labels; cannot override chart name, instance, or component labels. |
| `podSecurityContext` | object | nonroot, GID 65532 volumes, `RuntimeDefault` seccomp | Applies at pod level. |
| `securityContext` | object | UID/GID 65532, read-only root, no capabilities | Applies to application and migration containers. |
| `existingSecret` | string | empty | Runtime Secret exposed with `envFrom`; never created by the chart. |
| `allowInsecureChanges` | boolean | `false` | Disables only built-in non-delegable paths for every served installation. |
| `extraEnvFrom` | array | `[]` | Additional runtime `EnvFromSource` objects. |
| `extraEnv` | array | `[]` | `EnvVar` objects with `name` and exactly one of `value` or `valueFrom`; cannot override chart-managed environment or insecure-mode variables. |
| `extraVolumes` | array | `[]` | Volume objects with `name`; `tmp` is reserved. |
| `extraVolumeMounts` | array | `[]` | Mounts with `name` and `mountPath`; `tmp` and `/tmp` are reserved. |
| `extraArgs` | string array | `[]` | Replaces image arguments without replacing its entrypoint. |
| `migrations.enabled` | boolean | `true` | Runs the pre-install and pre-upgrade Alembic Job. |
| `migrations.lockTimeoutSeconds` | number | `60` | Greater than 0 and at most 300 seconds. |
| `migrations.activeDeadlineSeconds` | integer | `180` | 1 through 3600 seconds. |
| `migrations.backoffLimit` | integer | `0` | 0 through 10 Kubernetes retries. |
| `migrations.ttlSecondsAfterFinished` | integer | `3600` | 60 through 604800 seconds. |
| `migrations.annotations` | string map | `{}` | Additional annotations; hook, weight, and delete-policy annotations are reserved. |
| `migrations.serviceAccountName` | string | empty | Existing migration identity; empty uses the namespace's default account. |
| `migrations.existingSecret` | string | empty | Migration-only Secret exposed with `envFrom`. |
| `migrations.extraEnvFrom` | array | `[]` | Migration-only `EnvFromSource` objects. |
| `migrations.extraEnv` | array | `[]` | Migration-only `EnvVar` objects with `name` and exactly one of `value` or `valueFrom`; cannot override the production environment. |
| `migrations.extraVolumes` | array | `[]` | Migration-only volumes; `tmp` is reserved. |
| `migrations.extraVolumeMounts` | array | `[]` | Migration-only mounts; `tmp` and `/tmp` are reserved. |
| `service.type` | enum | `ClusterIP` | `ClusterIP`, `NodePort`, or `LoadBalancer`. |
| `service.port` | integer | `80` | 1 through 65535. |
| `service.annotations` | string map | `{}` | Adds Service annotations. |
| `ingress.enabled` | boolean | `false` | Creates an Ingress when true. |
| `ingress.className` | string | empty | Selects the ingress controller. |
| `ingress.annotations` | string map | `{}` | Adds controller-specific annotations. |
| `ingress.hosts` | array | example host and exact webhook path | At least one host; every path starts with `/` and has a valid Kubernetes path type. |
| `ingress.tls` | array | `[]` | Entries require a nonempty Secret name and at least one host. |
| `resources.requests` | object | `100m` CPU, `128Mi` memory | Application and migration requests. |
| `resources.limits` | object | `512Mi` memory | No CPU limit by default. |
| `probes.liveness.enabled` | boolean | `true` | Enables the process-health probe. |
| `probes.liveness.path` | string | `/health/live` | Must start with `/`. |
| `probes.liveness.initialDelaySeconds` | integer | `10` | At least 0. |
| `probes.liveness.periodSeconds` | integer | `10` | At least 1. |
| `probes.liveness.timeoutSeconds` | integer | `3` | At least 1. |
| `probes.liveness.failureThreshold` | integer | `3` | At least 1. |
| `probes.readiness.enabled` | boolean | `true` | Enables the dependency-aware readiness probe. |
| `probes.readiness.path` | string | `/health/ready` | Must start with `/`. |
| `probes.readiness.initialDelaySeconds` | integer | `5` | At least 0. |
| `probes.readiness.periodSeconds` | integer | `10` | At least 1. |
| `probes.readiness.timeoutSeconds` | integer | `3` | At least 1. |
| `probes.readiness.failureThreshold` | integer | `3` | At least 1. |
| `autoscaling.enabled` | boolean | `false` | Creates a CPU HorizontalPodAutoscaler. |
| `autoscaling.minReplicas` | integer | `2` | At least 1. |
| `autoscaling.maxReplicas` | integer | `5` | At least 1. |
| `autoscaling.targetCPUUtilizationPercentage` | integer | `70` | 1 through 100. |
| `podDisruptionBudget.enabled` | boolean | `false` | Creates a PodDisruptionBudget. |
| `podDisruptionBudget.minAvailable` | integer or percentage | `1` | Nonnegative integer or digits followed by `%`. |
| `networkPolicy.enabled` | boolean | `true` | Selects application and migration pods. |
| `networkPolicy.ingressFrom` | array | `[]` | Empty permits all peers to the named HTTP port. |
| `networkPolicy.egressEnabled` | boolean | `false` | Adds egress isolation when true. |
| `networkPolicy.egress` | array | `[]` | Complete egress rules; empty with isolation enabled denies all egress. |
| `terminationGracePeriodSeconds` | integer | `30` | At least 1 second for in-process leased work. |
| `priorityClassName` | string | empty | Existing PriorityClass name. |
| `nodeSelector` | string map | `{}` | Node label constraints. |
| `tolerations` | array | `[]` | Kubernetes toleration objects. |
| `affinity` | object | `{}` | Kubernetes affinity rules. |
| `topologySpreadConstraints` | array | `[]` | Kubernetes topology spread constraints. |

[upgrade]: https://extra-codeowners.readthedocs.io/en/latest/how-to/upgrade/
[upgrade-notes]: https://extra-codeowners.readthedocs.io/en/latest/reference/upgrade-notes/
