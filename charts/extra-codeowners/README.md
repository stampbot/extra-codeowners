# Extra CODEOWNERS Helm chart

This chart deploys the self-hosted Extra CODEOWNERS GitHub App service. The
repository contains the source chart. No versioned GitHub release, supported
production release, or hosted service is available.

Successful `main` builds publish public, signed multi-architecture development
images under the mutable `main` tag and a commit-specific `sha-*` tag. A version
tag that produces a GitHub release also publishes signed semantic-versioned
images and the chart at
`oci://ghcr.io/stampbot/charts/extra-codeowners`. No versioned chart is
available until such a release exists. The GitHub release and its attestations
define artifact availability; workflow definitions do not prove publication.

The current Check Run design has a documented commit-to-pull-request
inheritance window. It does not provide native-equivalent production
enforcement. The commands below test a specific checked-out commit and must not
be used to authorize production merges.

## Prerequisites

- Kubernetes 1.27 or later
- Helm 3.14 or later
- Docker and an operator-controlled container registry reachable by the cluster
  when building an image from source
- an installed Extra CODEOWNERS GitHub App
- a durable database supported by the application
- separate Kubernetes Secrets containing runtime settings, the database URL,
  and mounted GitHub credential files documented in the
  [configuration reference][configuration]
- an ingress controller or another way for GitHub to reach the webhook endpoint
  over HTTPS

The chart does not provide these resources or operations:

- application Secrets
- a database
- an ingress controller
- TLS certificates
- automated database backups or restore testing.

The chart runs a bounded Alembic migration Job before install and upgrade. The
application then validates the exact revision and table shape during startup;
it never creates or upgrades tables implicitly.

The chart sets `EXTRA_CODEOWNERS_ENVIRONMENT=production`. The database Secret
must replace the container's development-only SQLite URL with a PostgreSQL URL.
`extraEnv` rejects chart-managed environment variables.

The migration Job does not inherit `existingSecret`, `extraEnvFrom`,
`extraEnv`, `extraVolumes`, or `extraVolumeMounts`. Configure its database-only
inputs under `migrations`. Never attach the App private key or webhook secret
to that Job.

The application and migration pods set `enableServiceLinks: false`. Kubernetes
would otherwise inject a Service variable named `EXTRA_CODEOWNERS_PORT` with a
URL-like value, which conflicts with the application's integer port setting.
Use Kubernetes DNS for service discovery instead of injected Service variables.

## Build an image from source

Run these commands from the repository root. `IMAGE_REPOSITORY` must name an
operator-controlled registry path that the cluster can reach. Replace the
reserved `example.com` hostname. `IMAGE_TAG` identifies the reviewed Git commit
and must not be reused for another image. Docker and the cluster must already be
authenticated to the selected registry.

```shell
export IMAGE_REPOSITORY="registry.example.com/example/extra-codeowners"
export IMAGE_TAG="$(git rev-parse HEAD)"
docker build --tag "${IMAGE_REPOSITORY}:${IMAGE_TAG}" .
docker push "${IMAGE_REPOSITORY}:${IMAGE_TAG}"
```

The registry returns the image digest. Record it. This local source build does
not create a signature or provenance attestation. CI-published development and
release images have workflow-identity signatures and provenance attestations.

Export the digest returned by the registry, including its `sha256:` prefix:

```shell
export IMAGE_DIGEST="sha256:REPLACE_WITH_REGISTRY_DIGEST"
```

## Install the source chart

The commands use `extra-codeowners` as both the Helm release and Kubernetes
namespace. `RUNTIME_ENV_FILE` contains non-database runtime variables in
`KEY=value` format, including these file settings:

```text
EXTRA_CODEOWNERS_GITHUB_PRIVATE_KEY_FILE=/run/secrets/extra-codeowners/github-private-key
EXTRA_CODEOWNERS_GITHUB_WEBHOOK_SECRET_FILE=/run/secrets/extra-codeowners/github-webhook-secret
```

`DATABASE_ENV_FILE` contains exactly the database setting required by both
processes:

```text
EXTRA_CODEOWNERS_DATABASE_URL=postgresql+psycopg://DB_USER:DB_PASSWORD@DB_HOST:5432/DB_NAME?sslmode=verify-full
```

Replace every database placeholder and percent-encode reserved URL characters.
Both environment files and both credential source files must remain outside
version control with restricted filesystem permissions. The deployment uses
separate Secrets for runtime settings, the database URL, and mounted GitHub
credential files:

```shell
export RUNTIME_ENV_FILE="$HOME/.config/extra-codeowners/runtime.env"
export DATABASE_ENV_FILE="$HOME/.config/extra-codeowners/database.env"
export GITHUB_PRIVATE_KEY_FILE="$HOME/.config/extra-codeowners/private-key.pem"
export GITHUB_WEBHOOK_SECRET_FILE="$HOME/.config/extra-codeowners/webhook-secret"
kubectl create namespace extra-codeowners
kubectl --namespace extra-codeowners create secret generic extra-codeowners-runtime \
  --from-env-file="$RUNTIME_ENV_FILE"
kubectl --namespace extra-codeowners create secret generic extra-codeowners-database \
  --from-env-file="$DATABASE_ENV_FILE"
kubectl --namespace extra-codeowners create secret generic extra-codeowners-github \
  --from-file=github-private-key="$GITHUB_PRIVATE_KEY_FILE" \
  --from-file=github-webhook-secret="$GITHUB_WEBHOOK_SECRET_FILE"
```

Save the non-secret mount wiring as `deployment-values.yaml`:

```yaml
existingSecret: extra-codeowners-runtime
extraEnvFrom:
  - secretRef:
      name: extra-codeowners-database
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

Install the reviewed image and source chart:

```shell
helm install extra-codeowners \
  ./charts/extra-codeowners \
  --namespace extra-codeowners \
  --values deployment-values.yaml \
  --set-string image.repository="$IMAGE_REPOSITORY" \
  --set-string image.digest="$IMAGE_DIGEST"
```

Secret values must not be passed with `--set`. Shell history and Helm release
metadata may retain them.

A successful install creates:

- a bounded pre-install migration Job
- a Deployment
- a Service
- a ServiceAccount
- a NetworkPolicy that selects both application and migration pods after
  chart resources are installed.

The application remains unready until its GitHub App and persistence
configuration are valid.

## Verify

Wait for the rollout and run the chart's live-endpoint test:

```shell
kubectl --namespace extra-codeowners rollout status \
  deployment/extra-codeowners --timeout=5m
helm test extra-codeowners --namespace extra-codeowners
kubectl --namespace extra-codeowners get pods,service,networkpolicy
```

If rollout fails, the following commands show pod events and logs. Output must
be sanitized before sharing. App private keys, webhook secrets, installation
tokens, and private webhook payloads must not appear in an issue.

```shell
kubectl --namespace extra-codeowners describe deployment/extra-codeowners
kubectl --namespace extra-codeowners logs \
  deployment/extra-codeowners --all-pods --tail=100
```

## Expose the webhook securely

Ingress requires an installed ingress controller and TLS issuer. Replace
`extra-codeowners.example.com` with the public hostname registered in the GitHub
App. The `extra-codeowners-tls` Secret must contain a certificate valid for that
hostname.

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

Save the file as `ingress-values.yaml`, then apply it to the existing release:

```shell
helm upgrade extra-codeowners \
  ./charts/extra-codeowners \
  --namespace extra-codeowners \
  --reset-then-reuse-values \
  --values ingress-values.yaml
```

The default NetworkPolicy permits traffic to the HTTP port from any network
peer. This supports ingress controllers across common cluster topologies.
`networkPolicy.ingressFrom` can restrict access to the controller's namespace
and pod selectors when those labels are known.

The policy's selector covers the application and migration pod labels. The
Service and PodDisruptionBudget add `app.kubernetes.io/component: application`,
so they never select the one-shot migration pod. On the first install, Helm
runs `pre-install` hooks before it creates ordinary chart resources, including
this NetworkPolicy. Use a namespace-level default-deny policy or pre-create an
equivalent policy before installation when the initial migration must be
network-isolated. On upgrade, the installed chart policy already covers the
new migration pod.

The public Ingress must not expose `/metrics`, health endpoints, or setup
routes. Access to those endpoints requires an authenticated operator route or
port forwarding.

## Upgrade and roll back

Before an upgrade, complete the documented [backup and isolated restore
test][upgrade]. The chart's pre-upgrade hook uses the target image and database
environment to run `extra-codeowners database migrate`. It waits at most 60
seconds for the cross-replica PostgreSQL advisory lock, has no process retry,
has a 180-second Job deadline, and retains the completed Job for one hour by
default. A failed hook stops Helm before the application Deployment changes.

Keep `migrations.enabled: true` unless a separately controlled process applies
the exact target migration before Helm. Set `migrations.serviceAccountName` to
a pre-existing ServiceAccount when database authentication needs a Kubernetes
identity. The chart disables Kubernetes API token automounting for that pod;
review any identity-provider admission mutation separately.

Set `migrations.existingSecret` to a Secret containing only
`EXTRA_CODEOWNERS_DATABASE_URL`. Use the migration-specific `extraEnvFrom`,
`extraEnv`, `extraVolumes`, and `extraVolumeMounts` values only for database
authentication or trust material. Runtime App settings and GitHub credential
mounts are never inherited.

The default `Recreate` strategy prevents old and new application versions from
using the database concurrently. It causes a short pause in webhook processing.
GitHub does not automatically redeliver failed webhook deliveries. After
recovery, inspect and manually redeliver failures. Periodic reconciliation is a
separate convergence path for open pull requests.

Build and push the reviewed commit under a new `IMAGE_TAG`. Record its new
registry digest in `IMAGE_DIGEST`, then upgrade from the same checkout:

```shell
helm upgrade extra-codeowners \
  ./charts/extra-codeowners \
  --namespace extra-codeowners \
  --reset-then-reuse-values \
  --set-string image.repository="$IMAGE_REPOSITORY" \
  --set-string image.digest="$IMAGE_DIGEST"
kubectl --namespace extra-codeowners rollout status \
  deployment/extra-codeowners --timeout=5m
```

If health checks fail, compare the current database head with the previous
artifact's [required head][upgrade-notes]. When the head did not change, roll
back the application:

```shell
helm history extra-codeowners --namespace extra-codeowners
helm rollback extra-codeowners REVISION --namespace extra-codeowners --wait
```

`REVISION` is the known-good revision shown by `helm history`. Helm rollback
does not reverse database changes or run Alembic downgrade. When the head did
change, do not start the old image against the migrated database. Restore
native GitHub code-owner protection, preserve the failed database, restore the
verified pre-migration backup into a new empty database, and validate it with
the old artifact before rolling back the Deployment. This restore is required
even when the migration SQL was additive.

`--reset-then-reuse-values` starts with the new chart defaults before applying
the release's existing overrides. Plain `--reuse-values` can omit new safety
defaults. Every upgrade requires review of `helm get values` and the new
`values.yaml`. A successful merge does not establish that an old override
remains safe.

## Scaling and disruption

The application serves webhooks and executes durable leased work in the same
process. Database leases are designed to prevent duplicate ownership. High
availability has not been validated.

Until environment-specific validation is complete, use these settings:

```yaml
replicaCount: 1
autoscaling:
  enabled: false
podDisruptionBudget:
  enabled: false
```

Validation must cover reconciliation, database capacity, webhook routing, and
termination behavior.

The default `Recreate` strategy avoids mixed application versions. A
`RollingUpdate` requires an intentional and tested database-compatibility
contract for version overlap.

After validation, `podDisruptionBudget.minAvailable: 1` requires at least two
replicas. With one replica, the budget can block voluntary node maintenance.
The CPU-based autoscaler requires a cluster metrics API and meaningful CPU
requests.

The application has no separate worker command. The chart therefore creates one
Deployment. Separate webhook and worker Deployments are not supported.

## Insecure policy override

`allowInsecureChanges: true` sets
`EXTRA_CODEOWNERS_ALLOW_INSECURE_CHANGES=true` for the process. It removes the
built-in non-delegable path list. When repository delegation covers them, an
enrolled application can then satisfy changes to:

- `CODEOWNERS`
- Extra CODEOWNERS policy
- Stampbot policy at `/stampbot.toml`
- GitHub Actions workflows
- repository-local actions under `.github/actions/`.

The setting does not remove organization guardrails or bypass delegation
matching.

The default is `false`. A value of `true` accepts the risk that an application
can approve a change that expands its authority. The setting affects every
installation served by the deployment, not one repository. Helm notes print a
security warning when it is enabled.

## Egress policy

Egress isolation is disabled by default. The application must reach GitHub and
its database, and GitHub API addresses do not form a stable Kubernetes CIDR
contract.

Clusters with an egress proxy or gateway can set
`networkPolicy.egressEnabled`. `networkPolicy.egress` must then contain complete
DNS, GitHub, database, and telemetry rules. An empty list denies all egress and
prevents the readiness probe and migration Job from succeeding. The migration
pod receives no GitHub credentials even when the shared network rule permits
GitHub egress.

## Uninstall

Repository enforcement must be restored before the check publisher stops. For
every repository that depends on Extra CODEOWNERS:

1. Re-enable GitHub's native **Require review from Code Owners** rule.
2. Remove `Extra CODEOWNERS / approval` and its expected App source from the
   repository ruleset or branch protection.
3. Verify the changed rule is active, and use a test pull request to confirm
   that an unapproved owned-file change is blocked.

Stop the service only after every dependent repository passes that
verification:

```shell
helm uninstall extra-codeowners --namespace extra-codeowners
```

The GitHub App installation must remain active and retain repository access
until native enforcement is restored and verified. After App access or the
deployment is gone, Extra CODEOWNERS cannot revoke an earlier successful check.
The project does not assume that GitHub invalidates that success automatically.

Uninstalling does not delete:

- the runtime Secret
- the database Secret
- the GitHub credential Secret
- the database
- the TLS Secret
- externally managed infrastructure.

These resources can be removed after confirming that no other deployment uses
them, retaining required audit data, and completing App-access cleanup in that
order.

## Values

The table describes every chart value. The [values file](values.yaml) repeats
the descriptions beside each default. [values.schema.json](values.schema.json)
validates types, bounds, accepted enums, and unknown top-level properties during
`helm install`, `helm upgrade`, `helm lint`, and `helm template`.

| Value | Type | Default | Purpose |
| --- | --- | --- | --- |
| `replicaCount` | integer | `1` | API/worker pods when autoscaling is off. |
| `revisionHistoryLimit` | integer | `3` | Old ReplicaSets retained for rollback. |
| `deploymentStrategy` | object | `Recreate` | Deployment replacement strategy; avoids overlapping application versions by default. |
| `image.repository` | string | `ghcr.io/stampbot/extra-codeowners` | Container repository used by CI development and tagged release images. |
| `image.pullPolicy` | enum | `IfNotPresent` | Kubernetes image pull policy. |
| `image.tag` | string | empty | Image tag; an empty value uses chart `appVersion`. |
| `image.digest` | string | empty | `sha256:` digest that takes precedence over the tag. |
| `imagePullSecrets` | array | `[]` | Names of image-registry pull Secrets. |
| `nameOverride` | string | empty | Replacement for the chart name. |
| `fullnameOverride` | string | empty | Complete resource-name replacement. |
| `serviceAccount.create` | boolean | `true` | Create a dedicated ServiceAccount. |
| `serviceAccount.automountServiceAccountToken` | boolean | `false` | Mount a Kubernetes API token in the pod. |
| `serviceAccount.annotations` | object | `{}` | ServiceAccount annotations. |
| `serviceAccount.name` | string | empty | Existing account name, or created account name override. |
| `podAnnotations` | object | `{}` | Pod annotations. |
| `podLabels` | object | `{}` | Additional pod labels; chart selector labels are reserved. |
| `podSecurityContext` | object | non-root, GID 65532 volumes, `RuntimeDefault` seccomp | Pod-level security context. |
| `securityContext` | object | UID/GID 65532, read-only, no capabilities | Application container security context. |
| `existingSecret` | string | empty | Secret exposed with `envFrom`; the chart never creates it. |
| `allowInsecureChanges` | boolean | `false` | Disable only built-in non-delegable paths for every served installation. |
| `extraEnvFrom` | array | `[]` | Additional Kubernetes `EnvFromSource` objects. |
| `extraEnv` | array | `[]` | Additional Kubernetes `EnvVar` objects; chart-managed environment names are rejected. |
| `extraVolumes` | array | `[]` | Additional pod volumes, including externally managed Secret volumes; the name `tmp` is reserved. |
| `extraVolumeMounts` | array | `[]` | Additional application mounts; the name `tmp` and path `/tmp` are reserved. |
| `extraArgs` | array | `[]` | Override image command arguments without replacing its entrypoint. |
| `migrations.enabled` | boolean | `true` | Run the explicit pre-install and pre-upgrade Alembic Job. |
| `migrations.lockTimeoutSeconds` | number | `60` | Maximum PostgreSQL migration advisory-lock wait. |
| `migrations.activeDeadlineSeconds` | integer | `180` | Complete migration Job deadline. |
| `migrations.backoffLimit` | integer | `0` | Kubernetes retries after migration process failure. |
| `migrations.ttlSecondsAfterFinished` | integer | `3600` | Seconds to retain a completed migration Job for logs, from `60` through `604800`. |
| `migrations.annotations` | object | `{}` | Additional non-hook Job annotations. |
| `migrations.serviceAccountName` | string | empty | Pre-existing migration identity; empty uses the namespace's default account. |
| `migrations.existingSecret` | string | empty | Database-only Secret exposed to the migration container with `envFrom`. |
| `migrations.extraEnvFrom` | array | `[]` | Additional migration-only `EnvFromSource` objects. |
| `migrations.extraEnv` | array | `[]` | Additional migration-only `EnvVar` objects; the chart-managed environment name is reserved. |
| `migrations.extraVolumes` | array | `[]` | Migration-only volumes; the name `tmp` is reserved. |
| `migrations.extraVolumeMounts` | array | `[]` | Migration-only mounts; the name `tmp` and path `/tmp` are reserved. |
| `service.type` | enum | `ClusterIP` | Service type. |
| `service.port` | integer | `80` | In-cluster HTTP Service port. |
| `service.annotations` | object | `{}` | Service annotations. |
| `ingress.enabled` | boolean | `false` | Create an Ingress. |
| `ingress.className` | string | empty | Ingress controller class. |
| `ingress.annotations` | object | `{}` | Controller-specific Ingress annotations. |
| `ingress.hosts` | array | example host, exact webhook path | Host and path rules. |
| `ingress.tls` | array | `[]` | TLS Secret and hostname entries. |
| `resources.requests` | object | `100m` CPU, `128Mi` memory | Container resource requests. |
| `resources.limits` | object | `512Mi` memory | Container resource limits; no CPU limit is imposed. |
| `probes.liveness.enabled` | boolean | `true` | Enable the process liveness probe. |
| `probes.liveness.path` | string | `/health/live` | Liveness HTTP path. |
| `probes.liveness.initialDelaySeconds` | integer | `10` | Delay before liveness checks. |
| `probes.liveness.periodSeconds` | integer | `10` | Liveness check interval. |
| `probes.liveness.timeoutSeconds` | integer | `3` | Liveness request timeout. |
| `probes.liveness.failureThreshold` | integer | `3` | Failures before restart. |
| `probes.readiness.enabled` | boolean | `true` | Enable the dependency-aware readiness probe. |
| `probes.readiness.path` | string | `/health/ready` | Readiness HTTP path. |
| `probes.readiness.initialDelaySeconds` | integer | `5` | Delay before readiness checks. |
| `probes.readiness.periodSeconds` | integer | `10` | Readiness check interval. |
| `probes.readiness.timeoutSeconds` | integer | `3` | Readiness request timeout. |
| `probes.readiness.failureThreshold` | integer | `3` | Failures before becoming unready. |
| `autoscaling.enabled` | boolean | `false` | Create a CPU-based HorizontalPodAutoscaler. |
| `autoscaling.minReplicas` | integer | `2` | Autoscaler lower replica bound. |
| `autoscaling.maxReplicas` | integer | `5` | Autoscaler upper replica bound. |
| `autoscaling.targetCPUUtilizationPercentage` | integer | `70` | Average CPU utilization target. |
| `podDisruptionBudget.enabled` | boolean | `false` | Create a PodDisruptionBudget. |
| `podDisruptionBudget.minAvailable` | integer or percentage | `1` | Pods retained during voluntary disruption. |
| `networkPolicy.enabled` | boolean | `true` | Isolate application and migration pods; permit ingress only to the named application HTTP port. |
| `networkPolicy.ingressFrom` | array | `[]` | Allowed ingress peers; empty permits all peers to that port. |
| `networkPolicy.egressEnabled` | boolean | `false` | Add egress isolation to the NetworkPolicy. |
| `networkPolicy.egress` | array | `[]` | Complete egress rules; empty with isolation enabled denies all egress. |
| `terminationGracePeriodSeconds` | integer | `30` | Grace period for in-process leased work. |
| `priorityClassName` | string | empty | Existing PriorityClass name. |
| `nodeSelector` | object | `{}` | Node label constraints. |
| `tolerations` | array | `[]` | Pod tolerations. |
| `affinity` | object | `{}` | Pod and node affinity rules. |
| `topologySpreadConstraints` | array | `[]` | Failure-domain distribution rules. |

Security-relevant defaults are:

- a dedicated ServiceAccount with API token automounting disabled
- non-root execution with all Linux capabilities dropped
- a read-only root filesystem and runtime-default seccomp profile
- HTTP liveness and dependency-aware readiness probes
- the insecure policy override disabled
- no chart-managed Secret or credential value
- separate runtime and migration credential inputs
- a Service selector that excludes migration hooks
- Kubernetes Service environment-variable injection disabled
- a NetworkPolicy that covers both application and migration pod labels after
  ordinary chart resources are installed.

[configuration]: https://github.com/stampbot/extra-codeowners/blob/main/docs/reference/configuration.md
[upgrade]: https://extra-codeowners.readthedocs.io/en/latest/how-to/upgrade/
[upgrade-notes]: https://extra-codeowners.readthedocs.io/en/latest/reference/upgrade-notes/
