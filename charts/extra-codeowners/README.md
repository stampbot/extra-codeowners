# Extra CODEOWNERS Helm chart

This chart deploys the self-hosted Extra CODEOWNERS GitHub App service. The
project is still in early development and has no supported hosted service or
production release. Do not use a preview to authorize production merges. The
commands below are for reviewers testing a specific checked-out commit.

Successful `main` builds publish signed multi-architecture preview images under
the mutable `main` tag and a commit-specific `sha-*` tag. When a version tag
produces a GitHub release, the release workflow also publishes signed
semantic-versioned images and the chart at
`oci://ghcr.io/stampbot/charts/extra-codeowners`. Treat the GitHub release and
its attestations as the authority for whether a version is actually available;
workflow definitions alone are not evidence that an artifact was published.

## Prerequisites

- Kubernetes 1.27 or later
- Helm 3.14 or later
- Docker and an operator-controlled container registry reachable by the cluster
  when building the image from source
- an installed Extra CODEOWNERS GitHub App
- a durable database supported by the application
- Kubernetes Secrets containing the runtime environment variables and mounted
  GitHub credential files documented in the
  [configuration reference][configuration]
- an ingress controller or another way for GitHub to reach the webhook endpoint
  over HTTPS

The chart does not create application secrets or a database. It also does not
install an ingress controller, issue TLS certificates, or run a pre-upgrade
migration Job. The current application initializes missing tables during
startup, but it has no supported schema migration or database rollback contract.
The chart always sets `EXTRA_CODEOWNERS_ENVIRONMENT=production`; the runtime
Secret must override the container's development-only SQLite database URL with a
PostgreSQL URL. Do not redefine chart-managed environment variables through
`extraEnv`.

## Build a preview image

The following commands run from the repository root. `IMAGE_REPOSITORY` is an
operator-controlled registry path; the reserved `example.com` hostname must be
replaced. `IMAGE_TAG` is the reviewed Git commit and must not be reused for a
different image. Authenticate Docker and the cluster to the selected registry
before continuing.

```shell
export IMAGE_REPOSITORY="registry.example.com/example/extra-codeowners"
export IMAGE_TAG="$(git rev-parse HEAD)"
docker build --tag "${IMAGE_REPOSITORY}:${IMAGE_TAG}" .
docker push "${IMAGE_REPOSITORY}:${IMAGE_TAG}"
```

Record the digest returned by the registry. This local source-build workflow
does not produce a signature or provenance attestation. CI-published preview and
release images have workflow-identity signatures and provenance attestations.

## Install the source chart

The following commands use `extra-codeowners` as both the Helm release and
Kubernetes namespace. `RUNTIME_ENV_FILE` is a local file containing the required
environment variables in `KEY=value` format, including the database URL and
these two file settings:

```text
EXTRA_CODEOWNERS_GITHUB_PRIVATE_KEY_FILE=/run/secrets/extra-codeowners/github-private-key
EXTRA_CODEOWNERS_GITHUB_WEBHOOK_SECRET_FILE=/run/secrets/extra-codeowners/github-webhook-secret
```

Keep that file and both credential source files outside version control and
restrict their filesystem permissions. Create separate Secrets for environment
variables and mounted credential files:

```shell
export RUNTIME_ENV_FILE="$HOME/.config/extra-codeowners/preview.env"
export GITHUB_PRIVATE_KEY_FILE="$HOME/.config/extra-codeowners/private-key.pem"
export GITHUB_WEBHOOK_SECRET_FILE="$HOME/.config/extra-codeowners/webhook-secret"
kubectl create namespace extra-codeowners
kubectl --namespace extra-codeowners create secret generic extra-codeowners-runtime \
  --from-env-file="$RUNTIME_ENV_FILE"
kubectl --namespace extra-codeowners create secret generic extra-codeowners-github \
  --from-file=github-private-key="$GITHUB_PRIVATE_KEY_FILE" \
  --from-file=github-webhook-secret="$GITHUB_WEBHOOK_SECRET_FILE"
```

Save the non-secret mount wiring as `deployment-values.yaml`:

```yaml
existingSecret: extra-codeowners-runtime
extraVolumes:
  - name: github-credentials
    secret:
      secretName: extra-codeowners-github
      defaultMode: 0440
extraVolumeMounts:
  - name: github-credentials
    mountPath: /run/secrets/extra-codeowners
    readOnly: true
```

Install the reviewed image and source chart:

```shell
helm install extra-codeowners \
  ./charts/extra-codeowners \
  --namespace extra-codeowners \
  --values deployment-values.yaml \
  --set-string image.repository="$IMAGE_REPOSITORY" \
  --set-string image.tag="$IMAGE_TAG"
```

Do not pass secret values with `--set`; shell history and Helm release metadata
may retain them. A successful install creates a Deployment, Service,
ServiceAccount, and ingress NetworkPolicy. The application will not become
ready until its GitHub App and persistence configuration are valid.

## Verify

Wait for the rollout and run the chart's live-endpoint test:

```shell
kubectl --namespace extra-codeowners rollout status \
  deployment/extra-codeowners --timeout=5m
helm test extra-codeowners --namespace extra-codeowners
kubectl --namespace extra-codeowners get pods,service,networkpolicy
```

If rollout fails, inspect sanitized pod events and logs. Never copy App private
keys, webhook secrets, installation tokens, or private webhook payloads into an
issue.

```shell
kubectl --namespace extra-codeowners describe deployment/extra-codeowners
kubectl --namespace extra-codeowners logs \
  deployment/extra-codeowners --all-pods --tail=100
```

## Expose the webhook securely

Enable the Ingress only after an ingress controller and TLS issuer exist. Replace
`extra-codeowners.example.com` with the public hostname registered in the GitHub
App. The Secret `extra-codeowners-tls` must contain a certificate valid for that
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

Apply the file as `ingress-values.yaml` during install or upgrade:

```shell
helm upgrade --install extra-codeowners \
  ./charts/extra-codeowners \
  --namespace extra-codeowners \
  --reset-then-reuse-values \
  --values ingress-values.yaml
```

The default NetworkPolicy permits traffic to the HTTP port from any network
peer so that ingress-controller deployments work across common topologies.
Restrict `networkPolicy.ingressFrom` to the ingress controller's namespace and
pod selectors when your cluster labels are known. Keep `/metrics`, health
endpoints, and setup routes off the public Ingress; use an authenticated
operator route or port forwarding when you need them.

## Upgrade and roll back

Back up the database using its native tools before testing another commit. Read
the changed code and documentation for schema compatibility; the source chart
has no migration hook, and Helm rollback cannot reverse application startup
changes. The default `Recreate` strategy prevents old and new application
versions from using the database concurrently, at the cost of a short webhook
processing pause. GitHub does not automatically redeliver failed webhook
deliveries. After recovery, inspect and manually redeliver failures; periodic
reconciliation provides a separate path for open pull requests to converge.
Build and push the newly reviewed commit under a new `IMAGE_TAG`, then upgrade
from the same checkout:

```shell
helm upgrade extra-codeowners \
  ./charts/extra-codeowners \
  --namespace extra-codeowners \
  --reset-then-reuse-values \
  --set-string image.repository="$IMAGE_REPOSITORY" \
  --set-string image.tag="$IMAGE_TAG"
kubectl --namespace extra-codeowners rollout status \
  deployment/extra-codeowners --timeout=5m
```

If health checks fail and the reviewed changes leave the database
backward-compatible, roll back:

```shell
helm history extra-codeowners --namespace extra-codeowners
helm rollback extra-codeowners REVISION --namespace extra-codeowners --wait
```

`REVISION` is the known-good revision shown by `helm history`. A Helm rollback
does not reverse database changes; use the application-version-specific recovery
procedure when a migration is not backward-compatible.

`--reset-then-reuse-values` starts with the new chart defaults before applying
the release's existing overrides. This preserves new required safety defaults
that plain `--reuse-values` can omit. Review `helm get values` and the new
`values.yaml` before every upgrade; a successful merge is not evidence that an
old override remains safe.

## Scaling and disruption

The application serves webhooks and executes durable leased work in the same
process. Database leases are designed to prevent duplicate ownership, but the
project does not yet claim validated high availability. Keep `replicaCount: 1`,
autoscaling disabled, and the PodDisruptionBudget disabled until you have tested
reconciliation, database capacity, webhook routing, and termination behavior in
your environment.

The default `Recreate` deployment strategy also remains appropriate until mixed
application versions have a tested database-compatibility contract. Switch to
`RollingUpdate` only when that overlap is intentional and validated.

When that validation is complete, set at least two replicas before enabling the
default `podDisruptionBudget.minAvailable: 1`. Enabling the budget with one
replica can block voluntary node maintenance. The CPU-based autoscaler also
requires a cluster metrics API and meaningful CPU requests.

The app currently has no separate worker command, so the chart creates one
Deployment only. A future chart may split webhook serving and work execution
after that runtime interface exists.

## Insecure policy override

`allowInsecureChanges: true` sets
`EXTRA_CODEOWNERS_ALLOW_INSECURE_CHANGES=true` for the process. This removes the
application's built-in non-delegable path list, allowing an enrolled application
to satisfy changes to files such as `CODEOWNERS`, Extra CODEOWNERS policy, and
Stampbot policy (`/stampbot.toml`), GitHub Actions workflows, or
repository-local actions under `.github/actions/` when a repository delegation
covers them. It does not remove
organization-added guardrails or bypass ordinary delegation matching.

The default is `false`. Keep it false unless you intentionally accept the risk
that an application could approve a change which expands its own authority. The
setting affects every installation served by the deployment, not one repository.
The Helm notes print a security warning whenever it is enabled.

## Egress policy

Egress isolation is off by default because the app must reach GitHub and its
database, and GitHub API addresses are not a stable Kubernetes CIDR contract. If
your cluster provides an egress proxy or gateway, set `networkPolicy.egressEnabled`
and supply complete DNS, GitHub, database, and telemetry rules in
`networkPolicy.egress`. An empty egress list denies all egress and prevents the
readiness probe from succeeding.

## Uninstall

Restore repository enforcement before stopping the check publisher. For every
repository that depends on Extra CODEOWNERS:

1. Re-enable GitHub's native **Require review from Code Owners** rule.
2. Remove `Extra CODEOWNERS / approval` and its expected App source from the
   repository ruleset or branch protection.
3. Verify the changed rule is active, and use a test pull request to confirm
   that an unapproved owned-file change is blocked.

Only after every dependent repository has passed that verification should you
stop the service:

```shell
helm uninstall extra-codeowners --namespace extra-codeowners
```

Do not suspend the GitHub App installation, remove repository access, or
uninstall the App before restoring and verifying native enforcement. Once App
access or this deployment is gone, Extra CODEOWNERS cannot revoke an earlier
successful check, and this project does not assume that GitHub invalidates that
success automatically.

Uninstalling does not delete the runtime or GitHub credential Secrets, database,
TLS Secret, or externally managed infrastructure. Remove those only after
confirming that no other deployment uses them, retaining any required audit
data, and completing the App-access cleanup in that order.

## Values

The following table describes every value. The [values file](values.yaml) keeps
the same descriptions beside the defaults, and
[values.schema.json](values.schema.json) validates types, bounds, accepted
enums, and unknown top-level properties during `helm install`, `helm upgrade`,
`helm lint`, and `helm template`.

| Value | Type | Default | Purpose |
| --- | --- | --- | --- |
| `replicaCount` | integer | `1` | API/worker pods when autoscaling is off. |
| `revisionHistoryLimit` | integer | `3` | Old ReplicaSets retained for rollback. |
| `deploymentStrategy` | object | `Recreate` | Deployment replacement strategy; avoids overlapping application versions by default. |
| `image.repository` | string | `ghcr.io/stampbot/extra-codeowners` | Container repository used by CI preview and tagged release images. |
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
| `networkPolicy.enabled` | boolean | `true` | Limit ingress to the named HTTP container port. |
| `networkPolicy.ingressFrom` | array | `[]` | Allowed ingress peers; empty permits all peers to that port. |
| `networkPolicy.egressEnabled` | boolean | `false` | Add egress isolation to the NetworkPolicy. |
| `networkPolicy.egress` | array | `[]` | Complete egress rules; empty with isolation enabled denies all egress. |
| `terminationGracePeriodSeconds` | integer | `30` | Grace period for in-process leased work. |
| `priorityClassName` | string | empty | Existing PriorityClass name. |
| `nodeSelector` | object | `{}` | Node label constraints. |
| `tolerations` | array | `[]` | Pod tolerations. |
| `affinity` | object | `{}` | Pod and node affinity rules. |
| `topologySpreadConstraints` | array | `[]` | Failure-domain distribution rules. |

Security-relevant defaults include:

- a dedicated ServiceAccount with API token automounting disabled;
- non-root execution with all Linux capabilities dropped;
- a read-only root filesystem and runtime-default seccomp profile;
- HTTP liveness and dependency-aware readiness probes;
- the insecure policy override disabled;
- no chart-managed Secret or credential value; and
- an ingress NetworkPolicy limited to the application port.

[configuration]: https://github.com/stampbot/extra-codeowners/blob/main/docs/reference/configuration.md
