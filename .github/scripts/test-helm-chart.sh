#!/usr/bin/env bash

set -euo pipefail

output="${1:?usage: test-helm-chart.sh OUTPUT_DIRECTORY}"
mkdir -p "${output}"

cmp --silent LICENSE charts/extra-codeowners/LICENSE

chart_version="$(helm show chart charts/extra-codeowners | awk '$1 == "version:" {print $2}')"
app_version="$(
  helm show chart charts/extra-codeowners |
    awk '$1 == "appVersion:" {gsub(/"/, "", $2); print $2}'
)"
image_tag="$(awk '$1 == "tag:" {gsub(/"/, "", $2); print $2}' charts/extra-codeowners/values.yaml)"
if [[ "${chart_version}" != "0.0.0-dev" || "${app_version}" != "0.0.0-dev" || \
  -n "${image_tag}" ]]; then
  printf 'Chart source must retain development version placeholders.\n' >&2
  exit 1
fi

helm lint charts/extra-codeowners

helm template extra-codeowners charts/extra-codeowners >"${output}/default.yaml"
helm template extra-codeowners charts/extra-codeowners \
  --set existingSecret=extra-codeowners-runtime \
  --set ingress.enabled=true \
  --set ingress.className=nginx \
  --set autoscaling.enabled=true \
  --set podDisruptionBudget.enabled=true \
  --set allowInsecureChanges=true \
  --set-string 'deploymentAnnotations.reloader\.stakater\.com/auto=true' \
  >"${output}/optional.yaml"
helm template extra-codeowners charts/extra-codeowners \
  --set existingSecret=extra-codeowners-runtime \
  --set extraVolumes[0].name=github-credentials \
  --set extraVolumes[0].secret.secretName=extra-codeowners-github \
  --set extraVolumeMounts[0].name=github-credentials \
  --set extraVolumeMounts[0].mountPath=/run/secrets/extra-codeowners \
  --set extraVolumeMounts[0].readOnly=true \
  --set migrations.existingSecret=extra-codeowners-database \
  --set migrations.extraVolumes[0].name=migration-credentials \
  --set migrations.extraVolumes[0].secret.secretName=extra-codeowners-migration-credentials \
  --set migrations.extraVolumeMounts[0].name=migration-credentials \
  --set migrations.extraVolumeMounts[0].mountPath=/run/secrets/extra-codeowners/database \
  --set migrations.extraVolumeMounts[0].readOnly=true \
  >"${output}/credentials.yaml"
helm template extra-codeowners charts/extra-codeowners \
  --set migrations.asHelmHook=false \
  --set-json 'migrations.annotations={"argocd.argoproj.io/sync-wave":"-1"}' \
  --show-only templates/migration-job.yaml \
  >"${output}/controller-migration.yaml"
helm template extra-codeowners charts/extra-codeowners \
  --values tests/fixtures/helm-extra-manifests.yaml \
  --show-only templates/extra-manifests.yaml \
  >"${output}/extra-manifests.yaml"
helm template extra-codeowners charts/extra-codeowners \
  --set deploymentStrategy.type=RollingUpdate \
  --set deploymentStrategy.rollingUpdate.maxUnavailable=0 \
  --set deploymentStrategy.rollingUpdate.maxSurge=1 \
  >"${output}/rolling-update.yaml"

grep -Fq 'reloader.stakater.com/auto: "true"' "${output}/optional.yaml"
grep -Fq 'argocd.argoproj.io/sync-wave: "-1"' "${output}/controller-migration.yaml"
grep -Fq '"argocd.argoproj.io/hook": Sync' "${output}/controller-migration.yaml"
grep -Fq 'kind: ExternalSecret' "${output}/extra-manifests.yaml"
grep -Fq '{{ .password }}' "${output}/extra-manifests.yaml"

for rendered in default optional credentials rolling-update; do
  grep -Fq 'runAsNonRoot: true' "${output}/${rendered}.yaml"
  grep -Fq 'readOnlyRootFilesystem: true' "${output}/${rendered}.yaml"
  grep -Fq 'allowPrivilegeEscalation: false' "${output}/${rendered}.yaml"
done

if grep -Eq 'extra-codeowners-(runtime|github)|github-credentials' \
  "${output}/controller-migration.yaml"; then
  printf 'Migration Job inherited runtime GitHub credentials.\n' >&2
  exit 1
fi

reject_values() {
  local description="$1"
  shift
  if helm template extra-codeowners charts/extra-codeowners "$@" >/dev/null 2>&1; then
    printf 'Chart accepted unsafe values: %s.\n' "${description}" >&2
    exit 1
  fi
}

reject_values 'insecure-mode environment override' \
  --set-string extraEnv[0].name=EXTRA_CODEOWNERS_ALLOW_INSECURE_CHANGES \
  --set-string extraEnv[0].value=true
reject_values 'runtime ambient libpq environment' \
  --set-string extraEnv[0].name=PGHOST \
  --set-string extraEnv[0].value=database.example.com
reject_values 'runtime interpreter injection' \
  --set-string extraEnv[0].name=PYTHONPATH \
  --set-string extraEnv[0].value=/run/secrets/extra-codeowners
reject_values 'runtime loader injection' \
  --set-string extraEnv[0].name=LD_PRELOAD \
  --set-string extraEnv[0].value=/run/secrets/extra-codeowners/injected.so
reject_values 'runtime uninspectable environment source' \
  --set-string extraEnvFrom[0].secretRef.name=uninspectable
reject_values 'migration hook override' \
  --set-string 'migrations.annotations.helm\.sh/hook=post-install'
reject_values 'migration ambient libpq environment' \
  --set-string migrations.extraEnv[0].name=PGSERVICE \
  --set-string migrations.extraEnv[0].value=database
reject_values 'migration loader injection' \
  --set-string migrations.extraEnv[0].name=LD_LIBRARY_PATH \
  --set-string migrations.extraEnv[0].value=/run/secrets/extra-codeowners
reject_values 'build identity mount override' \
  --set-string extraVolumeMounts[0].name=other \
  --set-string extraVolumeMounts[0].mountPath=/app/build-identity.json
reject_values 'runtime interpreter mount override' \
  --set-string extraVolumeMounts[0].name=other \
  --set-string extraVolumeMounts[0].mountPath=/opt/venv/lib \
  --set extraVolumeMounts[0].readOnly=true
reject_values 'runtime writable secret mount' \
  --set-string extraVolumeMounts[0].name=other \
  --set-string extraVolumeMounts[0].mountPath=/run/secrets/extra-codeowners/other \
  --set extraVolumeMounts[0].readOnly=false
reject_values 'secret mount path escape' \
  --set-string extraVolumeMounts[0].name=other \
  --set-string extraVolumeMounts[0].mountPath=/run/secrets/extra-codeowners/../../../opt/venv \
  --set extraVolumeMounts[0].readOnly=true
reject_values 'rolling-update settings on Recreate' \
  --set deploymentStrategy.rollingUpdate.maxSurge=1
reject_values 'Secret in extraManifests' \
  --set-json 'extraManifests=[{"apiVersion":"v1","kind":"Secret","metadata":{"name":"rejected"}}]'

helm package charts/extra-codeowners --destination "${output}" >/dev/null
