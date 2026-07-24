{{/* Expand the chart name. */}}
{{- define "extra-codeowners.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Create a default fully qualified app name. */}}
{{- define "extra-codeowners.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/* Create the chart label. */}}
{{- define "extra-codeowners.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Common labels. */}}
{{- define "extra-codeowners.labels" -}}
helm.sh/chart: {{ include "extra-codeowners.chart" . }}
{{ include "extra-codeowners.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/* Selector labels. */}}
{{- define "extra-codeowners.selectorLabels" -}}
app.kubernetes.io/name: {{ include "extra-codeowners.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/* Application-only labels keep one-shot hooks out of Services and PDBs. */}}
{{- define "extra-codeowners.applicationSelectorLabels" -}}
{{ include "extra-codeowners.selectorLabels" . }}
app.kubernetes.io/component: application
{{- end }}

{{/* Service account name. */}}
{{- define "extra-codeowners.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "extra-codeowners.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/* Immutable digest or versioned image reference. */}}
{{- define "extra-codeowners.image" -}}
{{- if .Values.image.digest }}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest }}
{{- else }}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) }}
{{- end }}
{{- end }}

{{/* Reject extension values that shadow chart-owned security contracts. */}}
{{- define "extra-codeowners.validateValues" -}}
{{- if or (hasKey .Values.podLabels "app.kubernetes.io/name") (hasKey .Values.podLabels "app.kubernetes.io/instance") (hasKey .Values.podLabels "app.kubernetes.io/component") -}}
{{- fail "podLabels must not override app.kubernetes.io/name, app.kubernetes.io/instance, or app.kubernetes.io/component" -}}
{{- end -}}
{{- if .Values.extraEnvFrom -}}
{{- fail "extraEnvFrom is unsupported because EnvFromSource keys cannot be validated; use extraEnv with explicit names and valueFrom references" -}}
{{- end -}}
{{- range .Values.extraEnv -}}
{{- if or (eq .name "EXTRA_CODEOWNERS_ENVIRONMENT") (eq .name "EXTRA_CODEOWNERS_ALLOW_INSECURE_CHANGES") -}}
{{- fail (printf "extraEnv must not override chart-managed variable %s" .name) -}}
{{- end -}}
{{- if or (eq .name "PATH") (hasPrefix "PYTHON" .name) (hasPrefix "LD_" .name) (hasPrefix "DYLD_" .name) (eq .name "GCONV_PATH") (eq .name "LOCPATH") (hasPrefix "OPENSSL_" .name) (eq .name "SSLKEYLOGFILE") -}}
{{- fail (printf "extraEnv must not set interpreter or loader variable %s" .name) -}}
{{- end -}}
{{- end -}}
{{- range .Values.extraVolumes -}}
{{- if eq .name "tmp" -}}
{{- fail "extraVolumes must not override the chart-managed tmp volume" -}}
{{- end -}}
{{- end -}}
{{- range .Values.extraVolumeMounts -}}
{{- $mountPath := clean .mountPath -}}
{{- if not (or (eq $mountPath "/run/secrets/extra-codeowners") (hasPrefix "/run/secrets/extra-codeowners/" $mountPath)) -}}
{{- fail "extraVolumeMounts are limited to /run/secrets/extra-codeowners" -}}
{{- end -}}
{{- if not (default false .readOnly) -}}
{{- fail "extraVolumeMounts must be read-only" -}}
{{- end -}}
{{- end -}}
{{- if .Values.migrations.extraEnvFrom -}}
{{- fail "migrations.extraEnvFrom is unsupported because EnvFromSource keys cannot be validated; use migrations.extraEnv with explicit names and valueFrom references" -}}
{{- end -}}
{{- range .Values.migrations.extraEnv -}}
{{- if eq .name "EXTRA_CODEOWNERS_ENVIRONMENT" -}}
{{- fail "migrations.extraEnv must not override chart-managed variable EXTRA_CODEOWNERS_ENVIRONMENT" -}}
{{- end -}}
{{- if or (eq .name "PATH") (hasPrefix "PYTHON" .name) (hasPrefix "LD_" .name) (hasPrefix "DYLD_" .name) (eq .name "GCONV_PATH") (eq .name "LOCPATH") (hasPrefix "OPENSSL_" .name) (eq .name "SSLKEYLOGFILE") -}}
{{- fail (printf "migrations.extraEnv must not set interpreter or loader variable %s" .name) -}}
{{- end -}}
{{- end -}}
{{- range .Values.migrations.extraVolumes -}}
{{- if eq .name "tmp" -}}
{{- fail "migrations.extraVolumes must not override the chart-managed tmp volume" -}}
{{- end -}}
{{- end -}}
{{- range .Values.migrations.extraVolumeMounts -}}
{{- $mountPath := clean .mountPath -}}
{{- if not (or (eq $mountPath "/run/secrets/extra-codeowners") (hasPrefix "/run/secrets/extra-codeowners/" $mountPath) (eq $mountPath "/run/secrets/database-ca") (hasPrefix "/run/secrets/database-ca/" $mountPath)) -}}
{{- fail "migrations.extraVolumeMounts are limited to /run/secrets/extra-codeowners or /run/secrets/database-ca" -}}
{{- end -}}
{{- if not (default false .readOnly) -}}
{{- fail "migrations.extraVolumeMounts must be read-only" -}}
{{- end -}}
{{- end -}}
{{- range $name, $_ := .Values.migrations.annotations -}}
{{- if or (eq $name "helm.sh/hook") (eq $name "helm.sh/hook-weight") (eq $name "helm.sh/hook-delete-policy") -}}
{{- fail (printf "migrations.annotations must not override chart-managed annotation %s" $name) -}}
{{- end -}}
{{- end -}}
{{- end }}
