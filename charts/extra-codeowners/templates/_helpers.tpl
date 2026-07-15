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
{{- range .Values.extraEnv -}}
{{- if or (eq .name "EXTRA_CODEOWNERS_ENVIRONMENT") (eq .name "EXTRA_CODEOWNERS_ALLOW_INSECURE_CHANGES") -}}
{{- fail (printf "extraEnv must not override chart-managed variable %s" .name) -}}
{{- end -}}
{{- end -}}
{{- range .Values.extraVolumes -}}
{{- if eq .name "tmp" -}}
{{- fail "extraVolumes must not override the chart-managed tmp volume" -}}
{{- end -}}
{{- end -}}
{{- range .Values.extraVolumeMounts -}}
{{- if or (eq .name "tmp") (eq .mountPath "/tmp") -}}
{{- fail "extraVolumeMounts must not override the chart-managed /tmp mount" -}}
{{- end -}}
{{- end -}}
{{- range .Values.migrations.extraEnv -}}
{{- if eq .name "EXTRA_CODEOWNERS_ENVIRONMENT" -}}
{{- fail "migrations.extraEnv must not override chart-managed variable EXTRA_CODEOWNERS_ENVIRONMENT" -}}
{{- end -}}
{{- end -}}
{{- range .Values.migrations.extraVolumes -}}
{{- if eq .name "tmp" -}}
{{- fail "migrations.extraVolumes must not override the chart-managed tmp volume" -}}
{{- end -}}
{{- end -}}
{{- range .Values.migrations.extraVolumeMounts -}}
{{- if or (eq .name "tmp") (eq .mountPath "/tmp") -}}
{{- fail "migrations.extraVolumeMounts must not override the chart-managed /tmp mount" -}}
{{- end -}}
{{- end -}}
{{- range $name, $_ := .Values.migrations.annotations -}}
{{- if or (eq $name "helm.sh/hook") (eq $name "helm.sh/hook-weight") (eq $name "helm.sh/hook-delete-policy") -}}
{{- fail (printf "migrations.annotations must not override chart-managed annotation %s" $name) -}}
{{- end -}}
{{- end -}}
{{- end }}
