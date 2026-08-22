{{/*
Expand the name of the chart.
*/}}
{{- define "veeam-exporter.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "veeam-exporter.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Chart name and version as used by the chart label.
*/}}
{{- define "veeam-exporter.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "veeam-exporter.labels" -}}
helm.sh/chart: {{ include "veeam-exporter.chart" . }}
{{ include "veeam-exporter.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: {{ include "veeam-exporter.name" . }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "veeam-exporter.selectorLabels" -}}
app.kubernetes.io/name: {{ include "veeam-exporter.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Name of the service account to use.
*/}}
{{- define "veeam-exporter.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "veeam-exporter.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Name of the secret holding Veeam credentials.
*/}}
{{- define "veeam-exporter.secretName" -}}
{{- default (include "veeam-exporter.fullname" .) .Values.veeam.auth.existingSecret }}
{{- end }}
