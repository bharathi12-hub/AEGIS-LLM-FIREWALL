{{- define "aegis.name" -}}aegis{{- end -}}
{{- define "aegis.fullname" -}}{{ .Release.Name }}-aegis{{- end -}}
{{- define "aegis.labels" -}}
app.kubernetes.io/name: {{ include "aegis.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
{{- define "aegis.selectorLabels" -}}
app.kubernetes.io/name: {{ include "aegis.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
