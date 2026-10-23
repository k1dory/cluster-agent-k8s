{{- define "agent-sandbox.name" -}}agent-sandbox{{- end -}}
{{- define "agent-sandbox.fullname" -}}{{ .Release.Name }}-sandboxd{{- end -}}
{{- define "agent-sandbox.agentNamespace" -}}{{ default .Release.Namespace .Values.agent.namespace }}{{- end -}}
{{- define "agent-sandbox.labels" -}}
app.kubernetes.io/name: {{ include "agent-sandbox.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}
{{- define "agent-sandbox.selector" -}}
app.kubernetes.io/name: {{ include "agent-sandbox.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
