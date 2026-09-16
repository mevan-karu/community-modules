{{/*
Copyright 2026 The OpenChoreo Authors
SPDX-License-Identifier: Apache-2.0
*/}}

{{/*
Return common.openObserveAuditStream. OpenObserve rewrites other characters to "_" on
ingest, which would leave the adapter and setup job reading a different stream.

Usage: {{ include "observability-logs-openobserve.auditStream" . }}
*/}}
{{- define "observability-logs-openobserve.auditStream" -}}
{{- $stream := .Values.common.openObserveAuditStream -}}
{{- if not (regexMatch "^[a-z0-9_]+$" ($stream | toString)) -}}
{{- fail (printf "common.openObserveAuditStream %q must contain only lowercase letters, digits and '_'" $stream) -}}
{{- end -}}
{{- $stream -}}
{{- end }}
