// Copyright 2026 The OpenChoreo Authors
// SPDX-License-Identifier: Apache-2.0

package openobserve

import (
	"strings"
	"testing"
	"time"
)

const auditLine = `{"time":"2026-09-16T12:00:00.654321Z","level":"INFO","msg":"AUDIT-LOG",` +
	`"schema_version":"1.0","event_id":"0192-a","event_time":"2026-09-16T12:00:00.654321Z",` +
	`"actor":{"type":"user","id":"alice","issuer":"https://idp","entitlements":{"groups":["admins"]}},` +
	`"action":"create_project","category":"management","result":"success","producer":"openchoreo-api",` +
	`"resource":{"type":"project","namespace":"default","metadata":{"a":{"b":{"c":{"d":1}}}}}}`

func TestParseAuditRecord_ReadsTheRecordFromTheLogLine(t *testing.T) {
	record, err := ParseAuditRecord(map[string]interface{}{
		"log":                       auditLine,
		"actor_id":                  "flattened columns are not the source",
		"kubernetes_namespace_name": "openchoreo-control-plane",
		"kubernetes_pod_name":       "api-0",
		"kubernetes_container_name": "api-server",
	})
	if err != nil {
		t.Fatal(err)
	}

	if record.Actor.ID != "alice" || record.Actor.Entitlements["groups"][0] != "admins" {
		t.Errorf("actor = %+v", record.Actor)
	}
	if want := time.Date(2026, 9, 16, 12, 0, 0, 654321000, time.UTC); !record.EventTime.Equal(want) {
		t.Errorf("event_time = %s, want %s", record.EventTime, want)
	}
	if record.Resource == nil || record.Resource.Metadata["a"] == nil {
		t.Errorf("resource = %+v, want metadata nested past the flatten level intact", record.Resource)
	}
	if record.Collector != (AuditCollectorInfo{
		NamespaceName: "openchoreo-control-plane", PodName: "api-0", ContainerName: "api-server",
	}) {
		t.Errorf("collector = %+v", record.Collector)
	}
}

func TestParseAuditRecord_RejectsARowWithoutAnIdentity(t *testing.T) {
	for _, field := range []string{`"event_id":"0192-a",`, `"result":"success",`, `"schema_version":"1.0",`} {
		line := strings.Replace(auditLine, field, "", 1)
		if _, err := ParseAuditRecord(map[string]interface{}{"log": line}); err == nil {
			t.Errorf("expected a line without %s to be rejected", field)
		}
	}
}

func TestParseAuditRecord_KeepsARecordWithNoResolvedAction(t *testing.T) {
	line := strings.Replace(auditLine, `"action":"create_project","category":"management",`, "", 1)
	record, err := ParseAuditRecord(map[string]interface{}{"log": line})
	if err != nil {
		t.Fatalf("expected an unauthenticated rejection to be kept: %v", err)
	}
	if record.Action != "" || record.Category != "" {
		t.Errorf("action = %q, category = %q", record.Action, record.Category)
	}
}

func TestParseAuditRecord_RejectsARowWithoutALogLine(t *testing.T) {
	for _, row := range []map[string]interface{}{{}, {"log": ""}, {"log": "not json"}} {
		if _, err := ParseAuditRecord(row); err == nil {
			t.Errorf("expected %v to be rejected", row)
		}
	}
}
