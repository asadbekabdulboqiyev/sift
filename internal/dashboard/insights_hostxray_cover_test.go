package dashboard

// Table-driven coverage for the pure resource-evidence conversion helper in
// insights_hostxray.go. This helper has no handler or environment dependencies.

import (
	"math"
	"testing"

	"github.com/asadbekabdulboqiyev/sift/internal/hostxray"
)

func floatPtr(v float64) *float64 { return &v }

func TestResourceEvidenceToTwinTable(t *testing.T) {
	const observed = "2026-01-01T00:00:00Z"

	tests := []struct {
		name         string
		derived      hostxray.DerivedResourceEvidence
		source       string
		wantSource   string
		wantSchema   string
		wantAvail    []string
		wantMissing  []string
		wantValue    map[string]float64
		wantStatus   map[string]string
		wantName     map[string]string
		wantNilValue map[string]bool
	}{
		{
			name:       "empty evidence gets defaults",
			derived:    hostxray.DerivedResourceEvidence{},
			source:     "  ",
			wantSource: "hostxray-derived",
			wantSchema: "sift.resource-evidence/v1",
		},
		{
			name: "derived source is used when override is blank",
			derived: hostxray.DerivedResourceEvidence{
				Source:        "hostxray.proc",
				SchemaVersion: "custom/v2",
				Metrics:       map[string]hostxray.ResourceMetricEvidence{},
			},
			source:     "  ",
			wantSource: "hostxray.proc",
			wantSchema: "custom/v2",
		},
		{
			name: "explicit source overrides derived source",
			derived: hostxray.DerivedResourceEvidence{
				Source:  "hostxray.proc",
				Metrics: map[string]hostxray.ResourceMetricEvidence{},
			},
			source:     "user-supplied",
			wantSource: "user-supplied",
			wantSchema: "sift.resource-evidence/v1",
		},
		{
			name: "available finite values are exposed",
			derived: hostxray.DerivedResourceEvidence{
				Metrics: map[string]hostxray.ResourceMetricEvidence{
					"cpu": {Name: "cpu_utilization_pct", Status: hostxray.ResourceStatusAvailable, Value: floatPtr(42.5), Unit: "percent"},
					"mem": {Name: "memory_utilization_pct", Status: hostxray.ResourceStatusAvailable, Value: floatPtr(61), Unit: "percent"},
				},
			},
			wantSource: "hostxray-derived",
			wantSchema: "sift.resource-evidence/v1",
			wantAvail:  []string{"cpu", "mem"},
			wantValue:  map[string]float64{"cpu": 42.5, "mem": 61},
			wantStatus: map[string]string{"cpu": "available", "mem": "available"},
			wantName:   map[string]string{"cpu": "cpu_utilization_pct", "mem": "memory_utilization_pct"},
		},
		{
			name: "non-finite values are downgraded to insufficient data",
			derived: hostxray.DerivedResourceEvidence{
				Metrics: map[string]hostxray.ResourceMetricEvidence{
					"nan":  {Status: hostxray.ResourceStatusAvailable, Value: floatPtr(math.NaN())},
					"inf":  {Status: hostxray.ResourceStatusAvailable, Value: floatPtr(math.Inf(1))},
					"ninf": {Status: hostxray.ResourceStatusAvailable, Value: floatPtr(math.Inf(-1))},
				},
			},
			wantSource:   "hostxray-derived",
			wantSchema:   "sift.resource-evidence/v1",
			wantMissing:  []string{"inf", "nan", "ninf"},
			wantStatus:   map[string]string{"nan": "insufficient_data", "inf": "insufficient_data", "ninf": "insufficient_data"},
			wantName:     map[string]string{"nan": "nan", "inf": "inf", "ninf": "ninf"},
			wantNilValue: map[string]bool{"nan": true, "inf": true, "ninf": true},
		},
		{
			name: "nil value on an available metric is downgraded",
			derived: hostxray.DerivedResourceEvidence{
				Metrics: map[string]hostxray.ResourceMetricEvidence{
					"growth": {Status: hostxray.ResourceStatusAvailable, Reason: "custom reason"},
				},
			},
			wantSource:   "hostxray-derived",
			wantSchema:   "sift.resource-evidence/v1",
			wantMissing:  []string{"growth"},
			wantStatus:   map[string]string{"growth": "insufficient_data"},
			wantName:     map[string]string{"growth": "growth"},
			wantNilValue: map[string]bool{"growth": true},
		},
		{
			name: "non-available status keeps its own status",
			derived: hostxray.DerivedResourceEvidence{
				Metrics: map[string]hostxray.ResourceMetricEvidence{
					"disk": {Status: hostxray.ResourceStatusUnavailable, Reason: "no sampler", Value: floatPtr(5)},
				},
			},
			wantSource:  "hostxray-derived",
			wantSchema:  "sift.resource-evidence/v1",
			wantMissing: []string{"disk"},
			wantStatus:  map[string]string{"disk": "unavailable"},
			wantName:    map[string]string{"disk": "disk"},
		},
		{
			name: "metadata and notes are carried through",
			derived: hostxray.DerivedResourceEvidence{
				SampleCount:         7,
				ObservedAt:          observed,
				ObservedWindowStart: "2026-01-01T00:00:00Z",
				ObservedWindowEnd:   "2026-01-01T00:01:00Z",
				Notes:               []string{"derived note"},
				Metrics: map[string]hostxray.ResourceMetricEvidence{
					"cpu": {
						Name:                   "cpu_utilization_pct",
						Status:                 hostxray.ResourceStatusAvailable,
						Value:                  floatPtr(10),
						ObservationSampleCount: 7,
						ObservedAt:             observed,
						Notes:                  []string{"metric note"},
					},
				},
			},
			wantSource: "hostxray-derived",
			wantSchema: "sift.resource-evidence/v1",
			wantAvail:  []string{"cpu"},
			wantValue:  map[string]float64{"cpu": 10},
			wantStatus: map[string]string{"cpu": "available"},
			wantName:   map[string]string{"cpu": "cpu_utilization_pct"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := resourceEvidenceToTwin(tc.derived, tc.source)
			if got.Source != tc.wantSource {
				t.Errorf("Source = %q, want %q", got.Source, tc.wantSource)
			}
			if got.SchemaVersion != tc.wantSchema {
				t.Errorf("SchemaVersion = %q, want %q", got.SchemaVersion, tc.wantSchema)
			}
			if !equalStrings(got.Metrics, tc.wantAvail) {
				t.Errorf("Metrics = %v, want %v", got.Metrics, tc.wantAvail)
			}
			if !equalStrings(got.Missing, tc.wantMissing) {
				t.Errorf("Missing = %v, want %v", got.Missing, tc.wantMissing)
			}
			if len(got.Values) != len(tc.wantValue) {
				t.Errorf("Values = %v, want %v", got.Values, tc.wantValue)
			}
			for k, v := range tc.wantValue {
				if got.Values[k] != v {
					t.Errorf("Values[%q] = %v, want %v", k, got.Values[k], v)
				}
			}
			for k, want := range tc.wantStatus {
				detail, ok := got.MetricsDetail[k]
				if !ok {
					t.Errorf("MetricsDetail[%q] is missing", k)
					continue
				}
				if detail.Status != want {
					t.Errorf("MetricsDetail[%q].Status = %q, want %q", k, detail.Status, want)
				}
				if want == "insufficient_data" && detail.Reason == "" {
					t.Errorf("MetricsDetail[%q].Reason is empty for downgraded status", k)
				}
			}
			for k, want := range tc.wantName {
				if detail, ok := got.MetricsDetail[k]; !ok || detail.Name != want {
					t.Errorf("MetricsDetail[%q].Name = %q, want %q", k, detail.Name, want)
				}
			}
			for k := range tc.wantNilValue {
				if detail, ok := got.MetricsDetail[k]; !ok || detail.Value != nil {
					t.Errorf("MetricsDetail[%q].Value = %v, want nil", k, detail.Value)
				}
			}
		})
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestResourceEvidenceToTwinCopiesMetadata(t *testing.T) {
	derived := hostxray.DerivedResourceEvidence{
		SampleCount: 3,
		ObservedAt:  "2026-01-01T00:00:00Z",
		Notes:       []string{"note"},
		Metrics: map[string]hostxray.ResourceMetricEvidence{
			"cpu": {Status: hostxray.ResourceStatusAvailable, Value: floatPtr(1), Notes: []string{"metric note"}},
		},
	}
	got := resourceEvidenceToTwin(derived, "")
	if got.SampleCount != 3 || got.ObservedAt != "2026-01-01T00:00:00Z" {
		t.Fatalf("sample/observed fields = (%d, %q), want (3, timestamp)", got.SampleCount, got.ObservedAt)
	}
	if !equalStrings(got.Notes, []string{"note"}) {
		t.Fatalf("Notes = %v, want [note]", got.Notes)
	}
	derived.Notes[0] = "mutated"
	derived.Metrics["cpu"].Notes[0] = "mutated"
	if got.Notes[0] != "note" || got.MetricsDetail["cpu"].Notes[0] != "metric note" {
		t.Fatal("resourceEvidenceToTwin did not copy note slices")
	}
}
