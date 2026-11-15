package twin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestModelAndReportCarryStandardizedResourceEvidence(t *testing.T) {
	m := fittedModel(t)
	v := 42.5
	m.ResourceEvidence = &ResourceAvailability{
		SchemaVersion: "sift.resource-evidence/v1",
		Source:        "hostxray-derived",
		Available:     true,
		Metrics:       []string{"cpu"},
		Missing:       []string{"memory"},
		Values:        map[string]float64{"cpu": v},
		MetricsDetail: map[string]ResourceMetricEvidence{
			"cpu":    {Name: "cpu", Status: "available", Value: &v, Unit: "percent", Source: "hostxray.proc", ObservedAt: "2026-01-01T00:00:02Z", ObservedWindowStart: "2026-01-01T00:00:00Z", ObservedWindowEnd: "2026-01-01T00:00:02Z"},
			"memory": {Name: "memory", Status: "unavailable", Unit: "percent", Source: "hostxray", Reason: "memory counters unavailable"},
		},
		ObservedWindowStart: "2026-01-01T00:00:00Z",
		ObservedWindowEnd:   "2026-01-01T00:00:02Z",
	}
	dir := t.TempDir()
	modelPath, err := WriteModel(dir, m)
	if err != nil {
		t.Fatalf("WriteModel: %v", err)
	}
	loaded, err := LoadModel(modelPath)
	if err != nil {
		t.Fatalf("LoadModel: %v", err)
	}
	if loaded.ResourceEvidence == nil {
		t.Fatal("resource evidence not preserved in model")
	}
	if loaded.ResourceEvidence.MetricsDetail["memory"].Status != "unavailable" || loaded.ResourceEvidence.MetricsDetail["memory"].Reason == "" {
		t.Fatalf("standardized detail not preserved: %+v", loaded.ResourceEvidence.MetricsDetail["memory"])
	}
	if loaded.ResourceEvidence.ObservedWindowStart == "" || loaded.ResourceEvidence.SchemaVersion == "" {
		t.Fatalf("evidence metadata not preserved: %+v", loaded.ResourceEvidence)
	}

	results := sampleResults(t, m)
	paths, err := WriteArtifacts(dir, m, results)
	if err != nil {
		t.Fatalf("WriteArtifacts: %v", err)
	}
	md, err := os.ReadFile(paths.ReportPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(md)
	for _, want := range []string{"Resource monitoring evidence", "unavailable", "memory counters unavailable", "hostxray-derived"} {
		if !strings.Contains(text, want) {
			t.Fatalf("markdown missing %q\n%s", want, text)
		}
	}
	_ = filepath.Base(modelPath)
}
