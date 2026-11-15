package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/config"
	"github.com/asadbekabdulboqiyev/sift/internal/hostxray"
	"github.com/asadbekabdulboqiyev/sift/internal/metrics"
	"github.com/asadbekabdulboqiyev/sift/internal/report"
)

func TestRunResourceEvidenceFileAttachmentPath(t *testing.T) {
	dir := t.TempDir()
	evPath := filepath.Join(dir, "resource-evidence.json")
	ev := map[string]any{
		"schema_version": "sift.resource-evidence/v1",
		"metrics": map[string]any{
			"memory_growth_pct": map[string]any{
				"status": "insufficient_data",
				"reason": "need >=2 memory samples with used percent to derive memory growth",
				"unit":   "percentage_points",
				"source": "hostxray",
			},
		},
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(evPath, b, 0o600); err != nil {
		t.Fatal(err)
	}

	tel := metrics.NewTelemetry()
	step := metrics.NewStepStats("s")
	step.Record(10*time.Millisecond, 200, "")
	tel.AddStep(step)
	tel.Overall.Record(10*time.Millisecond, 200, "")
	tel.Finish()
	sc := &config.Scenario{Name: "run-attach", BaseURL: "http://x", Profile: config.Profile{Type: config.ProfileSteady}}
	r := report.Build(tel, sc)

	// Mirrors cmdRun --resource-evidence-file handling.
	raw, err := os.ReadFile(evPath)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(raw) {
		t.Fatal("evidence file not valid json")
	}
	r.ResourceEvidence = json.RawMessage(raw)
	out, err := r.SaveJSON(dir)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(saved, &got); err != nil {
		t.Fatal(err)
	}
	re, ok := got["resource_evidence"].(map[string]any)
	if !ok {
		t.Fatalf("resource_evidence missing: %#v", got["resource_evidence"])
	}
	metricsMap, _ := re["metrics"].(map[string]any)
	mg, _ := metricsMap["memory_growth_pct"].(map[string]any)
	if mg["status"] != "insufficient_data" || mg["reason"] == "" {
		t.Fatalf("insufficient_data distinction/reason not preserved: %#v", mg)
	}
}

func TestXrayReportEvidenceOutProducesConsistentDerivedEvidence(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	samples := []hostxray.Sample{
		{Timestamp: base, CPU: hostxray.CPUStats{UtilizationPct: 30, Available: true}, Mem: hostxray.MemoryStats{UsedPct: 40, Available: true}},
		{Timestamp: base.Add(3 * time.Second), CPU: hostxray.CPUStats{UtilizationPct: 50, Available: true}, Mem: hostxray.MemoryStats{UsedPct: 45, Available: true}},
	}
	caps := hostxray.Capabilities{ProcStat: true, ProcMemInfo: true, ProcNetDev: true}

	// Mirrors cmdXrayReport --evidence-out path.
	derived := hostxray.DeriveResourceEvidence(samples, caps)
	ePath := filepath.Join(dir, "evidence.json")
	b, err := json.MarshalIndent(derived, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ePath, append(b, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(ePath)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got["schema_version"] == "" || got["source"] == "" {
		t.Fatalf("missing standardized top-level fields: %#v", got)
	}
	ms, _ := got["metrics"].(map[string]any)
	for name, v := range ms {
		m, _ := v.(map[string]any)
		status, _ := m["status"].(string)
		if status == "" || m["unit"] == "" || m["source"] == "" {
			t.Fatalf("metric %s missing status/unit/source: %#v", name, m)
		}
		if status != "available" && m["reason"] == "" {
			t.Fatalf("metric %s non-available without reason: %#v", name, m)
		}
	}
	mg, _ := ms["memory_growth_pct"].(map[string]any)
	if mg["status"] != "available" {
		t.Fatalf("memory growth expected available with 2 samples: %#v", mg)
	}
}
