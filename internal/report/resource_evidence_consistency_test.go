package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/config"
	"github.com/asadbekabdulboqiyev/sift/internal/metrics"
)

func TestBuildAndSaveJSON_AttachedResourceEvidencePreserved(t *testing.T) {
	tel := metrics.NewTelemetry()
	step := metrics.NewStepStats("s")
	step.Record(10*time.Millisecond, 200, "")
	tel.AddStep(step)
	tel.Overall.Record(10*time.Millisecond, 200, "")
	tel.Finish()
	sc := &config.Scenario{Name: "run-evidence", BaseURL: "http://x", Profile: config.Profile{Type: config.ProfileSteady}}
	r := Build(tel, sc)

	// Mirrors run --resource-evidence-file attachment path.
	ev := []byte(`{"schema_version":"sift.resource-evidence/v1","metrics":{"cpu":{"status":"unavailable","reason":"not provided","unit":"percent","source":"manual"}}}`)
	if !json.Valid(ev) {
		t.Fatal("test evidence not valid json")
	}
	r.ResourceEvidence = json.RawMessage(ev)

	dir := t.TempDir()
	path, err := r.SaveJSON(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	re, ok := got["resource_evidence"].(map[string]any)
	if !ok {
		t.Fatalf("resource_evidence missing or wrong type: %#v", got["resource_evidence"])
	}
	if re["schema_version"] != "sift.resource-evidence/v1" {
		t.Fatalf("unexpected resource_evidence: %#v", re)
	}
	// round-trip parse as Report preserves raw JSON field
	loaded, err := LoadReport(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(loaded.ResourceEvidence) == "" || !json.Valid(loaded.ResourceEvidence) {
		t.Fatalf("loaded resource evidence missing/invalid: %q", string(loaded.ResourceEvidence))
	}
	_ = filepath.Base(path)
}
