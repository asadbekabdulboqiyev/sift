package twin

import (
	"encoding/json"
	"testing"
)

func TestValidateAndNormalizeLegacyV1Model(t *testing.T) {
	// Minimal legacy v1-shaped model; normalization should upgrade to v2 semantics.
	v1 := map[string]any{
		"schema_version": SchemaVersionV1,
		"source": map[string]any{
			"report_name": "legacy", "target_url": "http://example", "load_profile": "steady",
			"started_at": "2026-01-01T00:00:00Z", "ended_at": "2026-01-01T00:01:00Z",
			"duration_seconds": 60.0, "producer": "sift",
		},
		"workload": map[string]any{
			"rps": 100.0, "concurrency": 10.0, "active_users": 10, "duration_seconds": 60.0,
			"open_loop": true, "total_requests": 6000, "total_errors": 0, "error_rate_pct": 0.0,
		},
		"service_curve": map[string]any{
			"baseline_latency": map[string]any{"p50_ms": 10.0, "p95_ms": 20.0, "p99_ms": 30.0, "avg_ms": 12.0},
			"capacity_rps":     200.0, "capacity_low_rps": 150.0, "capacity_high_rps": 250.0,
			"capacity_relative_uncertainty": 0.25, "reference_utilization": 0.5,
			"degradation_shape": "mm1-tail", "queue_scale_ms": 14.4,
		},
		"confidence":  string(ConfidenceMedium),
		"calibration": map[string]any{"method": "mm1-tail", "fitted_at": "2026-01-01T00:01:00Z", "target_p99_ms": 200.0},
	}
	b, err := json.Marshal(v1)
	if err != nil {
		t.Fatal(err)
	}
	var m Model
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal v1: %v", err)
	}
	nm, err := ValidateAndNormalize(m)
	if err != nil {
		t.Fatalf("ValidateAndNormalize(v1): %v", err)
	}
	if nm.SchemaVersion != SchemaVersion {
		t.Fatalf("schema = %q, want %q", nm.SchemaVersion, SchemaVersion)
	}
	if nm.ConfidenceV2 == nil {
		t.Fatal("expected normalized ConfidenceV2")
	}
	if nm.Capacity == nil {
		t.Fatal("expected normalized Capacity assessment")
	}
	if nm.ModelInfo == nil {
		t.Fatal("expected normalized ModelInfo")
	}
	// Round-trip through JSON
	b2, err := json.Marshal(nm)
	if err != nil {
		t.Fatal(err)
	}
	var m2 Model
	if err := json.Unmarshal(b2, &m2); err != nil {
		t.Fatalf("unmarshal normalized: %v", err)
	}
	if _, err := ValidateAndNormalize(m2); err != nil {
		t.Fatalf("re-validate normalized: %v", err)
	}
}
