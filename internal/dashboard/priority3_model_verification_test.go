package dashboard

import (
	"bytes"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/hostxray"
	"github.com/asadbekabdulboqiyev/sift/internal/metrics"
	"github.com/asadbekabdulboqiyev/sift/internal/report"
	"github.com/asadbekabdulboqiyev/sift/internal/twin"
)

func syntheticDashboardTwinReport() report.Report {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return report.Report{
		Name:          "dash-benchmark",
		BaseURL:       "https://example.test",
		LoadProfile:   "constant-rps",
		StartedAt:     start,
		EndedAt:       start.Add(60 * time.Second),
		Duration:      60 * time.Second,
		TotalRequests: 12000,
		TotalErrors:   12,
		ErrorRatePct:  0.1,
		RPS:           200,
		Overall: report.StepReport{
			P50:      20 * time.Millisecond,
			P95:      45 * time.Millisecond,
			P99:      70 * time.Millisecond,
			Avg:      25 * time.Millisecond,
			Requests: 12000,
			Errors:   12,
		},
		Timeline: []metrics.TimelineSample{{Second: 1, Requests: 200}, {Second: 2, Requests: 400}, {Second: 3, Requests: 600}, {Second: 4, Requests: 800}},
	}
}

func TestPriority3_DashboardTwinBacktestIntegration_OODAndDrift(t *testing.T) {
	s := &Server{}

	body, _ := json.Marshal(map[string]any{
		"predicted":        []float64{100, 100, 100},
		"actual":           []float64{50, 100, 250},
		"model_range_low":  90,
		"model_range_high": 200,
		"model_version":    "twin-model/test",
		"dataset":          map[string]any{"kind": "pairs", "id": "hist-bench-1", "records": 3},
		"split":            map[string]any{"strategy": "time_cutoff", "train_end": "2026-01-01T00:00:00Z", "validation_dataset": "v"},
		"leakage":          map[string]any{"enforced": false, "proven": false, "reason": "test metadata"},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/insights/twin/backtest", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleInsightsTwinBacktest(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, w.Body.String())
	}
	if resp["ok"] != true {
		t.Fatalf("expected ok=true: %#v", resp)
	}
	if resp["derived_backtest_status"] != "OOD" || resp["derived_drift_status"] != "DETECTED" {
		t.Fatalf("expected OOD/DETECTED integration status: %#v", resp)
	}
	backtest, _ := resp["backtest"].(map[string]any)
	if backtest == nil || backtest["out_of_domain"] != true {
		t.Fatalf("expected out_of_domain backtest payload: %#v", resp["backtest"])
	}
	rec, _ := resp["validation_record"].(map[string]any)
	if rec == nil || rec["backtest_status"] != "OOD" {
		t.Fatalf("expected validation_record with canonical status: %#v", resp["validation_record"])
	}
}

func TestPriority3_DashboardTwinCompareIntegration_PredictionVsActual(t *testing.T) {
	s := &Server{}
	rep := syntheticDashboardTwinReport()
	m, err := twin.Fit(rep, twin.FitOptions{Producer: "dashboard-test"})
	if err != nil {
		t.Fatalf("fit: %v", err)
	}
	sc, err := twin.Preset("normal", m)
	if err != nil {
		t.Fatalf("preset: %v", err)
	}
	sc.Iterations = 50
	res, err := twin.Simulate(m, sc, 123)
	if err != nil {
		t.Fatalf("simulate: %v", err)
	}
	actual := rep
	actual.RPS = rep.RPS * 0.2
	actual.Overall.P95 = time.Duration(float64(rep.Overall.P95) * 3)
	actual.Overall.P99 = time.Duration(float64(rep.Overall.P99) * 3)
	body, _ := json.Marshal(map[string]any{
		"model":   m,
		"result":  res,
		"actual":  actual,
		"seed":    123,
		"dataset": map[string]any{"kind": "report", "id": "actual-bench"},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/insights/twin/compare", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleInsightsTwinCompare(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp["ok"] != true {
		t.Fatalf("expected ok=true: %#v", resp)
	}
	if _, ok := resp["comparison"].(map[string]any); !ok {
		t.Fatalf("expected comparison payload: %#v", resp["comparison"])
	}
	if resp["derived_validation_status"] == "OK" {
		t.Fatalf("expected non-OK derived status for mismatched actual: %#v", resp)
	}
}

func TestPriority3_DashboardResourceEvidenceNoFabrication(t *testing.T) {
	derived := hostxray.DeriveResourceEvidence(nil, hostxray.Capabilities{})
	ra := resourceEvidenceToTwin(derived, "hostxray-derived")
	if ra.Available {
		t.Fatal("resource availability must be false when no supported metrics derived")
	}
	for _, name := range []string{"network_utilization", "active_connections", "server_response_time_ms"} {
		d, ok := ra.MetricsDetail[name]
		if !ok {
			t.Fatalf("missing detail for %s", name)
		}
		if d.Status == string(hostxray.ResourceStatusAvailable) || d.Value != nil {
			t.Fatalf("unsupported metric %s must not be fabricated: %+v", name, d)
		}
	}
	if ra.MetricsDetail["memory_growth_pct"].Status != string(hostxray.ResourceStatusInsufficientData) {
		t.Fatalf("memory growth should be insufficient without samples: %+v", ra.MetricsDetail["memory_growth_pct"])
	}
	manual := twin.AssessResourceMonitoringExtended(nil, nil, nil, nil, nil, nil)
	for _, name := range []string{"cpu", "memory", "network", "connections", "server_response_time", "memory_growth"} {
		d, ok := manual.MetricsDetail[name]
		if !ok {
			t.Fatalf("missing manual metric %s", name)
		}
		if d.Status == "available" || d.Value != nil {
			t.Fatalf("manual unavailable metric %s must not be fabricated: %+v", name, d)
		}
		if d.Status != "unavailable" {
			t.Fatalf("manual missing metric %s should be explicitly unavailable: %+v", name, d)
		}
	}
	if manual.Available {
		t.Fatal("manual availability must be false when nothing provided")
	}

	base := time.Unix(1700000000, 0).UTC()
	derived2 := hostxray.DeriveResourceEvidence([]hostxray.Sample{
		{Timestamp: base, CPU: hostxray.CPUStats{UtilizationPct: 30, Available: true}, Mem: hostxray.MemoryStats{UsedPct: 40, Available: true}},
		{Timestamp: base.Add(5 * time.Second), CPU: hostxray.CPUStats{UtilizationPct: 50, Available: true}, Mem: hostxray.MemoryStats{UsedPct: 45, Available: true}},
	}, hostxray.Capabilities{ProcStat: true, ProcMemInfo: true, ProcNetDev: true})
	ra2 := resourceEvidenceToTwin(derived2, "hostxray-derived")
	if !ra2.Available {
		t.Fatalf("expected available derived metrics: %+v", ra2)
	}
	cpu := ra2.MetricsDetail["cpu_utilization_pct"]
	if cpu.Status != string(hostxray.ResourceStatusAvailable) || cpu.Value == nil || math.Abs(*cpu.Value-40) > 1e-9 {
		t.Fatalf("cpu metric mismatch: %+v", cpu)
	}
	if ra2.MetricsDetail["active_connections"].Status == string(hostxray.ResourceStatusAvailable) {
		t.Fatal("active connections must remain unavailable")
	}
}
