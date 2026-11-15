package dashboard

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/metrics"
	"github.com/asadbekabdulboqiyev/sift/internal/report"
	"github.com/asadbekabdulboqiyev/sift/internal/twin"
)

func syntheticLeakageReport() report.Report {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return report.Report{
		Name:          "leakage-benchmark",
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
		Timeline: []metrics.TimelineSample{{Second: 1, Requests: 200}, {Second: 2, Requests: 400}},
	}
}

func TestInsightsTwinBacktest_RejectsMetadataOnlyVerifiedNoLeakage(t *testing.T) {
	s := &Server{}
	body, _ := json.Marshal(map[string]any{
		"predicted": []float64{100, 110},
		"actual":    []float64{100, 110},
		"leakage": map[string]any{
			"status":   "verified_no_leakage",
			"verified": true,
			"proven":   true,
			"enforced": true,
			"reason":   "caller metadata only",
		},
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
	leakage, _ := resp["leakage"].(map[string]any)
	if leakage == nil {
		t.Fatalf("missing leakage: %#v", resp)
	}
	if leakage["status"] != twin.LeakageStatusUnverified {
		t.Fatalf("metadata-only claim must be unverified, got %#v", leakage["status"])
	}
	if v, _ := leakage["verified"].(bool); v {
		t.Fatalf("verified must be false for metadata-only claim: %#v", leakage)
	}
	if v, _ := leakage["proven"].(bool); v {
		t.Fatalf("proven must be false for metadata-only claim: %#v", leakage)
	}
	if v, _ := leakage["enforced"].(bool); v {
		t.Fatalf("enforced must be false for metadata-only claim: %#v", leakage)
	}
}

func TestInsightsTwinCompare_RejectsMetadataOnlyVerifiedNoLeakage(t *testing.T) {
	s := &Server{}
	rep := syntheticLeakageReport()
	m, err := twin.Fit(rep, twin.FitOptions{Producer: "dashboard-test"})
	if err != nil {
		t.Fatalf("fit: %v", err)
	}
	sc, err := twin.Preset("normal", m)
	if err != nil {
		t.Fatalf("preset: %v", err)
	}
	sc.Iterations = 20
	res, err := twin.Simulate(m, sc, 7)
	if err != nil {
		t.Fatalf("simulate: %v", err)
	}
	body, _ := json.Marshal(map[string]any{
		"model":  m,
		"result": res,
		"actual": rep,
		"leakage": map[string]any{
			"status":   "verified_no_leakage",
			"verified": true,
			"proven":   true,
			"enforced": true,
		},
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
		t.Fatalf("unmarshal: %v body=%s", err, w.Body.String())
	}
	leakage, _ := resp["leakage"].(map[string]any)
	if leakage == nil {
		t.Fatalf("missing leakage: %#v", resp)
	}
	if leakage["status"] != twin.LeakageStatusUnverified {
		t.Fatalf("metadata-only claim must be unverified, got %#v", leakage["status"])
	}
	if v, _ := leakage["verified"].(bool); v {
		t.Fatalf("verified must be false for metadata-only claim: %#v", leakage)
	}
	vr, _ := resp["validation_record"].(map[string]any)
	if vr != nil {
		if lg, _ := vr["leakage"].(map[string]any); lg != nil {
			if lg["status"] == twin.LeakageStatusVerifiedNoLeakage {
				t.Fatalf("validation_record leakage must not be verified_no_leakage without manifest provenance: %#v", lg)
			}
		}
	}
}
