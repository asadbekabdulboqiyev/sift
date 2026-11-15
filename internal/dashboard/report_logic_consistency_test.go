package dashboard

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/report"
)

func TestHandleInsightsTwinFitRejectsZeroRequests(t *testing.T) {
	s := &Server{}
	body := map[string]any{
		"report": report.Report{
			Duration:      10 * time.Second,
			TotalRequests: 0,
			StartedAt:     time.Unix(100, 0).UTC(),
			EndedAt:       time.Unix(110, 0).UTC(),
		},
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/insights/twin/fit", bytes.NewReader(b))
	req.Host = "localhost"
	w := httptest.NewRecorder()
	s.handleInsightsTwinFit(w, req)
	if w.Code != 400 {
		t.Fatalf("status=%d body=%s, want 400", w.Code, w.Body.String())
	}
}

func TestHandleInsightsTwinFitRejectsZeroDuration(t *testing.T) {
	s := &Server{}
	body := map[string]any{
		"report": report.Report{
			Duration:      0,
			TotalRequests: 10,
			StartedAt:     time.Unix(100, 0).UTC(),
			EndedAt:       time.Unix(100, 0).UTC(),
		},
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/insights/twin/fit", bytes.NewReader(b))
	req.Host = "localhost"
	w := httptest.NewRecorder()
	s.handleInsightsTwinFit(w, req)
	if w.Code != 400 {
		t.Fatalf("status=%d body=%s, want 400", w.Code, w.Body.String())
	}
}

func TestHandleInsightsTwinFitRejectsInconsistentTiming(t *testing.T) {
	s := &Server{}
	body := map[string]any{
		"report": report.Report{
			Duration:      10 * time.Second,
			TotalRequests: 10,
			StartedAt:     time.Unix(110, 0).UTC(),
			EndedAt:       time.Unix(100, 0).UTC(), // before start
		},
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/insights/twin/fit", bytes.NewReader(b))
	req.Host = "localhost"
	w := httptest.NewRecorder()
	s.handleInsightsTwinFit(w, req)
	if w.Code != 400 {
		t.Fatalf("status=%d body=%s, want 400", w.Code, w.Body.String())
	}
}

func TestHandleInsightsTwinSimulateRejectsInvalidBreachProb(t *testing.T) {
	s := &Server{}
	body := map[string]any{
		"model":               map[string]any{"schema_version": "x", "curve": map[string]any{"capacity_rps": 10}},
		"scenario":            "likely",
		"fail_on_breach_prob": 1.5,
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/insights/twin/simulate", bytes.NewReader(b))
	req.Host = "localhost"
	w := httptest.NewRecorder()
	s.handleInsightsTwinSimulate(w, req)
	if w.Code != 400 {
		t.Fatalf("status=%d body=%s, want 400", w.Code, w.Body.String())
	}
}

func TestPentestCertifiableReportZeroTestedNotContradictory(t *testing.T) {
	res := PentestScanResult{
		Target: "https://example.com",
		Tested: 0,
		Total:  10,
		Score:  0,
		Grade:  "",
	}
	r := pentestCertifiableReport(res, time.Now().UTC(), 0)
	if r.Verdict != "NOT ASSESSED -- No categories tested" {
		t.Fatalf("verdict=%q", r.Verdict)
	}
	if r.Grade != "" || r.RiskScore != 0 {
		t.Fatalf("grade=%q score=%d, want empty/0", r.Grade, r.RiskScore)
	}
	if r.Critical != 0 || r.High != 0 || r.Medium != 0 || r.Low != 0 || r.InfoCount != 0 {
		t.Fatalf("counts not zero: %+v", r)
	}
}
