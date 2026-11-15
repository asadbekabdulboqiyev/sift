package dashboard

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/hostxray"
)

func TestHandleInsightsResourceAssessment_ManualStandardized(t *testing.T) {
	s := NewServer()
	body := []byte(`{"cpu":72.5,"network":null,"connections":1200}`)
	req := httptest.NewRequest(http.MethodPost, "/api/insights/resources/assess", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Host = "127.0.0.1:8888"
	rr := httptest.NewRecorder()
	s.handleInsightsResourceAssessment(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		OK                 bool `json:"ok"`
		DerivedFromSamples bool `json:"derived_from_samples"`
		ResourceMonitoring struct {
			SchemaVersion string `json:"schema_version"`
			Source        string `json:"source"`
			MetricsDetail map[string]struct {
				Name   string   `json:"name"`
				Status string   `json:"status"`
				Unit   string   `json:"unit"`
				Source string   `json:"source"`
				Reason string   `json:"reason"`
				Value  *float64 `json:"value"`
			} `json:"metrics_detail"`
		} `json:"resource_monitoring"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v body=%s", err, rr.Body.String())
	}
	if !resp.OK || resp.DerivedFromSamples {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if resp.ResourceMonitoring.SchemaVersion == "" || resp.ResourceMonitoring.Source == "" {
		t.Fatalf("missing container metadata: %+v", resp.ResourceMonitoring)
	}
	cpu := resp.ResourceMonitoring.MetricsDetail["cpu"]
	if cpu.Status != "available" || cpu.Value == nil || cpu.Unit == "" || cpu.Source == "" {
		t.Fatalf("cpu not standardized: %+v", cpu)
	}
	net := resp.ResourceMonitoring.MetricsDetail["network"]
	if net.Status != "unavailable" || net.Reason == "" || net.Unit == "" || net.Source == "" {
		t.Fatalf("network unavailable must be explicit: %+v", net)
	}
}

func TestHandleInsightsResourceAssessment_SampleDerivedStandardized(t *testing.T) {
	s := NewServer()
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	payload := map[string]any{
		"samples": []hostxray.Sample{
			{Timestamp: base, CPU: hostxray.CPUStats{UtilizationPct: 40, Available: true}, Mem: hostxray.MemoryStats{UsedPct: 50, Available: true}},
			{Timestamp: base.Add(2 * time.Second), CPU: hostxray.CPUStats{UtilizationPct: 60, Available: true}, Mem: hostxray.MemoryStats{UsedPct: 54, Available: true}},
		},
		"capabilities": hostxray.Capabilities{ProcStat: true, ProcMemInfo: true, ProcNetDev: true},
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/insights/resources/assess", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Host = "127.0.0.1:8888"
	rr := httptest.NewRecorder()
	s.handleInsightsResourceAssessment(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		OK                 bool `json:"ok"`
		DerivedFromSamples bool `json:"derived_from_samples"`
		SampleCount        int  `json:"sample_count"`
		ResourceMonitoring struct {
			SchemaVersion       string `json:"schema_version"`
			Source              string `json:"source"`
			ObservedWindowStart string `json:"observed_window_start"`
			ObservedWindowEnd   string `json:"observed_window_end"`
			MetricsDetail       map[string]struct {
				Name                string   `json:"name"`
				Status              string   `json:"status"`
				Unit                string   `json:"unit"`
				Source              string   `json:"source"`
				Reason              string   `json:"reason"`
				ObservedWindowStart string   `json:"observed_window_start"`
				Value               *float64 `json:"value"`
			} `json:"metrics_detail"`
		} `json:"resource_monitoring"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v body=%s", err, rr.Body.String())
	}
	if !resp.OK || !resp.DerivedFromSamples || resp.SampleCount != 2 {
		t.Fatalf("unexpected response flags/count: %+v", resp)
	}
	rm := resp.ResourceMonitoring
	if rm.SchemaVersion == "" || rm.Source == "" || rm.ObservedWindowStart == "" || rm.ObservedWindowEnd == "" {
		t.Fatalf("missing derived container metadata: %+v", rm)
	}
	mg := rm.MetricsDetail["memory_growth_pct"]
	if mg.Status != "available" || mg.Value == nil || mg.Source == "" || mg.Unit == "" || mg.ObservedWindowStart == "" {
		t.Fatalf("memory growth not standardized: %+v", mg)
	}
	if *mg.Value != 4 {
		t.Fatalf("memory growth value=%v want 4", *mg.Value)
	}
	net := rm.MetricsDetail["network_utilization"]
	if net.Status != "unavailable" || net.Reason == "" || net.Unit == "" || net.Source == "" {
		t.Fatalf("network unavailable must be explicit: %+v", net)
	}
	srt := rm.MetricsDetail["server_response_time_ms"]
	if srt.Status != "unavailable" || srt.Reason == "" {
		t.Fatalf("server response time must be unavailable with reason: %+v", srt)
	}
}
