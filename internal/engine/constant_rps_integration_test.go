//go:build integration

package engine

import (
	"context"
	"fmt"
	"github.com/asadbekabdulboqiyev/sift/internal/config"
	"github.com/asadbekabdulboqiyev/sift/internal/report"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestConstantRPSEndToEnd(t *testing.T) {
	var reqCount atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCount.Add(1)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "ok")
	}))
	defer srv.Close()

	sc := &config.Scenario{
		Name: "rps-test",
		Profile: config.Profile{
			Type:      config.ProfileConstantRPS,
			TargetRPS: 200,
			Duration:  3,
			RampUp:    1,
			Timeout:   5,
		},
		Steps: []config.Step{
			{Name: "hit", Method: "GET", URL: srv.URL + "/"},
		},
	}
	if err := sc.Normalize(); err != nil {
		t.Fatal(err)
	}

	eng, err := New(sc)
	if err != nil {
		t.Fatal(err)
	}

	telemetry, err := eng.Run(context.Background(), RunOptions{Quiet: true})
	if err != nil {
		t.Fatal(err)
	}

	actual := telemetry.RPS()
	if actual < 50 {
		t.Errorf("actual RPS = %.1f, want >= 50", actual)
	}
	if actual > 400 {
		t.Errorf("actual RPS = %.1f, want <= 400 (cap ~200 rps + ramp overhead)", actual)
	}
	t.Logf("target=200 rps, actual=%.1f rps, total_requests=%d", actual, telemetry.TotalRequests())
}

func TestConstantRPSCapEnforcement(t *testing.T) {
	var reqCount atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sc := &config.Scenario{
		Name: "cap-test",
		Profile: config.Profile{
			Type:      config.ProfileConstantRPS,
			TargetRPS: 50,
			Duration:  3,
			RampUp:    0,
			Timeout:   5,
		},
		Steps: []config.Step{
			{Name: "hit", Method: "GET", URL: srv.URL + "/"},
		},
	}
	if err := sc.Normalize(); err != nil {
		t.Fatal(err)
	}

	eng, err := New(sc)
	if err != nil {
		t.Fatal(err)
	}

	telemetry, err := eng.Run(context.Background(), RunOptions{Quiet: true})
	if err != nil {
		t.Fatal(err)
	}

	actual := telemetry.RPS()
	// With 50 rps target and 3s duration, expect 120-200 total (accounting for
	// burst at start and ramp-up overhead).
	if actual < 30 {
		t.Errorf("actual RPS = %.1f, want >= 30 (ramp-up consumed some time)", actual)
	}
	if actual > 100 {
		t.Errorf("actual RPS = %.1f, want <= 100 (cap should hold at 50)", actual)
	}
	t.Logf("target=50 rps, actual=%.1f rps, total_requests=%d", actual, telemetry.TotalRequests())
}

func TestConstantRPSReportShowsTargetRPS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sc := &config.Scenario{
		Name: "rps-report",
		Profile: config.Profile{
			Type:      config.ProfileConstantRPS,
			TargetRPS: 100,
			Duration:  2,
			RampUp:    1,
			Timeout:   5,
		},
		Steps: []config.Step{
			{Name: "hit", Method: "GET", URL: srv.URL + "/"},
		},
	}
	if err := sc.Normalize(); err != nil {
		t.Fatal(err)
	}

	eng, err := New(sc)
	if err != nil {
		t.Fatal(err)
	}

	telemetry, err := eng.Run(context.Background(), RunOptions{Quiet: true})
	if err != nil {
		t.Fatal(err)
	}

	r := report.Build(telemetry, sc)
	if r.TargetRPS != 100 {
		t.Errorf("report TargetRPS = %d, want 100", r.TargetRPS)
	}
	if r.LoadProfile != "constant-rps" {
		t.Errorf("report LoadProfile = %q, want constant-rps", r.LoadProfile)
	}
}
