package engine

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/config"
	"github.com/asadbekabdulboqiyev/sift/internal/metrics"
)

// runFlowScenario runs a scenario to completion and returns the telemetry.
func runFlowScenario(t *testing.T, sc *config.Scenario) *metrics.Telemetry {
	t.Helper()
	if err := sc.Normalize(); err != nil {
		t.Fatal(err)
	}
	eng, err := New(sc)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tel, err := eng.Run(ctx, RunOptions{Out: io.Discard, Quiet: true})
	if err != nil {
		t.Fatal(err)
	}
	return tel
}

func flowScenario(steps []config.Step, profile config.Profile) *config.Scenario {
	if profile.Users == 0 {
		profile.Users = 1
	}
	if profile.Duration == 0 {
		profile.Duration = 2
	}
	if profile.Timeout == 0 {
		profile.Timeout = 5
	}
	return &config.Scenario{
		Name:    "flow-test",
		Profile: profile,
		Steps:   steps,
	}
}

// ---- on_error: continue vs stop ----

// ---- retries ----

// ---- conditional branching ----

// ---- skip_on_error ----

// ---- think_time ----

// ---- stop_on_status ----

func TestStopOnStatusExactHaltRun(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(429)
	}))
	defer srv.Close()

	sc := flowScenario([]config.Step{{
		Name: "rl", Method: "GET", URL: srv.URL + "/rl",
		StopOnStatus: "429",
	}}, config.Profile{Users: 1, Duration: 2, Timeout: 5})

	tel := runFlowScenario(t, sc)

	// A single user: iteration 1 hits 429 → the whole run halts → no more
	// hits for the remaining ~2s window.
	if hits.Load() != 1 {
		t.Errorf("hits = %d, want exactly 1 (run must halt after 429)", hits.Load())
	}
	if tel.Steps[0].StatusCodes()[429] != 1 {
		t.Error("expected one 429 recorded")
	}
}

func TestStopOnStatusClassHaltRun(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(503)
	}))
	defer srv.Close()

	sc := flowScenario([]config.Step{{
		Name: "boom", Method: "GET", URL: srv.URL + "/boom",
		StopOnStatus: "5xx",
	}}, config.Profile{Users: 1, Duration: 2, Timeout: 5})

	runFlowScenario(t, sc)

	if hits.Load() != 1 {
		t.Errorf("hits = %d, want exactly 1 (run must halt after a 5xx)", hits.Load())
	}
}
