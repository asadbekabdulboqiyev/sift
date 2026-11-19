package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/config"
)

// TestEngineReuseWithGate runs the same Engine twice with Profile.Gate on.
// Run used to close the single startGate created by New(), so the second run
// closed an already-closed channel and panicked from a goroutine, taking the
// process down. The gate is now recreated per run.
func TestEngineReuseWithGate(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	sc := &config.Scenario{
		Name: "gate-reuse",
		Profile: config.Profile{
			Type:     config.ProfileSteady,
			Users:    2,
			Duration: 10,
			Timeout:  3,
			Gate:     true,
		},
		Steps: []config.Step{{Name: "strike", Method: "GET", URL: srv.URL}},
	}
	eng, err := New(sc)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for run := 1; run <= 2; run++ {
		before := hits.Load()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		_, runErr := eng.Run(ctx, RunOptions{Quiet: true})
		cancel()
		if runErr != nil {
			t.Fatalf("run %d: %v", run, runErr)
		}
		if got := hits.Load() - before; got != 2 {
			t.Fatalf("run %d hits = %d, want 2 (one strike per user)", run, got)
		}
	}

	// The close(startGate) goroutine sleeps before firing; give it time so a
	// double close would panic here rather than after the test binary exits.
	time.Sleep(400 * time.Millisecond)
}
