//go:build integration

package coordinator

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func newCountingHTTPServer(t *testing.T) *httptest.Server {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func waitForWorkerProgress(t *testing.T, master *Master, minRequests int64) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		agg := master.Aggregator().Snapshot()
		if agg.TotalRequests >= minRequests && agg.Elapsed > 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for worker progress (got %+v)", master.Aggregator().Snapshot())
}

func connectMasterWithRetry(t *testing.T, cfg MasterConfig) *Master {
	t.Helper()
	ctx := context.Background()
	var err error
	var master *Master
	var healthy []string
	for attempt := 0; attempt < 5; attempt++ {
		if master != nil {
			master.Close()
		}
		master = NewMaster(cfg)
		healthy, err = master.Connect(ctx, cfg.Workers)
		if err == nil && len(healthy) == len(cfg.Workers) {
			return master
		}
		if err == nil {
			err = fmt.Errorf("connected %d/%d workers", len(healthy), len(cfg.Workers))
		}
		if attempt < 4 {
			time.Sleep(150 * time.Millisecond)
		}
	}
	if master != nil {
		master.Close()
	}
	t.Fatalf("connect: %v", err)
	return nil
}

func TestDistributedRunPartialTimingOnWorkerDisconnect(t *testing.T) {
	target := newCountingHTTPServer(t)
	addr, srv := startWorker(t, WorkerConfig{ID: "w1", MaxUsers: 1000})
	addr2, _ := startWorker(t, WorkerConfig{ID: "w2", MaxUsers: 1000})

	master := connectMasterWithRetry(t, MasterConfig{
		Scenario:   tinyScenario(t, target.URL, 8, 10),
		Workers:    []string{addr, addr2},
		ListenAddr: "127.0.0.1:0",
		RunTimeout: 20 * time.Second,
	})
	defer master.Close()

	ctx := context.Background()
	if err := master.StartRun(ctx, "run-partial-disconnect"); err != nil {
		t.Fatalf("start run: %v", err)
	}

	waitForWorkerProgress(t, master, 1)
	srv.Stop() // disconnect/fail worker mid-run

	select {
	case <-master.Done():
	case <-time.After(25 * time.Second):
		t.Fatal("timed out waiting for completion after worker disconnect")
	}

	if len(master.FailedWorkers()) == 0 {
		t.Fatal("expected at least one failed/disconnected worker")
	}
	// The disconnected worker must leave a preserved partial report behind. A
	// missing entry would mean its measured evidence was silently dropped when
	// the stream closed, which is exactly what this test guards against.
	master.mu.Lock()
	partial, ok := master.reports[addr]
	master.mu.Unlock()
	if !ok || partial == nil {
		t.Fatalf("partial report for disconnected worker %s was not preserved", addr)
	}
	rep := master.FinalReport()
	if rep == nil || rep.TotalRequests == 0 {
		t.Fatalf("expected partial final report with timing, got %+v", rep)
	}
	if rep.Duration <= 0 {
		t.Fatalf("expected actual partial duration > 0, got %s", rep.Duration)
	}
	if rep.StartedAt.IsZero() || rep.EndedAt.IsZero() {
		t.Fatalf("expected valid partial timestamps, got %s..%s", rep.StartedAt, rep.EndedAt)
	}
	if err := rep.ValidateTimestamps(); err != nil {
		t.Fatalf("ValidateTimestamps: %v", err)
	}
}

func TestDistributedRunPartialTimingOnLivenessKill(t *testing.T) {
	target := newCountingHTTPServer(t)
	addr, _ := startWorker(t, WorkerConfig{ID: "w1", MaxUsers: 1000})
	addr2, _ := startWorker(t, WorkerConfig{ID: "w2", MaxUsers: 1000})

	master := connectMasterWithRetry(t, MasterConfig{
		Scenario:   tinyScenario(t, target.URL, 8, 10),
		Workers:    []string{addr, addr2},
		ListenAddr: "127.0.0.1:0",
		RunTimeout: 30 * time.Second,
	})
	defer master.Close()

	ctx := context.Background()
	if err := master.StartRun(ctx, "run-partial-liveness"); err != nil {
		t.Fatalf("start run: %v", err)
	}

	waitForWorkerProgress(t, master, 1)

	// Force liveness timeout for one worker without waiting the real deadline.
	master.mu.Lock()
	master.lastSeen[addr] = time.Now().Add(-livenessDeadline - time.Second)
	// Ensure Ping probe fails so the worker is treated as dead/unreachable.
	master.clients[addr] = nil
	addrs := []string{addr, addr2}
	master.mu.Unlock()
	master.checkLiveness(addrs)

	select {
	case <-master.Done():
	case <-time.After(25 * time.Second):
		t.Fatal("timed out waiting for completion after liveness kill")
	}

	rep := master.FinalReport()
	if rep == nil || rep.TotalRequests == 0 {
		t.Fatalf("expected partial report preserving timing, got %+v", rep)
	}
	if rep.Duration <= 0 || rep.StartedAt.IsZero() || rep.EndedAt.IsZero() {
		t.Fatalf("expected valid partial timing, got dur=%s %s..%s", rep.Duration, rep.StartedAt, rep.EndedAt)
	}
	if err := rep.ValidateTimestamps(); err != nil {
		t.Fatalf("ValidateTimestamps: %v", err)
	}
}

func TestDistributedRunPartialTimingOnTimeoutGrace(t *testing.T) {
	target := newCountingHTTPServer(t)
	addr, _ := startWorker(t, WorkerConfig{ID: "w1", MaxUsers: 1000})
	addr2, _ := startWorker(t, WorkerConfig{ID: "w2", MaxUsers: 1000})

	master := connectMasterWithRetry(t, MasterConfig{
		Scenario:   tinyScenario(t, target.URL, 6, 10),
		Workers:    []string{addr, addr2},
		ListenAddr: "127.0.0.1:0",
		RunTimeout: 2 * time.Second,
	})
	defer master.Close()

	ctx := context.Background()
	if err := master.StartRun(ctx, "run-partial-timeout"); err != nil {
		t.Fatalf("start run: %v", err)
	}

	select {
	case <-master.Done():
	case <-time.After(20 * time.Second):
		t.Fatal("timed out waiting for timeout/grace completion")
	}

	rep := master.FinalReport()
	if rep == nil {
		t.Fatal("expected final report after timeout/grace")
	}
	if rep.TotalRequests == 0 {
		t.Fatalf("expected partial requests/timing after timeout/grace, got %+v", rep)
	}
	if rep.Duration <= 0 || rep.StartedAt.IsZero() || rep.EndedAt.IsZero() {
		t.Fatalf("expected timing-consistent partial results, got dur=%s %s..%s", rep.Duration, rep.StartedAt, rep.EndedAt)
	}
	if err := rep.ValidateTimestamps(); err != nil {
		t.Fatalf("ValidateTimestamps: %v", err)
	}
}
