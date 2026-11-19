//go:build integration

package coordinator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestDistributedRunAggregatesAcrossWorkers(t *testing.T) {
	var hits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()

	addr1, _ := startWorker(t, WorkerConfig{ID: "w1", MaxUsers: 1000})
	addr2, _ := startWorker(t, WorkerConfig{ID: "w2", MaxUsers: 1000})

	master := NewMaster(MasterConfig{
		Scenario:   tinyScenario(t, target.URL, 6, 1),
		Workers:    []string{addr1, addr2},
		ListenAddr: "127.0.0.1:0",
		RunTimeout: 20 * time.Second,
	})
	defer master.Close()

	ctx := context.Background()
	workers, err := master.Connect(ctx, master.cfg.Workers)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if len(workers) != 2 {
		t.Fatalf("expected 2 workers, got %d", len(workers))
	}

	if err := master.StartRun(ctx, "run-it"); err != nil {
		t.Fatalf("start run: %v", err)
	}

	select {
	case <-master.Done():
	case <-time.After(25 * time.Second):
		t.Fatal("timed out waiting for run completion")
	}

	if got := len(master.FailedWorkers()); got != 0 {
		t.Fatalf("unexpected failed workers: %v", master.FailedWorkers())
	}

	rep := master.FinalReport()
	if rep == nil {
		t.Fatal("nil final report")
	}
	if rep.TotalRequests == 0 {
		t.Fatal("no requests recorded")
	}
	if rep.RPS <= 0 {
		t.Fatalf("expected positive RPS, got %f", rep.RPS)
	}
	if rep.Status[200] == 0 {
		t.Fatalf("expected 200 responses, got status map %v", rep.Status)
	}
	if len(rep.Steps) != 1 || rep.Steps[0].Requests == 0 {
		t.Fatalf("expected one populated step, got %+v", rep.Steps)
	}
	if rep.Duration <= 0 {
		t.Fatalf("expected positive duration, got %s", rep.Duration)
	}
	if hits.Load() == 0 {
		t.Fatal("target server was never hit")
	}

	agg := master.Aggregator().Snapshot()
	if agg.Workers != 2 {
		t.Fatalf("expected 2 live workers in aggregate, got %d", agg.Workers)
	}
}

func TestMasterToleratesDeadWorker(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer target.Close()

	addr1, _ := startWorker(t, WorkerConfig{ID: "live", MaxUsers: 1000})

	master := NewMaster(MasterConfig{
		Scenario:   tinyScenario(t, target.URL, 4, 1),
		Workers:    []string{addr1, "127.0.0.1:1"},
		RunTimeout: 20 * time.Second,
	})
	defer master.Close()

	ctx := context.Background()
	workers, err := master.Connect(ctx, master.cfg.Workers)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if len(workers) != 1 {
		t.Fatalf("expected 1 reachable worker, got %d", len(workers))
	}

	if err := master.StartRun(ctx, "run-dead"); err != nil {
		t.Fatalf("start: %v", err)
	}
	select {
	case <-master.Done():
	case <-time.After(25 * time.Second):
		t.Fatal("run never completed despite one live worker")
	}
	if master.FinalReport().TotalRequests == 0 {
		t.Fatal("expected partial report from live worker")
	}
}
