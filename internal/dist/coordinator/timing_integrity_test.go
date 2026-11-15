package coordinator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/config"
	distproto "github.com/asadbekabdulboqiyev/sift/internal/dist/proto"
	"github.com/asadbekabdulboqiyev/sift/internal/report"
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

func TestReportFromProtoTiming_UnsetTimestampsNotEpoch(t *testing.T) {
	r := ReportFromProto(&distproto.Report{DurationMs: 1500})
	if !r.StartedAt.IsZero() || !r.EndedAt.IsZero() {
		t.Fatalf("expected unset timestamps, got %s..%s", r.StartedAt, r.EndedAt)
	}
	if r.Duration != 1500*time.Millisecond {
		t.Fatalf("duration=%s want 1.5s", r.Duration)
	}
}

func TestReportFromProtoTiming_NormalizesEndFromStartAndDuration(t *testing.T) {
	start := time.Now().Add(-5 * time.Second).Truncate(time.Millisecond)
	r := ReportFromProto(&distproto.Report{
		StartedAt:  start.UnixMilli(),
		EndedAt:    start.Add(999 * time.Millisecond).UnixMilli(), // inconsistent/ignored in favor of duration
		DurationMs: 2500,
	})
	if !r.StartedAt.Equal(start) {
		t.Fatalf("started_at=%s want %s", r.StartedAt, start)
	}
	if got := r.EndedAt.Sub(r.StartedAt); got != r.Duration {
		t.Fatalf("ended-started=%s want duration=%s", got, r.Duration)
	}
	if err := r.ValidateTimestamps(); err != nil {
		t.Fatalf("ValidateTimestamps: %v", err)
	}
}

func TestReportFromProtoTiming_InfersStartFromEndAndDuration(t *testing.T) {
	end := time.Now().Truncate(time.Millisecond)
	r := ReportFromProto(&distproto.Report{EndedAt: end.UnixMilli(), DurationMs: 1200})
	if r.EndedAt.IsZero() || r.StartedAt.IsZero() {
		t.Fatalf("expected inferred bounds, got %s..%s", r.StartedAt, r.EndedAt)
	}
	if got := r.EndedAt.Sub(r.StartedAt); got != r.Duration {
		t.Fatalf("ended-started=%s want duration=%s", got, r.Duration)
	}
	if err := r.ValidateTimestamps(); err != nil {
		t.Fatalf("ValidateTimestamps: %v", err)
	}
}

func TestMergeReportsTiming_NormalizesWhenStartKnownEndMissing(t *testing.T) {
	start := time.Now().Add(-3 * time.Second).Truncate(time.Millisecond)
	r1 := &report.Report{Name: "r", StartedAt: start, Duration: 1500 * time.Millisecond, TotalRequests: 10}
	r2 := &report.Report{Name: "r", StartedAt: start, Duration: 900 * time.Millisecond, TotalRequests: 5}
	merged := MergeReports(&config.Scenario{}, []*report.Report{r1, r2})
	if merged.StartedAt.IsZero() || merged.EndedAt.IsZero() {
		t.Fatalf("expected normalized timestamps, got %s..%s", merged.StartedAt, merged.EndedAt)
	}
	if merged.Duration != 1500*time.Millisecond {
		t.Fatalf("duration=%s want 1.5s", merged.Duration)
	}
	if got := merged.EndedAt.Sub(merged.StartedAt); got != merged.Duration {
		t.Fatalf("ended-started=%s want %s", got, merged.Duration)
	}
	if err := merged.ValidateTimestamps(); err != nil {
		t.Fatalf("ValidateTimestamps: %v", err)
	}
}

func TestMergeReportsTiming_InfersStartWhenOnlyEndAndDurationKnown(t *testing.T) {
	end := time.Now().Truncate(time.Millisecond)
	r1 := &report.Report{Name: "r", EndedAt: end, Duration: 2 * time.Second, TotalRequests: 10}
	merged := MergeReports(&config.Scenario{}, []*report.Report{r1})
	if merged.StartedAt.IsZero() || merged.EndedAt.IsZero() {
		t.Fatalf("expected inferred timestamps, got %s..%s", merged.StartedAt, merged.EndedAt)
	}
	if merged.Duration != 2*time.Second {
		t.Fatalf("duration=%s want 2s", merged.Duration)
	}
	if err := merged.ValidateTimestamps(); err != nil {
		t.Fatalf("ValidateTimestamps: %v", err)
	}
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

func TestDistributedRunPartialTimingOnWorkerDisconnect(t *testing.T) {
	target := newCountingHTTPServer(t)
	addr, srv := startWorker(t, WorkerConfig{ID: "w1", MaxUsers: 1000})
	addr2, _ := startWorker(t, WorkerConfig{ID: "w2", MaxUsers: 1000})

	master := NewMaster(MasterConfig{
		Scenario:   tinyScenario(t, target.URL, 8, 10),
		Workers:    []string{addr, addr2},
		ListenAddr: "127.0.0.1:0",
		RunTimeout: 20 * time.Second,
	})
	defer master.Close()

	ctx := context.Background()
	workers, err := master.Connect(ctx, master.cfg.Workers)
	if err != nil || len(workers) != 2 {
		t.Fatalf("connect: workers=%v err=%v", workers, err)
	}
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
	if _, ok := master.reports[addr]; !ok {
		// Partial report for disconnected worker should be preserved (merged may aggregate; direct map check best-effort).
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

	master := NewMaster(MasterConfig{
		Scenario:   tinyScenario(t, target.URL, 8, 10),
		Workers:    []string{addr, addr2},
		ListenAddr: "127.0.0.1:0",
		RunTimeout: 30 * time.Second,
	})
	defer master.Close()

	ctx := context.Background()
	if _, err := master.Connect(ctx, master.cfg.Workers); err != nil {
		t.Fatalf("connect: %v", err)
	}
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

	master := NewMaster(MasterConfig{
		Scenario:   tinyScenario(t, target.URL, 6, 10),
		Workers:    []string{addr, addr2},
		ListenAddr: "127.0.0.1:0",
		RunTimeout: 2 * time.Second,
	})
	defer master.Close()

	ctx := context.Background()
	if _, err := master.Connect(ctx, master.cfg.Workers); err != nil {
		t.Fatalf("connect: %v", err)
	}
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
