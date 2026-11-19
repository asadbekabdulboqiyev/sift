//go:build integration

package coordinator

import (
	"context"
	"github.com/asadbekabdulboqiyev/sift/internal/attest"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestDistributedRunAttestedE2E runs the full path over real gRPC: a worker
// holding an Ed25519 keypair streams signed progress and a signed final report,
// and a master that pins that key and requires attestation completes the run
// with the telemetry counted.
func TestDistributedRunAttestedE2E(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()

	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	addr, _ := startWorker(t, WorkerConfig{ID: "w1", MaxUsers: 100, Keypair: kp})

	master := NewMaster(MasterConfig{
		Scenario:                 tinyScenario(t, target.URL, 4, 2),
		Workers:                  []string{addr},
		ListenAddr:               "127.0.0.1:0",
		RunTimeout:               20 * time.Second,
		RequireWorkerAttestation: true,
		AuthorizedWorkers:        map[string]string{"w1": attest.PublicKeyHex(kp.Public)},
		Logf:                     func(string, ...any) {},
	})
	defer master.Close()

	ctx := context.Background()
	if _, err := master.Connect(ctx, []string{addr}); err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := master.StartRun(ctx, "run-attested"); err != nil {
		t.Fatalf("start run: %v", err)
	}
	select {
	case <-master.Done():
	case <-time.After(25 * time.Second):
		t.Fatal("timed out waiting for the attested run")
	}

	if got := master.FailedWorkers(); len(got) != 0 {
		t.Fatalf("attested worker must not fail, got %v (rejections: %v)", got, master.RejectedWorkers())
	}
	rep := master.FinalReport()
	if rep == nil || rep.TotalRequests == 0 {
		t.Fatalf("expected a non-empty merged report, got %+v", rep)
	}
	if agg := master.Aggregator().Snapshot(); agg.Workers == 0 || agg.TotalRequests == 0 {
		t.Fatalf("signed progress never reached the aggregator: %+v", agg)
	}
}

// TestDistributedRunRejectsUnsignedWorkerE2E proves the fail-closed path end to
// end: a worker with no keypair cannot get telemetry into an attested master,
// and it is reported as failed instead of contributing numbers.
func TestDistributedRunRejectsUnsignedWorkerE2E(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	// Worker has no Keypair: it streams unsigned telemetry.
	addr, _ := startWorker(t, WorkerConfig{ID: "w1", MaxUsers: 100})

	master := NewMaster(MasterConfig{
		Scenario:                 tinyScenario(t, target.URL, 4, 2),
		Workers:                  []string{addr},
		ListenAddr:               "127.0.0.1:0",
		RunTimeout:               20 * time.Second,
		RequireWorkerAttestation: true,
		AuthorizedWorkers:        map[string]string{"w1": attest.PublicKeyHex(kp.Public)},
		Logf:                     func(string, ...any) {},
	})
	defer master.Close()

	ctx := context.Background()
	if _, err := master.Connect(ctx, []string{addr}); err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := master.StartRun(ctx, "run-unsigned"); err != nil {
		t.Fatalf("start run: %v", err)
	}
	select {
	case <-master.Done():
	case <-time.After(25 * time.Second):
		t.Fatal("timed out waiting for the unsigned worker to be dropped")
	}

	if got := master.FailedWorkers(); len(got) != 1 || got[0] != addr {
		t.Fatalf("unsigned worker must be marked failed, got %v", got)
	}
	if got := master.RejectedWorkers(); len(got) != 1 {
		t.Fatalf("rejection reason must be recorded, got %v", got)
	}
	if agg := master.Aggregator().Snapshot(); agg.Workers != 0 || agg.TotalRequests != 0 {
		t.Fatalf("unsigned telemetry must not be aggregated: %+v", agg)
	}
	if rep := master.FinalReport(); rep != nil && rep.TotalRequests > 0 {
		t.Fatalf("unsigned worker report must not be merged, got %d requests", rep.TotalRequests)
	}
}
