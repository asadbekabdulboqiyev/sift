//go:build integration

package evidence

import (
	"context"
	"github.com/asadbekabdulboqiyev/sift/internal/attest"
	"github.com/asadbekabdulboqiyev/sift/internal/config"
	"github.com/asadbekabdulboqiyev/sift/internal/engine"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"
)

// A live run must hand the collector exactly the requests the run reports, and
// every collected record must be a valid, canonical, uniquely numbered record.
func TestCollectorRecordsEveryRequestFromLiveRun(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sc := &config.Scenario{
		Name: "evidence",
		Profile: config.Profile{
			Type:     config.ProfileSteady,
			Users:    4,
			Duration: 1,
			Timeout:  2,
		},
		Steps: []config.Step{{Name: "health", Method: "GET", URL: srv.URL}},
	}
	eng, err := engine.New(sc)
	if err != nil {
		t.Fatal(err)
	}

	collector, err := NewCollector("test-worker-1")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tel, err := eng.Run(ctx, engine.RunOptions{Quiet: true, Samples: collector})
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	if err := collector.Err(); err != nil {
		t.Fatalf("collector reported unrepresentable samples: %v", err)
	}
	if got, want := uint64(collector.Count()), tel.TotalRequests(); got != want {
		t.Fatalf("collected %d records, run reported %d requests — evidence must match the report", got, want)
	}

	recs := collector.Records()
	if len(recs) == 0 {
		t.Fatal("no records collected")
	}
	if !attest.RecordsInFileOrder(recs) {
		t.Error("records are not in canonical leaf order")
	}
	seenSeq := make(map[uint64]bool, len(recs))
	for i, rec := range recs {
		if err := rec.Validate(); err != nil {
			t.Fatalf("record %d invalid: %v", i, err)
		}
		if rec.Worker != "test-worker-1" {
			t.Errorf("record %d worker = %q, want test-worker-1", i, rec.Worker)
		}
		if rec.Seq == 0 {
			t.Errorf("record %d has zero seq — the wire format is 1-based", i)
		}
		if seenSeq[rec.Seq] {
			t.Errorf("record %d repeats seq %d", i, rec.Seq)
		}
		seenSeq[rec.Seq] = true
		if rec.Status != http.StatusOK {
			t.Errorf("record %d status = %d, want 200", i, rec.Status)
		}
		// See the same assertion in internal/engine/sink_test.go: on Windows
		// the Go runtime's monotonic clock is the system interrupt time
		// (~15.6 ms tick), so a fast loopback request can legitimately measure
		// 0 ns. Negative is never valid; 0 is only acceptable on Windows.
		if rec.LatencyNS < 0 || (rec.LatencyNS == 0 && runtime.GOOS != "windows") {
			t.Errorf("record %d latency = %d, want > 0 (0 is only valid on Windows, where the clock cannot resolve it)", i, rec.LatencyNS)
		}
	}
	// The 1-based shift must be dense: 1..n.
	for i := uint64(1); i <= uint64(len(recs)); i++ {
		if !seenSeq[i] {
			t.Errorf("seq %d missing from the collected set", i)
		}
	}

	// The leaves must reproduce a root: the evidence is attestable.
	leaves, err := collector.Leaves()
	if err != nil {
		t.Fatalf("Leaves: %v", err)
	}
	if len(leaves) != len(recs) {
		t.Fatalf("Leaves = %d entries, records = %d", len(leaves), len(recs))
	}
	root := attest.MerkleRootHex(leaves)
	if root == "" || root == attest.EmptyRootHex {
		t.Fatalf("merkle root %q is empty for a non-empty run", root)
	}
	// A proof for the first leaf must verify against that root.
	proof, err := attest.MerkleProof(leaves, 0)
	if err != nil {
		t.Fatalf("MerkleProof: %v", err)
	}
	// VerifyProof takes the raw leaf value and applies the domain-separated,
	// index-bound leaf hash itself.
	if !attest.VerifyProof(attest.MerkleRoot(leaves), leaves[0], 0, proof) {
		t.Fatal("inclusion proof for leaf 0 does not verify")
	}
}
