package evidence

import (
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/asadbekabdulboqiyev/sift/internal/attest"
	"github.com/asadbekabdulboqiyev/sift/internal/engine"
)

// The engine's "unknown bytes" marker must become the protocol's "not recorded"
// zero; nothing else about the record may change.
func TestCollectorNormalizesUnknownBytes(t *testing.T) {
	collector, err := NewCollector("normalize")
	if err != nil {
		t.Fatal(err)
	}
	collector.Emit(engine.Sample{
		Seq:       0,
		Step:      "health",
		StartNS:   1_700_000_000_000_000_000,
		LatencyNS: 1_500_000,
		Status:    http.StatusOK,
		Bytes:     -1,
	})

	if err := collector.Err(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	recs := collector.Records()
	if len(recs) != 1 {
		t.Fatalf("collected %d records, want 1", len(recs))
	}
	rec := recs[0]
	if rec.Bytes != 0 {
		t.Errorf("bytes = %d, want 0 (unknown normalizes to not-recorded)", rec.Bytes)
	}
	if rec.Seq != 1 {
		t.Errorf("seq = %d, want 1 (engine seq 0 becomes wire seq 1)", rec.Seq)
	}
	if rec.LatencyNS != 1_500_000 {
		t.Errorf("latency = %d, want 1500000 (unchanged)", rec.LatencyNS)
	}
	if rec.StartNS != 1_700_000_000_000_000_000 {
		t.Errorf("start_ns = %d, want unchanged", rec.StartNS)
	}
}

// A sample that cannot be represented must not be silently repaired or silently
// dropped: it is counted, reported, and left out, so the caller can refuse to
// emit an incomplete bundle.
func TestCollectorRefusesUnrepresentableSample(t *testing.T) {
	collector, err := NewCollector("broken")
	if err != nil {
		t.Fatal(err)
	}
	collector.Emit(engine.Sample{Seq: 0, StartNS: 1000, LatencyNS: -5, Status: 200})
	collector.Emit(engine.Sample{Seq: 1, StartNS: 2000, LatencyNS: 1000, Status: 200})

	if collector.Err() == nil {
		t.Fatal("negative latency was accepted — the evidence would be unusable")
	}
	if collector.Dropped() != 1 {
		t.Errorf("dropped = %d, want 1", collector.Dropped())
	}
	if collector.Count() != 1 {
		t.Errorf("count = %d, want 1 (only the valid sample)", collector.Count())
	}
	if collector.Err().Error() == "" || !strings.Contains(collector.Err().Error(), "latency") {
		t.Errorf("error %q does not name the offending field", collector.Err())
	}
}

func TestNewCollectorRejectsUnusableWorkerIDs(t *testing.T) {
	for _, id := range []string{"", "   ", "\t\n"} {
		if _, err := NewCollector(id); err == nil {
			t.Errorf("worker id %q was accepted", id)
		}
	}
	if _, err := NewCollector("w1"); err != nil {
		t.Errorf("valid worker id rejected: %v", err)
	}
	// A long id is truncated rather than rejected.
	long := strings.Repeat("w", attest.MaxWorkerIDLen+50)
	c, err := NewCollector(long)
	if err != nil {
		t.Fatalf("long worker id rejected: %v", err)
	}
	if len(c.Worker()) != attest.MaxWorkerIDLen {
		t.Errorf("worker id length = %d, want %d", len(c.Worker()), attest.MaxWorkerIDLen)
	}
}

// Emit is called from every virtual user at once; the collector must not lose
// or corrupt a record under concurrency.
func TestCollectorIsSafeForConcurrentEmit(t *testing.T) {
	const goroutines, perGoroutine = 16, 250
	collector, err := NewCollector("concurrent")
	if err != nil {
		t.Fatal(err)
	}

	var seq uint64
	var seqMu sync.Mutex
	next := func() uint64 {
		seqMu.Lock()
		defer seqMu.Unlock()
		s := seq
		seq++
		return s
	}

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				collector.Emit(engine.Sample{
					Seq:       next(),
					StartNS:   int64(1_700_000_000_000_000_000 + i),
					LatencyNS: 1000,
					Status:    200,
					Bytes:     -1,
				})
			}
		}()
	}
	wg.Wait()

	if err := collector.Err(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	recs := collector.Records()
	if len(recs) != goroutines*perGoroutine {
		t.Fatalf("collected %d records, want %d", len(recs), goroutines*perGoroutine)
	}
	seen := make(map[uint64]bool, len(recs))
	for _, rec := range recs {
		if err := rec.Validate(); err != nil {
			t.Fatalf("record invalid after concurrent collection: %v", err)
		}
		if seen[rec.Seq] {
			t.Fatalf("duplicate seq %d after concurrent collection", rec.Seq)
		}
		seen[rec.Seq] = true
	}
	if !attest.RecordsInFileOrder(recs) {
		t.Error("records are not in canonical order after concurrent collection")
	}
}

// compile-time assertion: the collector is a valid engine.SampleSink.
var _ engine.SampleSink = (*Collector)(nil)
