package evidence

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/attest"
	"github.com/asadbekabdulboqiyev/sift/internal/config"
	"github.com/asadbekabdulboqiyev/sift/internal/engine"
)

// runAndCollect drives a short live run against a local target and returns the
// collector together with the run description that matches it.
func runAndCollect(t *testing.T, durationSeconds int) (*Collector, attest.Run) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	sc := &config.Scenario{
		Name: "evidence-build",
		Profile: config.Profile{
			Type:     config.ProfileSteady,
			Users:    4,
			Duration: durationSeconds,
			Timeout:  2,
		},
		Steps: []config.Step{{Name: "health", Method: "GET", URL: srv.URL}},
	}
	eng, err := engine.New(sc)
	if err != nil {
		t.Fatal(err)
	}
	collector, err := NewCollector("local-1")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := eng.Run(ctx, engine.RunOptions{Quiet: true, Samples: collector}); err != nil {
		t.Fatalf("run: %v", err)
	}

	planned, err := attest.DecimalFromMilli(200)
	if err != nil {
		t.Fatal(err)
	}
	return collector, attest.Run{
		Target:     srv.URL,
		Profile:    "steady",
		DurationNS: int64(durationSeconds) * int64(time.Second),
		PlannedRPS: planned,
	}
}

func testKeys(t *testing.T) (*attest.Keypair, *attest.Keypair) {
	t.Helper()
	worker, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	coord, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	return worker, coord
}

func testTool() attest.Tool {
	return attest.Tool{Name: "Sift", Version: "test"}
}

// Evidence that is known to be incomplete must never be sealed: a bundle
// claiming a completeness the run does not have is worse than no bundle.
func TestBuildBundleRefusesIncompleteEvidence(t *testing.T) {
	collector, err := NewCollector("incomplete")
	if err != nil {
		t.Fatal(err)
	}
	collector.Emit(engine.Sample{Seq: 0, StartNS: 1000, LatencyNS: -1, Status: 200})
	if collector.Err() == nil {
		t.Fatal("test setup: the collector accepted an unusable sample")
	}
	workerKey, coordKey := testKeys(t)
	planned, err := attest.DecimalFromMilli(100)
	if err != nil {
		t.Fatal(err)
	}

	_, err = BuildBundle(BundleInput{
		Collector:      collector,
		WorkerKey:      workerKey,
		CoordinatorKey: coordKey,
		Tool:           testTool(),
		Run: attest.Run{
			Target:     "http://example.invalid",
			Profile:    "steady",
			DurationNS: int64(time.Second),
			PlannedRPS: planned,
		},
	})
	if err == nil {
		t.Fatal("evidence known to be incomplete was sealed anyway")
	}
	if !strings.Contains(err.Error(), "incomplete") {
		t.Errorf("error %q does not explain the refusal", err)
	}
}

// The coordinated-omission correction is defined against a pacing schedule, so
// it cannot be claimed for an unpaced run.
func TestCorrectionRequiresAPlannedRate(t *testing.T) {
	collector, err := NewCollector("unpaced")
	if err != nil {
		t.Fatal(err)
	}
	collector.Emit(engine.Sample{Seq: 0, StartNS: 1000, LatencyNS: 1000, Status: 200})
	workerKey, coordKey := testKeys(t)
	zero, err := attest.DecimalFromMilli(0)
	if err != nil {
		t.Fatal(err)
	}

	_, err = BuildBundle(BundleInput{
		Collector:      collector,
		WorkerKey:      workerKey,
		CoordinatorKey: coordKey,
		Tool:           testTool(),
		Run: attest.Run{
			Target:     "http://example.invalid",
			Profile:    "steady",
			DurationNS: int64(time.Second),
			PlannedRPS: zero,
		},
		COCorrected: true,
	})
	if err == nil {
		t.Fatal("a corrected claim was sealed with a zero planned rate")
	}
	if !strings.Contains(err.Error(), "planned rate") {
		t.Errorf("error %q does not name the missing rate", err)
	}
}

func TestSidecarPath(t *testing.T) {
	for _, tc := range []struct{ bundle, want string }{
		{"run.json", "run.samples.jsonl"},
		{"/tmp/a/bundle.json", "/tmp/a/bundle.samples.jsonl"},
		{"evidence", "evidence.samples.jsonl"},
		{"/tmp/evidence.bundle", "/tmp/evidence.bundle.samples.jsonl"},
	} {
		if got := SidecarPath(tc.bundle); got != tc.want {
			t.Errorf("SidecarPath(%q) = %q, want %q", tc.bundle, got, tc.want)
		}
	}
}
