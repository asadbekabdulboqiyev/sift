package evidence

import (
	"bytes"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/attest"
	"github.com/asadbekabdulboqiyev/sift/internal/engine"
	"github.com/asadbekabdulboqiyev/sift/internal/honesty"
)

func unitCollector(t *testing.T) *Collector {
	t.Helper()
	c, err := NewCollector("unit-worker")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []engine.Sample{
		{Seq: 0, StartNS: 1_000_000, LatencyNS: 1_000_000, Status: 200, Bytes: 10},
		{Seq: 1, StartNS: 2_000_000, LatencyNS: 2_000_000, Status: 200, Bytes: 20},
		{Seq: 2, StartNS: 3_000_000, LatencyNS: 3_000_000, Status: 204, Bytes: -1},
	} {
		c.Emit(s)
	}
	if err := c.Err(); err != nil {
		t.Fatalf("test setup: collector refused a sample: %v", err)
	}
	return c
}

func validBundleInput(t *testing.T) BundleInput {
	t.Helper()
	workerKey, coordKey := testKeys(t)
	planned, err := attest.DecimalFromMilli(3000)
	if err != nil {
		t.Fatal(err)
	}
	return BundleInput{
		Collector:      unitCollector(t),
		WorkerKey:      workerKey,
		CoordinatorKey: coordKey,
		Tool:           testTool(),
		Run: attest.Run{
			Target:     "http://example.test",
			Profile:    "steady",
			DurationNS: int64(time.Second),
			PlannedRPS: planned,
		},
		CreatedAt:   time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC),
		COCorrected: true,
	}
}

func TestBuildBundleSealsDeterministicCollectedEvidence(t *testing.T) {
	in := validBundleInput(t)

	b, err := BuildBundle(in)

	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}
	if err := b.Validate(); err != nil {
		t.Fatalf("built bundle does not validate: %v", err)
	}
	if err := b.VerifyCoordinatorSig(); err != nil {
		t.Fatalf("coordinator signature does not verify: %v", err)
	}
	if b.Format != attest.FormatID {
		t.Errorf("format = %q, want %q", b.Format, attest.FormatID)
	}
	if b.CreatedAt != "2026-11-20T10:00:00Z" {
		t.Errorf("created_at = %q, want fixed UTC timestamp", b.CreatedAt)
	}
	if len(b.Workers) != 1 || b.Workers[0].ID != "unit-worker" {
		t.Fatalf("workers = %+v, want one unit-worker", b.Workers)
	}
	if b.Workers[0].Commit.SampleCount != 3 {
		t.Errorf("commit sample count = %d, want 3", b.Workers[0].Commit.SampleCount)
	}
	if b.Aggregate.Count != 3 || b.Aggregate.SumLatencyNS != 6_000_000 {
		t.Errorf("aggregate count/sum = %d/%d, want 3/6000000", b.Aggregate.Count, b.Aggregate.SumLatencyNS)
	}
	if b.Aggregate.P50NS != 2_000_000 || b.Aggregate.P95NS != 3_000_000 || b.Aggregate.P99NS != 3_000_000 {
		t.Errorf("percentiles = %d/%d/%d, want 2ms/3ms/3ms", b.Aggregate.P50NS, b.Aggregate.P95NS, b.Aggregate.P99NS)
	}
	if !b.Aggregate.COCorrected || b.Aggregate.COCI95NS.HighNS < b.Aggregate.COCI95NS.LowNS {
		t.Errorf("CO claim is missing or inverted: %+v", b.Aggregate)
	}
	if b.Integrity.DroppedSamples != 0 {
		t.Errorf("dropped samples = %d, want 0 for 3 requests against 3 planned slots", b.Integrity.DroppedSamples)
	}
	if b.Integrity.ScheduleAccuracyPPM != 1_000_000 {
		t.Errorf("schedule accuracy = %d, want 1000000", b.Integrity.ScheduleAccuracyPPM)
	}
}

func TestBuildBundleFailsClosedOnInvalidInputs(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*BundleInput)
		want   string
	}{
		{"nil collector", func(in *BundleInput) { in.Collector = nil }, "no collector"},
		{"nil worker key", func(in *BundleInput) { in.WorkerKey = nil }, "worker signing key"},
		{"nil coordinator key", func(in *BundleInput) { in.CoordinatorKey = nil }, "coordinator signing key"},
		{"non-positive duration", func(in *BundleInput) { in.Run.DurationNS = 0 }, "must be positive"},
		{"non-canonical planned rate", func(in *BundleInput) { in.Run.PlannedRPS = attest.Decimal("bad") }, "planned_rps"},
		{"uncorrectable plan", func(in *BundleInput) {
			in.Run.PlannedRPS = attest.Decimal("0.000")
		}, "planned rate"},
		{"record with overflowing window", func(in *BundleInput) {
			c, err := NewCollector("overflow")
			if err != nil {
				t.Fatal(err)
			}
			c.Emit(engine.Sample{Seq: 0, StartNS: math.MaxInt64, LatencyNS: 1, Status: 200})
			in.Collector = c
		}, "build commit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := validBundleInput(t)
			tc.mutate(&in)

			b, err := BuildBundle(in)

			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("BuildBundle = (%+v, %v), want error containing %q", b, err, tc.want)
			}
		})
	}
}

func TestPercentileOfUsesNearestRankAndHandlesEmptyInput(t *testing.T) {
	values := []int64{10, 20, 30, 40, 50, 60, 70, 80, 90, 100}
	for _, tc := range []struct {
		name string
		ppm  int
		want int64
	}{
		{"below range", -1, 10},
		{"median", honesty.PPM50, 50},
		{"p95", honesty.PPM95, 100},
		{"p99", honesty.PPM99, 100},
		{"above range", 1_000_000, 100},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := percentileOf(values, tc.ppm); got != tc.want {
				t.Errorf("percentileOf(values, %d) = %d, want %d", tc.ppm, got, tc.want)
			}
		})
	}
	if got := percentileOf(nil, honesty.PPM99); got != 0 {
		t.Errorf("percentileOf(nil, p99) = %d, want 0", got)
	}
}

func TestCollectorLeavesMatchCanonicalRecords(t *testing.T) {
	c := unitCollector(t)
	recs := c.Records()

	leaves, err := c.Leaves()

	if err != nil {
		t.Fatalf("Leaves: %v", err)
	}
	if len(leaves) != len(recs) {
		t.Fatalf("leaves = %d, want %d", len(leaves), len(recs))
	}
	for i, rec := range recs {
		want, err := attest.CanonicalRecord(rec)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(leaves[i], want) {
			t.Errorf("leaf %d = %q, want %q", i, leaves[i], want)
		}
		if digest := attest.LeafHash(i, leaves[i]); len(digest) == 0 {
			t.Errorf("leaf %d produced an empty hash", i)
		}
	}
}

func TestWriteBundleWritesSidecarAndBundle(t *testing.T) {
	in := validBundleInput(t)
	b, err := BuildBundle(in)
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "run.json")

	sidecar, err := WriteBundle(b, in.Collector.Records(), bundlePath)

	if err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}
	wantSidecar := filepath.Join(dir, "run.samples.jsonl")
	if sidecar != wantSidecar {
		t.Errorf("sidecar = %q, want %q", sidecar, wantSidecar)
	}
	loaded, err := attest.LoadBundle(bundlePath)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	if loaded.CreatedAt != b.CreatedAt {
		t.Errorf("loaded created_at = %q, want %q", loaded.CreatedAt, b.CreatedAt)
	}
	samples, _, err := attest.LoadSamples(sidecar, attest.DefaultSampleLoadOptions())
	if err != nil {
		t.Fatalf("LoadSamples: %v", err)
	}
	res := attest.Verify(loaded, samples)
	if !res.Valid {
		t.Fatalf("written bundle does not verify: %v", res.ErrorLines())
	}
	if res.Summary.SamplesTotal != in.Collector.Count() {
		t.Errorf("verified sidecar samples = %d, want %d", res.Summary.SamplesTotal, in.Collector.Count())
	}
	info, err := os.Stat(sidecar)
	if err != nil {
		t.Fatal(err)
	}
	// Windows has no POSIX permission bits: os.Chmod only toggles the
	// read-only attribute and os.Stat reports 0666 for any writable file,
	// so the assertion is meaningful on Unix (Linux/macOS) only.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("sidecar mode = %o, want 600", info.Mode().Perm())
	}
}

func TestWriteBundleFailsWhenBundleCannotBeSaved(t *testing.T) {
	in := validBundleInput(t)
	b, err := BuildBundle(in)
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle-dir")
	if err := os.Mkdir(bundlePath, 0o750); err != nil {
		t.Fatal(err)
	}

	sidecar, err := WriteBundle(b, in.Collector.Records(), bundlePath)

	if err == nil {
		t.Fatal("WriteBundle succeeded with a directory as the bundle path")
	}
	if sidecar != "" {
		t.Errorf("sidecar = %q, want empty on failure", sidecar)
	}
	if _, err := os.Stat(filepath.Join(dir, "bundle-dir.samples.jsonl")); err != nil {
		t.Errorf("sidecar should have been written before the bundle: %v", err)
	}
}

func TestWriteSidecarReportsAllFailureModes(t *testing.T) {
	recs := unitCollector(t).Records()
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	sidecarDir := filepath.Join(dir, "sidecar-dir")
	if err := os.Mkdir(sidecarDir, 0o750); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		path string
		recs []attest.Record
		want string
	}{
		{"parent is a file", filepath.Join(blocker, "sub", "sidecar.jsonl"), recs, "create"},
		{"unrepresentable record", filepath.Join(dir, "invalid.jsonl"), []attest.Record{{Seq: 0, Worker: "w"}}, "encode sidecar"},
		{"target is a directory", sidecarDir, recs, "write sidecar"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := writeSidecar(tc.path, tc.recs)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("writeSidecar = %v, want error containing %q", err, tc.want)
			}
		})
	}
}
