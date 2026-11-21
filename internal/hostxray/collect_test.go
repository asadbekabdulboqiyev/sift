package hostxray

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// scriptedCollector is a deterministic Collector: it returns a fixed sequence
// of samples and never touches /proc, the network, or the DNS. Call 1 is the
// priming read performed by Stream; calls 2..n are the emitted reads.
type scriptedCollector struct {
	samples  []Sample
	calls    int
	errAt    map[int]error
	caps     Capabilities
	closeErr error
	closed   bool
}

func (c *scriptedCollector) Collect(context.Context) (Sample, error) {
	c.calls++
	if err := c.errAt[c.calls]; err != nil {
		return Sample{}, err
	}
	if c.calls > len(c.samples) {
		return Sample{}, nil
	}
	return c.samples[c.calls-1], nil
}

func (c *scriptedCollector) Capabilities() Capabilities { return c.caps }

func (c *scriptedCollector) Close() error {
	c.closed = true
	return c.closeErr
}

func fixedSample(source string, at time.Time) Sample {
	return Sample{Source: source, Timestamp: at}
}

func TestNewRequiresOptIn(t *testing.T) {
	_, err := New(Options{Interval: MinInterval, MaxSamples: 1})
	if !errors.Is(err, ErrNotOptedIn) {
		t.Fatalf("New without opt-in returned %v, want ErrNotOptedIn", err)
	}
}

func TestNewValidatesOptions(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts Options
		want string
	}{
		{"interval below minimum", Options{OptIn: true, Interval: MinInterval - time.Millisecond, MaxSamples: 1}, "below the"},
		{"interval above maximum", Options{OptIn: true, Interval: MaxInterval + time.Second, MaxSamples: 1}, "exceeds the"},
		{"negative duration", Options{OptIn: true, Interval: MinInterval, Duration: -time.Second}, "duration must not be negative"},
		{"duration above maximum", Options{OptIn: true, Interval: MinInterval, Duration: MaxDuration + time.Second}, "exceeds the"},
		{"negative max samples", Options{OptIn: true, Interval: MinInterval, MaxSamples: -1}, "max samples must not be negative"},
		{"max samples above limit", Options{OptIn: true, Interval: MinInterval, MaxSamples: MaxSamplesLimit + 1}, "max samples"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			agent, err := New(tc.opts)
			if err == nil {
				t.Fatalf("New(%+v) succeeded; want error containing %q", tc.opts, tc.want)
			}
			if agent != nil {
				t.Errorf("New returned agent %v alongside error", agent)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

func TestNewNormalizesOptionsAndExposesCapabilities(t *testing.T) {
	agent, err := New(Options{OptIn: true, Labels: map[string]string{"run": "r1"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = agent.Close() })

	opts := agent.Options()
	if opts.Interval != DefaultInterval {
		t.Errorf("normalized interval = %s, want %s", opts.Interval, DefaultInterval)
	}
	if opts.Duration != DefaultDuration {
		t.Errorf("normalized duration = %s, want %s", opts.Duration, DefaultDuration)
	}
	if opts.MaxSamples != 0 || !opts.OptIn || opts.Redact {
		t.Errorf("unexpected normalized options: %+v", opts)
	}
	if opts.Labels["run"] != "r1" {
		t.Errorf("labels lost: %+v", opts.Labels)
	}

	caps := agent.Capabilities()
	if caps.OS != runtime.GOOS || caps.Arch != runtime.GOARCH {
		t.Errorf("capabilities OS/arch = %s/%s, want %s/%s", caps.OS, caps.Arch, runtime.GOOS, runtime.GOARCH)
	}
	if caps.DetectedAt.IsZero() {
		t.Error("capabilities DetectedAt is zero")
	}
	wantSource := SourceRuntime
	if runtime.GOOS == "linux" {
		wantSource = SourceLinuxProc
	}
	if caps.Source != wantSource {
		t.Errorf("capabilities source = %q, want %q", caps.Source, wantSource)
	}
}

func TestAgentOptionsReturnsDefensiveCopy(t *testing.T) {
	agent := &Agent{opts: Options{Labels: map[string]string{"run": "r1"}}}
	opts := agent.Options()
	opts.Labels["run"] = "changed"
	if agent.opts.Labels["run"] != "r1" {
		t.Errorf("mutating the returned labels changed the agent: %+v", agent.opts.Labels)
	}
}

func TestAgentCloseIsNilSafeAndIdempotent(t *testing.T) {
	var nilAgent *Agent
	if err := nilAgent.Close(); err != nil {
		t.Errorf("nil agent Close = %v, want nil", err)
	}

	sentinel := errors.New("close failed")
	fake := &scriptedCollector{closeErr: sentinel}
	agent := &Agent{collector: fake}
	if err := agent.Close(); !errors.Is(err, sentinel) {
		t.Errorf("first Close = %v, want %v", err, sentinel)
	}
	if err := agent.Close(); !errors.Is(err, sentinel) {
		t.Errorf("second Close = %v, want %v", err, sentinel)
	}
	if fake.closed != true {
		t.Error("collector Close was not called")
	}
}

func TestAgentRunCollectsBoundedDeterministicSamples(t *testing.T) {
	// Arrange: call 1 primes the delta state and is not emitted.
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	fake := &scriptedCollector{samples: []Sample{
		{Source: "prime"},
		{Source: "first", Timestamp: base, Labels: map[string]string{"sample": "yes"}},
		{Source: "second", Timestamp: base.Add(time.Second)},
	}}
	agent := &Agent{
		opts:      Options{Interval: MinInterval, MaxSamples: 2, Labels: map[string]string{"run": "r1"}},
		collector: fake,
	}

	// Act.
	got, err := agent.Run(context.Background())

	// Assert.
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("emitted %d samples, want 2", len(got))
	}
	if fake.calls != 3 {
		t.Errorf("collector calls = %d, want 3 (one prime + two emitted)", fake.calls)
	}
	if got[0].Source != "first" || got[1].Source != "second" {
		t.Errorf("sample sources = %q, %q; want first, second", got[0].Source, got[1].Source)
	}
	if !got[0].Timestamp.Equal(base) || !got[1].Timestamp.Equal(base.Add(time.Second)) {
		t.Errorf("timestamps were not preserved: %v, %v", got[0].Timestamp, got[1].Timestamp)
	}
	if got[0].Labels["run"] != "r1" || got[0].Labels["sample"] != "yes" {
		t.Errorf("first sample labels = %+v, want run=r1 and sample=yes", got[0].Labels)
	}
	if got[1].Labels["run"] != "r1" {
		t.Errorf("second sample labels = %+v, want run=r1", got[1].Labels)
	}
}

func TestAgentStreamFillsMissingTimestampRedactsAndMergesLabels(t *testing.T) {
	fake := &scriptedCollector{samples: []Sample{
		{Source: "prime"},
		{
			Source: "emitted",
			Net: NetStats{
				Interfaces: []InterfaceCounters{{Name: "eth0", RxBytes: 10}, {Name: "ens5"}, {Name: "eth0"}},
				Aggregate:  InterfaceCounters{Name: "real-host-name", RxBytes: 10},
			},
			Labels: map[string]string{"sample": "s"},
		},
	}}
	before := time.Now().UTC()
	agent := &Agent{
		opts:      Options{Interval: MinInterval, MaxSamples: 1, Redact: true, Labels: map[string]string{"run": "r1"}},
		collector: fake,
	}

	var emitted []Sample
	err := agent.Stream(context.Background(), func(s Sample) error {
		emitted = append(emitted, s)
		return nil
	})

	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	if len(emitted) != 1 {
		t.Fatalf("emitted %d samples, want 1", len(emitted))
	}
	s := emitted[0]
	if s.Timestamp.IsZero() || s.Timestamp.Before(before.Add(-time.Second)) {
		t.Errorf("zero/missing timestamp was not filled: %v", s.Timestamp)
	}
	// Sorted unique names are ens5, eth0, eth0 -> aliases iface-0 and iface-1.
	wantNames := []string{"iface-1", "iface-0", "iface-1"}
	if len(s.Net.Interfaces) != len(wantNames) {
		t.Fatalf("interfaces = %+v, want %d entries", s.Net.Interfaces, len(wantNames))
	}
	for i, want := range wantNames {
		if s.Net.Interfaces[i].Name != want {
			t.Errorf("interface %d name = %q, want %q", i, s.Net.Interfaces[i].Name, want)
		}
	}
	if s.Net.Aggregate.Name != "aggregate" {
		t.Errorf("aggregate name = %q, want %q", s.Net.Aggregate.Name, "aggregate")
	}
	if s.Labels["run"] != "r1" || s.Labels["sample"] != "s" {
		t.Errorf("merged labels = %+v", s.Labels)
	}
	// Redaction must not mutate the source sample.
	if fake.samples[1].Net.Interfaces[0].Name != "eth0" || fake.samples[1].Net.Aggregate.Name != "real-host-name" {
		t.Errorf("redaction mutated the collector's sample: %+v", fake.samples[1].Net)
	}
}

func TestAgentStreamStopsOnCallbackError(t *testing.T) {
	sentinel := errors.New("consumer rejected sample")
	fake := &scriptedCollector{samples: []Sample{
		{Source: "prime"},
		{Source: "first"},
		{Source: "second"},
	}}
	agent := &Agent{
		opts:      Options{Interval: MinInterval, MaxSamples: 2},
		collector: fake,
	}

	seen := 0
	err := agent.Stream(context.Background(), func(Sample) error {
		seen++
		return sentinel
	})

	if !errors.Is(err, sentinel) {
		t.Fatalf("Stream error = %v, want %v", err, sentinel)
	}
	if seen != 1 || fake.calls != 2 {
		t.Errorf("seen=%d calls=%d, want 1 and 2 (no read after the callback error)", seen, fake.calls)
	}
}

func TestAgentStreamHonorsAlreadyCanceledContext(t *testing.T) {
	fake := &scriptedCollector{samples: []Sample{{Source: "prime"}, {Source: "emitted"}}}
	agent := &Agent{opts: Options{Interval: MinInterval, MaxSamples: 1}, collector: fake}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := agent.Stream(ctx, func(Sample) error { return nil })

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Stream error = %v, want context.Canceled", err)
	}
	if fake.calls != 0 {
		t.Errorf("collector was called %d times on a canceled context, want 0", fake.calls)
	}
}

func TestAgentStreamRejectsConcurrentCollection(t *testing.T) {
	fake := &scriptedCollector{samples: []Sample{{Source: "prime"}, {Source: "emitted"}}}
	agent := &Agent{opts: Options{Interval: MinInterval, MaxSamples: 1}, collector: fake}
	agent.running.Store(true)

	err := agent.Stream(context.Background(), func(Sample) error { return nil })

	if err == nil || !strings.Contains(err.Error(), "already in progress") {
		t.Fatalf("concurrent Stream error = %v, want 'already in progress'", err)
	}
	if fake.calls != 0 {
		t.Errorf("collector was called %d times, want 0", fake.calls)
	}
}

func TestAgentStreamReportsPrimeAndCollectFailures(t *testing.T) {
	sentinel := errors.New("collector unavailable")
	for _, tc := range []struct {
		name     string
		errAt    map[int]error
		errText  string
		wantCall int
	}{
		{"prime failure", map[int]error{1: sentinel}, "prime sample", 1},
		{"emitted failure", map[int]error{2: sentinel}, "collect sample", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &scriptedCollector{
				samples: []Sample{{Source: "prime"}, {Source: "emitted"}},
				errAt:   tc.errAt,
			}
			agent := &Agent{opts: Options{Interval: MinInterval, MaxSamples: 1}, collector: fake}

			err := agent.Stream(context.Background(), func(Sample) error { return nil })

			if !errors.Is(err, sentinel) {
				t.Fatalf("Stream error = %v, want wrapped %v", err, sentinel)
			}
			if !strings.Contains(err.Error(), tc.errText) {
				t.Errorf("error %q does not contain %q", err, tc.errText)
			}
			if fake.calls != tc.wantCall {
				t.Errorf("collector calls = %d, want %d", fake.calls, tc.wantCall)
			}
		})
	}
}

func TestAgentStreamNilGuards(t *testing.T) {
	var nilAgent *Agent
	if err := nilAgent.Stream(context.Background(), func(Sample) error { return nil }); err == nil {
		t.Error("nil agent Stream succeeded")
	}

	agent := &Agent{opts: Options{Interval: MinInterval, MaxSamples: 1}, collector: &scriptedCollector{}}
	if err := agent.Stream(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "nil sample callback") {
		t.Errorf("nil callback error = %v, want 'nil sample callback'", err)
	}

	// A nil context is treated as context.Background(). Use a typed zero-value
	// variable to exercise that path without passing a nil literal.
	var nilCtx context.Context
	fake := &scriptedCollector{samples: []Sample{{Source: "prime"}, {Source: "emitted"}}}
	agent = &Agent{opts: Options{Interval: MinInterval, MaxSamples: 1}, collector: fake}
	emitted := 0
	if err := agent.Stream(nilCtx, func(Sample) error { emitted++; return nil }); err != nil {
		t.Fatalf("Stream with nil context: %v", err)
	}
	if emitted != 1 {
		t.Errorf("emitted %d samples with nil context, want 1", emitted)
	}
}

func TestAgentSchedule(t *testing.T) {
	for _, tc := range []struct {
		name         string
		opts         Options
		wantInterval time.Duration
		wantLimit    int
	}{
		{"defaults", Options{}, DefaultInterval, 1},
		{"duration divides exactly", Options{Interval: 2 * time.Second, Duration: 10 * time.Second}, 2 * time.Second, 5},
		{"window shorter than interval yields one sample", Options{Interval: 5 * time.Second, Duration: 3 * time.Second}, 3 * time.Second, 1},
		{"max samples overrides duration limit", Options{Interval: 2 * time.Second, Duration: 10 * time.Second, MaxSamples: 3}, 2 * time.Second, 3},
		{"max samples only", Options{Interval: 0, MaxSamples: 7}, DefaultInterval, 7},
		{"negative interval falls back", Options{Interval: -time.Second, MaxSamples: 1}, DefaultInterval, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			agent := &Agent{opts: tc.opts}
			interval, limit := agent.schedule()
			if interval != tc.wantInterval || limit != tc.wantLimit {
				t.Errorf("schedule = (%s, %d), want (%s, %d)", interval, limit, tc.wantInterval, tc.wantLimit)
			}
		})
	}
}

func TestExpectedSamplesMatchesScheduleLimit(t *testing.T) {
	for _, tc := range []struct {
		opts Options
		want int
	}{
		{Options{}, 1},
		{Options{Interval: MinInterval, MaxSamples: 4}, 4},
		{Options{Interval: time.Second, Duration: 5 * time.Second}, 5},
	} {
		if got := (&Agent{opts: tc.opts}).expectedSamples(); got != tc.want {
			t.Errorf("expectedSamples(%+v) = %d, want %d", tc.opts, got, tc.want)
		}
	}
}

func TestNormalizeOptions(t *testing.T) {
	labels := map[string]string{"run": "r1"}
	got := normalizeOptions(Options{Labels: labels})
	if got.Interval != DefaultInterval || got.Duration != DefaultDuration {
		t.Errorf("defaults not applied: %+v", got)
	}
	labels["run"] = "changed"
	if got.Labels["run"] != "r1" {
		t.Errorf("normalizeOptions did not copy labels: %+v", got.Labels)
	}

	explicit := Options{Interval: MinInterval, Duration: time.Second, MaxSamples: 2, Redact: true}
	if norm := normalizeOptions(explicit); norm.Interval != MinInterval || norm.Duration != time.Second || norm.MaxSamples != 2 || !norm.Redact {
		t.Errorf("explicit options were changed: %+v", norm)
	}
}

func TestValidateOptionsRejectsInvalidBounds(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts Options
		want string
	}{
		{"interval below minimum", Options{Interval: MinInterval - time.Nanosecond, MaxSamples: 1}, "below the"},
		{"interval above maximum", Options{Interval: MaxInterval + time.Nanosecond, MaxSamples: 1}, "exceeds the"},
		{"negative duration", Options{Interval: MinInterval, Duration: -1}, "duration must not be negative"},
		{"duration above maximum", Options{Interval: MinInterval, Duration: MaxDuration + 1}, "exceeds the"},
		{"unbounded collection", Options{Interval: MinInterval}, "must be bounded"},
		{"negative max samples", Options{Interval: MinInterval, MaxSamples: -1}, "max samples must not be negative"},
		{"too many max samples", Options{Interval: MinInterval, MaxSamples: MaxSamplesLimit + 1}, "exceeds the"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateOptions(tc.opts)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("validateOptions(%+v) = %v, want error containing %q", tc.opts, err, tc.want)
			}
		})
	}

	valid := []Options{
		{Interval: MinInterval, MaxSamples: 1},
		{Interval: MaxInterval, Duration: MaxDuration},
		{Interval: MinInterval, Duration: time.Second, MaxSamples: 3},
	}
	for _, opts := range valid {
		if err := validateOptions(opts); err != nil {
			t.Errorf("validateOptions(%+v) = %v, want nil", opts, err)
		}
	}
}

func TestDetectCapabilitiesReportsHostFacts(t *testing.T) {
	caps := DetectCapabilities()
	if caps.OS != runtime.GOOS || caps.Arch != runtime.GOARCH {
		t.Errorf("OS/arch = %s/%s, want %s/%s", caps.OS, caps.Arch, runtime.GOOS, runtime.GOARCH)
	}
	if caps.DetectedAt.IsZero() {
		t.Error("DetectedAt is zero")
	}
	if runtime.GOOS == "linux" {
		if caps.Source != SourceLinuxProc {
			t.Errorf("linux source = %q, want %q", caps.Source, SourceLinuxProc)
		}
		if len(caps.Notes) == 0 {
			t.Error("linux capabilities carry no notes")
		}
	} else {
		if caps.Source != SourceRuntime {
			t.Errorf("non-linux source = %q, want %q", caps.Source, SourceRuntime)
		}
		joined := strings.Join(caps.Notes, " ")
		if !strings.Contains(joined, "Go runtime") {
			t.Errorf("notes do not explain the runtime-only source: %v", caps.Notes)
		}
	}
}

func TestExistsOnlyForPresentPath(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Join(dir, "present")
	if err := os.WriteFile(present, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !exists(present) {
		t.Error("exists returned false for a present file")
	}
	if exists(filepath.Join(dir, "missing")) {
		t.Error("exists returned true for a missing file")
	}
}

func TestRuntimeSnapshotIsAvailable(t *testing.T) {
	snap := runtimeSnapshot()
	if !snap.Available {
		t.Errorf("runtime snapshot is not available: %+v", snap)
	}
	if snap.GOMAXPROCS != runtime.GOMAXPROCS(0) {
		t.Errorf("GOMAXPROCS = %d, want %d", snap.GOMAXPROCS, runtime.GOMAXPROCS(0))
	}
	if snap.Goroutines <= 0 || snap.HeapAllocBytes == 0 {
		t.Errorf("implausible runtime snapshot: %+v", snap)
	}
}

func TestRedactSampleUsesStableSortedAliases(t *testing.T) {
	in := Sample{
		Net: NetStats{
			Interfaces: []InterfaceCounters{
				{Name: "eth0", RxBytes: 1},
				{Name: "ens5", RxBytes: 2},
				{Name: "eth0", RxBytes: 3},
				{Name: "lo", RxBytes: 4},
			},
			Aggregate: InterfaceCounters{Name: "eth0", RxBytes: 11},
		},
	}
	got := redactSample(in)
	want := []string{"iface-1", "iface-0", "iface-1", "iface-2"}
	if len(got.Net.Interfaces) != len(want) {
		t.Fatalf("interfaces = %+v, want %d entries", got.Net.Interfaces, len(want))
	}
	for i, name := range want {
		if got.Net.Interfaces[i].Name != name {
			t.Errorf("interface %d = %q, want %q", i, got.Net.Interfaces[i].Name, name)
		}
	}
	if got.Net.Interfaces[0].RxBytes != 1 || got.Net.Interfaces[3].RxBytes != 4 {
		t.Errorf("counters were not preserved: %+v", got.Net.Interfaces)
	}
	if got.Net.Aggregate.Name != "aggregate" || got.Net.Aggregate.RxBytes != 11 {
		t.Errorf("aggregate = %+v, want name 'aggregate' and RxBytes 11", got.Net.Aggregate)
	}
	if in.Net.Interfaces[0].Name != "eth0" || in.Net.Aggregate.Name != "eth0" {
		t.Errorf("input sample was mutated: %+v", in.Net)
	}
}

func TestRedactSampleWithNoInterfaces(t *testing.T) {
	got := redactSample(Sample{Net: NetStats{Aggregate: InterfaceCounters{Name: "eth0"}}})
	if len(got.Net.Interfaces) != 0 {
		t.Errorf("interfaces = %+v, want none", got.Net.Interfaces)
	}
	if got.Net.Aggregate.Name != "aggregate" {
		t.Errorf("aggregate name = %q, want 'aggregate'", got.Net.Aggregate.Name)
	}
}

func TestMergeAndCloneLabels(t *testing.T) {
	for _, tc := range []struct {
		name         string
		opts, sample map[string]string
		want         map[string]string
	}{
		{"both empty", nil, nil, nil},
		{"opts only", map[string]string{"a": "1"}, nil, map[string]string{"a": "1"}},
		{"sample only", nil, map[string]string{"b": "2"}, map[string]string{"b": "2"}},
		{"sample wins on conflict", map[string]string{"a": "1", "b": "2"}, map[string]string{"b": "3"}, map[string]string{"a": "1", "b": "3"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := mergeLabels(tc.opts, tc.sample)
			if len(got) != len(tc.want) {
				t.Fatalf("mergeLabels = %+v, want %+v", got, tc.want)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Errorf("key %q = %q, want %q", k, got[k], v)
				}
			}
		})
	}

	if cloneLabels(nil) != nil {
		t.Error("cloneLabels(nil) should be nil")
	}
	src := map[string]string{"a": "1"}
	clone := cloneLabels(src)
	clone["a"] = "changed"
	if src["a"] != "1" {
		t.Errorf("cloneLabels shared the backing map: %+v", src)
	}
}
