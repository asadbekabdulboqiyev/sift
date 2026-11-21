package hostxray

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func assertSignalsEqual(t *testing.T, got, want []Signal) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("signals count = %d, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if !got[i].Timestamp.Equal(want[i].Timestamp) {
			t.Errorf("signal %d timestamp = %v, want %v", i, got[i].Timestamp, want[i].Timestamp)
		}
		if got[i].RPS != want[i].RPS || got[i].P99Ms != want[i].P99Ms || got[i].ErrorRate != want[i].ErrorRate {
			t.Errorf("signal %d metrics = %+v, want %+v", i, got[i], want[i])
		}
		if got[i].Step != want[i].Step || got[i].Endpoint != want[i].Endpoint || got[i].Label != want[i].Label {
			t.Errorf("signal %d labels = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestLoadSignalsAcceptsEveryDocumentShape(t *testing.T) {
	first := Signal{
		Timestamp: time.Date(2026, 1, 2, 3, 4, 4, 0, time.UTC),
		P99Ms:     90,
	}
	second := Signal{
		Timestamp: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		RPS:       12,
		P99Ms:     150,
		ErrorRate: 0.02,
		Step:      "load",
		Endpoint:  "/api",
		Label:     "peak",
	}
	want := []Signal{first, second}

	for _, tc := range []struct {
		name string
		body string
	}{
		{
			name: "JSON array",
			body: `[
				{"timestamp":"2026-01-02T03:04:05Z","rps":12,"p99":150,"error_rate":0.02,"step":"load","endpoint":"/api","label":"peak"},
				{"timestamp":"2026-01-02T03:04:04Z","p99_ms":90}
			]`,
		},
		{
			name: "wrapper object",
			body: `{"signals":[
				{"timestamp":"2026-01-02T03:04:05Z","rps":12,"p99":150,"error_rate":0.02,"step":"load","endpoint":"/api","label":"peak"},
				{"timestamp":"2026-01-02T03:04:04Z","p99_ms":90}
			]}`,
		},
		{
			name: "JSON Lines with comments",
			body: "# operator annotation\n\n" +
				`{"timestamp":"2026-01-02T03:04:05Z","rps":12,"p99":150,"error_rate":0.02,"step":"load","endpoint":"/api","label":"peak"}` + "\n" +
				`{"ts":"2026-01-02T03:04:04Z","p99_ms":90}` + "\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "signals.json")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}

			got, err := LoadSignals(path)

			if err != nil {
				t.Fatalf("LoadSignals: %v", err)
			}
			assertSignalsEqual(t, got, want)
		})
	}
}

// TestLoadSignalsAcceptsSingleObject pins the third documented input shape:
// a bare signal object must load as one signal, not be mistaken for an empty
// {"signals":[]} wrapper.
func TestLoadSignalsAcceptsSingleObject(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signals.json")
	body := `{"timestamp":"2026-01-02T03:04:05Z","rps":12,"p99":150,"error_rate":0.02,"step":"load","endpoint":"/api","label":"peak"}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := LoadSignals(path)
	if err != nil {
		t.Fatalf("LoadSignals: %v", err)
	}
	assertSignalsEqual(t, got, []Signal{{
		Timestamp: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		RPS:       12,
		P99Ms:     150,
		ErrorRate: 0.02,
		Step:      "load",
		Endpoint:  "/api",
		Label:     "peak",
	}})
}

func TestLoadSignalsAcceptsNumericTimestampsInJSONL(t *testing.T) {
	base := time.Unix(1_760_000_000, 0).UTC()
	trailing := `{"timestamp":1760000001,"rps":2}` + "\n"
	for _, tc := range []struct {
		name string
		body string
	}{
		{"seconds", `{"timestamp":1760000000,"rps":1}` + "\n" + trailing},
		{"milliseconds", `{"timestamp":1760000000000,"rps":1}` + "\n" + trailing},
		{"microseconds", `{"timestamp":1760000000000000,"rps":1}` + "\n" + trailing},
		{"nanoseconds", `{"timestamp":1760000000000000000,"rps":1}` + "\n" + trailing},
		{"ts alias", `{"ts":1760000000,"rps":1}` + "\n" + trailing},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "signals.json")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}

			got, err := LoadSignals(path)

			if err != nil {
				t.Fatalf("LoadSignals: %v", err)
			}
			assertSignalsEqual(t, got, []Signal{
				{Timestamp: base, RPS: 1},
				{Timestamp: base.Add(time.Second), RPS: 2},
			})
		})
	}
}

func TestLoadSignalsRejectsMalformedOrUnjoinableInput(t *testing.T) {
	jsonlTail := "\n" + `{"timestamp":"2026-01-02T03:04:05Z","rps":1}` + "\n"
	for _, tc := range []struct {
		name    string
		content *string
		want    string
	}{
		{name: "missing file", want: "read"},
		{name: "empty file", content: stringPtr("  \n"), want: "empty"},
		{name: "empty wrapper", content: stringPtr(`{"signals":[]}`), want: "no signals"},
		{name: "only comments", content: stringPtr("# nothing\n\n"), want: "no signals"},
		{name: "malformed array", content: stringPtr(`[{"timestamp":`), want: "parse signals"},
		{name: "single object without timestamp", content: stringPtr(`{"rps":1}`), want: "missing timestamp"},
		{name: "malformed line", content: stringPtr("{not json}\n"), want: "line 1"},
		{name: "missing timestamp", content: stringPtr(`{"rps":1}` + jsonlTail), want: "missing timestamp"},
		{name: "negative rps", content: stringPtr(`{"timestamp":"2026-01-02T03:04:05Z","rps":-1}` + jsonlTail), want: "must not be negative"},
		{name: "negative p99", content: stringPtr(`{"timestamp":"2026-01-02T03:04:05Z","p99_ms":-1}` + jsonlTail), want: "must not be negative"},
		{name: "error rate above one", content: stringPtr(`{"timestamp":"2026-01-02T03:04:05Z","error_rate":2}` + jsonlTail), want: "fraction between 0 and 1"},
		{name: "negative error rate", content: stringPtr(`{"timestamp":"2026-01-02T03:04:05Z","error_rate":-0.1}` + jsonlTail), want: "fraction between 0 and 1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "signals.json")
			if tc.content != nil {
				if err := os.WriteFile(path, []byte(*tc.content), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			got, err := LoadSignals(path)

			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("LoadSignals = (%v, %v), want error containing %q", got, err, tc.want)
			}
			if got != nil {
				t.Errorf("LoadSignals returned signals %+v alongside error", got)
			}
		})
	}
}

func TestWriteJSONLAndLoadJSONLRoundTrip(t *testing.T) {
	base := time.Date(2026, 1, 2, 3, 4, 5, 123_000_000, time.UTC)
	first := fixedSample(SourceRuntime, base.Add(time.Second))
	first.Labels = map[string]string{"run": "r1"}
	second := fixedSample(SourceLinuxProc, base)
	samples := []Sample{first, second}

	dir := filepath.Join(t.TempDir(), "artifacts", "nested")
	path := filepath.Join(dir, "samples.jsonl")
	if err := WriteJSONL(path, samples); err != nil {
		t.Fatalf("WriteJSONL: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Windows has no POSIX permission bits: os.Chmod only toggles the
	// read-only attribute and os.Stat reports 0666 for any writable file,
	// so the assertion is meaningful on Unix (Linux/macOS) only.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("artifact mode = %o, want 600", info.Mode().Perm())
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !dirInfo.IsDir() {
		t.Error("artifact parent is not a directory")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data), "\n") != 2 {
		t.Errorf("expected two JSONL lines, got %q", data)
	}

	got, err := LoadJSONL(path)
	if err != nil {
		t.Fatalf("LoadJSONL: %v", err)
	}
	if len(got) != 2 || !got[0].Timestamp.Equal(base) || !got[1].Timestamp.Equal(base.Add(time.Second)) {
		t.Fatalf("samples were not sorted by timestamp: %+v", got)
	}
	if got[1].Labels["run"] != "r1" {
		t.Errorf("labels were not preserved: %+v", got[1].Labels)
	}
}

func TestWriteJSONLIsDeterministicAndDoesNotMutateInput(t *testing.T) {
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	early := fixedSample("b", base)
	late := fixedSample("a", base.Add(time.Second))
	input := []Sample{late, early}

	dir := t.TempDir()
	shuffledPath := filepath.Join(dir, "shuffled.jsonl")
	sortedPath := filepath.Join(dir, "sorted.jsonl")
	if err := WriteJSONL(shuffledPath, input); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSONL(sortedPath, []Sample{early, late}); err != nil {
		t.Fatal(err)
	}
	shuffled, err := os.ReadFile(shuffledPath)
	if err != nil {
		t.Fatal(err)
	}
	sorted, err := os.ReadFile(sortedPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(shuffled) != string(sorted) {
		t.Errorf("write order changed the artifact:\n%s\n%s", shuffled, sorted)
	}
	if input[0].Source != "a" || input[1].Source != "b" {
		t.Errorf("WriteJSONL mutated the input slice: %+v", input)
	}
}

func TestLoadJSONLAcceptsArrayAndSkipsComments(t *testing.T) {
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	earlyJSON, err := json.Marshal(fixedSample("early", base))
	if err != nil {
		t.Fatal(err)
	}
	lateJSON, err := json.Marshal(fixedSample("late", base.Add(time.Second)))
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		body string
	}{
		{"JSON array", "[" + string(lateJSON) + "," + string(earlyJSON) + "]"},
		{"JSONL with comments", "# header\n\n" + string(lateJSON) + "\n" + string(earlyJSON) + "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "samples.json")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}

			got, err := LoadJSONL(path)

			if err != nil {
				t.Fatalf("LoadJSONL: %v", err)
			}
			if len(got) != 2 || got[0].Source != "early" || got[1].Source != "late" {
				t.Errorf("samples = %+v, want early then late", got)
			}
		})
	}
}

func TestLoadJSONLRejectsMalformedInput(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content *string
		want    string
	}{
		{name: "missing file", want: "read"},
		{name: "empty file", content: stringPtr("\n"), want: "empty"},
		{name: "only comments", content: stringPtr("# none\n"), want: "no samples"},
		{name: "malformed array", content: stringPtr(`[{"timestamp":`), want: "parse samples"},
		{name: "malformed line", content: stringPtr("not json\n"), want: "line 1"},
		{name: "missing timestamp", content: stringPtr(`{"source":"x"}` + "\n"), want: "no timestamp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "samples.json")
			if tc.content != nil {
				if err := os.WriteFile(path, []byte(*tc.content), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			got, err := LoadJSONL(path)

			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("LoadJSONL = (%v, %v), want error containing %q", got, err, tc.want)
			}
			if got != nil {
				t.Errorf("LoadJSONL returned samples %+v alongside error", got)
			}
		})
	}
}

func TestWriteMarkdownRendersSortedDeterministicReport(t *testing.T) {
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	early := fixedSample(SourceRuntime, base)
	early.Load = LoadAverage{One: 0.5, Available: true}
	early.CPU = CPUStats{UtilizationPct: 10, IOWaitPct: 1, Available: true}
	early.Mem = MemoryStats{UsedPct: 40, Available: true}
	early.PSI.Memory = &Pressure{Some10: 0.25}
	early.Runtime.Goroutines = 12
	early.Net = NetStats{
		Available: true,
		Aggregate: InterfaceCounters{RxErrors: 1},
	}
	late := fixedSample(SourceLinuxProc, base.Add(time.Second))
	late.Runtime.Goroutines = 15
	late.Net = NetStats{
		Available: true,
		Aggregate: InterfaceCounters{RxErrors: 2, RxDrops: 1, TxErrors: 1},
	}

	report := Report{
		Title:       "Incident review",
		GeneratedAt: base.Add(2 * time.Second),
		Capabilities: Capabilities{
			OS:            "linux",
			Arch:          "amd64",
			Source:        SourceLinuxProc,
			ProcAvailable: true,
			Notes:         []string{"aggregate counters only"},
		},
		Options: Options{Interval: time.Second, Duration: 0, MaxSamples: 3},
		Window:  DefaultCorrelateWindow,
		Samples: []Sample{late, early},
		Signals: []Signal{
			{Timestamp: base.Add(time.Second), RPS: 20, P99Ms: 150, ErrorRate: 0.02, Step: "load"},
			{Timestamp: base, RPS: 18, P99Ms: 90, ErrorRate: 0.01},
		},
		Indicators: []Indicator{
			{ID: "info-1", Severity: SeverityInfo, Confidence: ConfidenceLow, Title: "Info finding", Explanation: "info explanation", Evidence: []string{"", "info evidence"}},
			{ID: "warn-2", Severity: SeverityWarning, Confidence: ConfidenceMedium, Title: "Warning finding", Explanation: "warning explanation", Evidence: []string{"warning evidence"}},
			{ID: "crit-3", Severity: SeverityCritical, Confidence: ConfidenceHigh, Title: "Critical finding", Explanation: "critical explanation", Evidence: []string{"critical evidence"}},
		},
	}
	path := filepath.Join(t.TempDir(), "report.md")

	if err := WriteMarkdown(path, report); err != nil {
		t.Fatalf("WriteMarkdown: %v", err)
	}
	firstRun, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(firstRun)

	for _, want := range []string{
		"# Incident review\n\n",
		"_Generated 2026-01-02T03:04:07Z",
		"| Platform | linux/amd64 |",
		"| /proc available | yes |",
		"| BTF (/sys/kernel/btf/vmlinux) | no |",
		"- aggregate counters only",
		"| Duration | not set (bounded by max samples) |",
		"| Max samples | 3 |",
		"| Correlation window | 5s |",
		"| First sample | 2026-01-02T03:04:05Z |",
		"| Last sample | 2026-01-02T03:04:06Z |",
		"### 1. critical / high confidence — Critical finding",
		"### 2. warning / medium confidence — Warning finding",
		"### 3. info / low confidence — Info finding",
		"- info evidence",
		"| Peak p99 | 150.0 ms |",
		"| 03:04:05.000 | 0.50 | 10.0 | 1.0 | 40.0 | 0.25 | - | 12 | 90.0 |",
		"| 03:04:06.000 | - | - | - | - | - | 3 | 15 | 150.0 |",
		"No eBPF program, kernel module, or privileged call is involved",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("report does not contain %q", want)
		}
	}
	if strings.Index(text, "Critical finding") > strings.Index(text, "Warning finding") ||
		strings.Index(text, "Warning finding") > strings.Index(text, "Info finding") {
		t.Error("indicators were not sorted most-severe-first")
	}
	if strings.Index(text, "| 03:04:05.000 |") > strings.Index(text, "| 03:04:06.000 |") {
		t.Error("samples were not sorted by timestamp")
	}
	if strings.Contains(text, "- \n") {
		t.Error("empty evidence line was rendered")
	}

	if err := WriteMarkdown(path, report); err != nil {
		t.Fatalf("second WriteMarkdown: %v", err)
	}
	secondRun, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(secondRun) != string(firstRun) {
		t.Error("WriteMarkdown is not deterministic for the same report")
	}
}

func TestWriteMarkdownUsesDocumentedDefaultsAndEmptySections(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.md")

	if err := WriteMarkdown(path, Report{}); err != nil {
		t.Fatalf("WriteMarkdown: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{
		"# Sift Host X-Ray Report",
		"| Evidence source | - |",
		"| Interval | 0s |",
		"| Correlation window | 5s |",
		"No indicator met the conservative evidence threshold",
		"No external signal file was supplied",
		"No samples were collected.",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("report does not contain %q", want)
		}
	}
	if !strings.Contains(text, "_Generated ") {
		t.Error("generated timestamp was not filled")
	}
}

func TestWriteMarkdownSubsamplesLongTimeline(t *testing.T) {
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	samples := make([]Sample, 0, maxTimelineRows+1)
	for i := 0; i <= maxTimelineRows; i++ {
		samples = append(samples, fixedSample(SourceRuntime, base.Add(time.Duration(i)*time.Millisecond)))
	}
	path := filepath.Join(t.TempDir(), "report.md")

	if err := WriteMarkdown(path, Report{GeneratedAt: base, Samples: samples}); err != nil {
		t.Fatalf("WriteMarkdown: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "Showing every 2th sample of 301") {
		t.Error("long timeline notice is missing or incorrect")
	}
	if got := strings.Count(text, "| 03:04:05."); got != 151 {
		t.Errorf("timeline rows = %d, want 151 (every second sample)", got)
	}
	if !strings.Contains(text, "| 03:04:05.300 |") {
		t.Error("last sample was not included in the subsampled timeline")
	}
}

func TestWriteCapabilityRowReplacesBlankValues(t *testing.T) {
	for _, tc := range []struct{ name, value, want string }{
		{"empty", "", "| Label | - |\n"},
		{"whitespace", " \t ", "| Label | - |\n"},
		{"value", "yes", "| Label | yes |\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b strings.Builder
			writeCapabilityRow(&b, "Label", tc.value)
			if got := b.String(); got != tc.want {
				t.Errorf("row = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBoolWordDurationAndMaxSamplesLabels(t *testing.T) {
	if boolWord(true) != "yes" || boolWord(false) != "no" {
		t.Error("boolWord returned an unexpected value")
	}
	for _, tc := range []struct {
		name                string
		duration            time.Duration
		maxSamples          int
		wantDuration        string
		wantMaxSamplesLabel string
	}{
		{"explicit duration", 5 * time.Second, 3, "5s", "3"},
		{"max samples only", 0, 7, "not set (bounded by max samples)", "7"},
		{"no bound", 0, 0, "-", "derived from duration"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := durationLabel(tc.duration, tc.maxSamples); got != tc.wantDuration {
				t.Errorf("durationLabel = %q, want %q", got, tc.wantDuration)
			}
			if got := maxSamplesLabel(tc.maxSamples); got != tc.wantMaxSamplesLabel {
				t.Errorf("maxSamplesLabel = %q, want %q", got, tc.wantMaxSamplesLabel)
			}
		})
	}
}

func TestNetFaultDeltaHandlesMissingAndRegressingCounters(t *testing.T) {
	available := NetStats{Available: true, Aggregate: InterfaceCounters{RxErrors: 1}}
	increased := NetStats{Available: true, Aggregate: InterfaceCounters{RxErrors: 2, RxDrops: 1, TxErrors: 1}}
	regressed := NetStats{Available: true, Aggregate: InterfaceCounters{RxErrors: 1}}
	unavailable := NetStats{Available: false, Aggregate: InterfaceCounters{RxErrors: 99}}

	samples := []Sample{
		{Net: available},
		{Net: increased},
		{Net: increased},
		{Net: regressed},
		{Net: unavailable},
	}
	for _, tc := range []struct {
		name   string
		index  int
		want   uint64
		wantOK bool
	}{
		{"first sample has no predecessor", 0, 0, false},
		{"negative index", -1, 0, false},
		{"out of range", 5, 0, false},
		{"counter increase", 1, 3, true},
		{"counter unchanged", 2, 0, true},
		{"counter regression", 3, 0, false},
		{"unavailable current", 4, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := netFaultDelta(samples, tc.index)
			if got != tc.want || ok != tc.wantOK {
				t.Errorf("netFaultDelta(%d) = (%d, %v), want (%d, %v)", tc.index, got, ok, tc.want, tc.wantOK)
			}
		})
	}

	prevUnavailable := []Sample{{Net: unavailable}, {Net: increased}}
	if _, ok := netFaultDelta(prevUnavailable, 1); ok {
		t.Error("delta accepted a missing predecessor counter")
	}
}

func TestNearestSignalFindsClosestSignalInsideWindow(t *testing.T) {
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	signals := []Signal{
		{Timestamp: base, P99Ms: 90},
		{Timestamp: base.Add(10 * time.Second), P99Ms: 150},
	}
	for _, tc := range []struct {
		name      string
		signals   []Signal
		ts        time.Time
		window    time.Duration
		wantP99   float64
		wantFound bool
	}{
		{"no signals", nil, base, time.Second, 0, false},
		{"exact match", signals, base, time.Second, 90, true},
		{"nearest before", signals, base.Add(9 * time.Second), time.Second, 150, true},
		{"nearest after", signals, base.Add(2 * time.Second), 3 * time.Second, 90, true},
		{"outside window", signals, base.Add(5 * time.Second), time.Second, 0, false},
		{"equal distance prefers first candidate", signals, base.Add(5 * time.Second), 5 * time.Second, 150, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := nearestSignal(tc.signals, tc.ts, tc.window)
			if ok != tc.wantFound || got.P99Ms != tc.wantP99 {
				t.Errorf("nearestSignal = (%+v, %v), want P99 %v and found %v", got, ok, tc.wantP99, tc.wantFound)
			}
		})
	}
}

func TestSortedSamplesSortsByTimeThenSourceWithoutMutation(t *testing.T) {
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	input := []Sample{
		{Source: "b", Timestamp: base},
		{Source: "a", Timestamp: base.Add(time.Second)},
		{Source: "z", Timestamp: base},
		{Source: "a", Timestamp: base},
	}

	got := sortedSamples(input)

	want := []string{"a", "b", "z", "a"}
	for i, source := range want {
		if got[i].Source != source {
			t.Errorf("sample %d source = %q, want %q", i, got[i].Source, source)
		}
	}
	if input[0].Source != "b" {
		t.Errorf("sortedSamples mutated the input: %+v", input)
	}
}

func TestReadAndWriteArtifactValidatePaths(t *testing.T) {
	if _, err := readArtifact(""); err == nil {
		t.Error("readArtifact accepted an empty path")
	}
	if _, err := readArtifact(string(filepath.Separator)); err == nil {
		t.Error("readArtifact accepted the root path")
	}
	if err := writeArtifact("", []byte("x")); err == nil {
		t.Error("writeArtifact accepted an empty path")
	}
	if err := writeArtifact(string(filepath.Separator), []byte("x")); err == nil {
		t.Error("writeArtifact accepted the root path")
	}

	dir := filepath.Join(t.TempDir(), "nested")
	path := filepath.Join(dir, "artifact.txt")
	if err := writeArtifact(path, []byte("payload")); err != nil {
		t.Fatalf("writeArtifact: %v", err)
	}
	data, err := readArtifact(path)
	if err != nil {
		t.Fatalf("readArtifact: %v", err)
	}
	if string(data) != "payload" {
		t.Errorf("artifact = %q, want payload", data)
	}
}

func TestRawSignalToSignalValidationAndAliases(t *testing.T) {
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	ts := flexibleTime{Time: base}
	rps, p99, rate := 10.0, 120.0, 0.05
	for _, tc := range []struct {
		name    string
		raw     rawSignal
		want    Signal
		wantErr string
	}{
		{
			name: "timestamp alias and p99 alias",
			raw:  rawSignal{TS: ts, RPS: &rps, P99Alt: &p99, ErrorRate: &rate, Step: "s", Endpoint: "/e", Label: "l"},
			want: Signal{Timestamp: base, RPS: rps, P99Ms: p99, ErrorRate: rate, Step: "s", Endpoint: "/e", Label: "l"},
		},
		{
			name: "p99_ms wins over p99",
			raw:  rawSignal{Timestamp: ts, P99Ms: &p99, P99Alt: float64Ptr(999)},
			want: Signal{Timestamp: base, P99Ms: p99},
		},
		{name: "missing timestamp", raw: rawSignal{}, wantErr: "missing timestamp"},
		{name: "negative rps", raw: rawSignal{Timestamp: ts, RPS: float64Ptr(-1)}, wantErr: "must not be negative"},
		{name: "negative p99", raw: rawSignal{Timestamp: ts, P99Alt: float64Ptr(-1)}, wantErr: "must not be negative"},
		{name: "error rate above one", raw: rawSignal{Timestamp: ts, ErrorRate: float64Ptr(1.5)}, wantErr: "fraction between 0 and 1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.raw.toSignal(7)

			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) || !strings.Contains(err.Error(), "signal 7") {
					t.Fatalf("toSignal error = %v, want %q with index 7", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("toSignal: %v", err)
			}
			if !got.Timestamp.Equal(tc.want.Timestamp) || got.RPS != tc.want.RPS || got.P99Ms != tc.want.P99Ms || got.ErrorRate != tc.want.ErrorRate ||
				got.Step != tc.want.Step || got.Endpoint != tc.want.Endpoint || got.Label != tc.want.Label {
				t.Errorf("signal = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestFlexibleTimeUnmarshalJSON(t *testing.T) {
	want := time.Date(2026, 1, 2, 3, 4, 5, 123_000_000, time.UTC)
	for _, tc := range []struct {
		name    string
		input   string
		want    time.Time
		wantErr string
	}{
		{"RFC3339Nano", `"2026-01-02T03:04:05.123Z"`, want, ""},
		{"RFC3339", `"2026-01-02T03:04:05Z"`, want.Truncate(time.Second), ""},
		{"date and time with T", `"2026-01-02T03:04:05"`, want.Truncate(time.Second), ""},
		{"date and time with space", `"2026-01-02 03:04:05"`, want.Truncate(time.Second), ""},
		{"null", `null`, time.Time{}, ""},
		{"empty string", `""`, time.Time{}, ""},
		{"unrecognized string", `"02/01/2026"`, time.Time{}, "unrecognized timestamp"},
		{"zero number", `0`, time.Time{}, "invalid timestamp"},
		{"negative number", `-1`, time.Time{}, "invalid timestamp"},
		{"not a number", `"nan"`, time.Time{}, "unrecognized timestamp"},
		{"out of range", `9.3e18`, time.Time{}, "out of range"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got flexibleTime
			err := got.UnmarshalJSON([]byte(tc.input))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("UnmarshalJSON(%s) = %v, want error containing %q", tc.input, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalJSON(%s): %v", tc.input, err)
			}
			if !got.Equal(tc.want) {
				t.Errorf("time = %v, want %v", got.Time, tc.want)
			}
		})
	}
}

func stringPtr(s string) *string { return &s }

func float64Ptr(f float64) *float64 { return &f }
