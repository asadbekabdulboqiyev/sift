package report

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/config"
	"github.com/asadbekabdulboqiyev/sift/internal/metrics"
	"github.com/asadbekabdulboqiyev/sift/internal/shared"
)

// StepReport holds the measured statistics for one load-test step.
type StepReport struct {
	Name       string            `json:"name"`
	Requests   uint64            `json:"requests"`
	Errors     uint64            `json:"errors"`
	Status     map[int]uint64    `json:"status_codes"`
	ErrorTypes map[string]uint64 `json:"error_types"`
	Min        time.Duration     `json:"min"`
	Avg        time.Duration     `json:"avg"`
	Max        time.Duration     `json:"max"`
	P50        time.Duration     `json:"p50"`
	P95        time.Duration     `json:"p95"`
	P99        time.Duration     `json:"p99"`
}

// Report is the complete result of a load-test run.
type Report struct {
	Name          string                   `json:"name"`
	BaseURL       string                   `json:"base_url"`
	LoadProfile   string                   `json:"load_profile"`
	TargetRPS     int                      `json:"target_rps,omitempty"`
	StartedAt     time.Time                `json:"started_at"`
	EndedAt       time.Time                `json:"ended_at"`
	Duration      time.Duration            `json:"duration"`
	ActiveUsers   int64                    `json:"active_users"`
	TotalRequests uint64                   `json:"total_requests"`
	TotalErrors   uint64                   `json:"total_errors"`
	ErrorRatePct  float64                  `json:"error_rate_pct"`
	RPS           float64                  `json:"rps"`
	PreWarmTime   time.Duration            `json:"pre_warm_time,omitempty"`
	Status        map[int]uint64           `json:"status_codes"`
	Errors        map[string]uint64        `json:"errors"`
	Gate          bool                     `json:"gate"`
	Overall       StepReport               `json:"overall"`
	Steps         []StepReport             `json:"steps"`
	SLA           []SLAResult              `json:"sla,omitempty"`
	Timeline      []metrics.TimelineSample `json:"timeline,omitempty"`
	// ResourceEvidence holds optional, evidence-based resource monitoring data
	// (CPU/memory/network/connections/memory growth/server response time) with
	// explicit availability/insufficiency labeling. It is never fabricated and
	// must not be interpreted as measured load-test telemetry unless the source
	// states so. Omitted when unavailable.
	ResourceEvidence json.RawMessage `json:"resource_evidence,omitempty"`
}

// renderLatencyBars builds ASCII bar rows for key latency percentiles. Bar
// width scales logarithmically against p99 so heavy tails stay visible while
// fast percentiles do not vanish.
func renderLatencyBars(o StepReport) []string {
	points := []struct {
		label string
		value time.Duration
	}{
		{"p50", o.P50},
		{"p95", o.P95},
		{"p99", o.P99},
	}
	maxV := float64(o.P99)
	if maxV <= 0 {
		return nil
	}
	const maxBar = 34
	var out []string
	for _, pt := range points {
		v := float64(pt.value)
		width := int(math.Log1p(v/maxV*(math.E-1)) * maxBar)
		if width < 1 {
			width = 1
		}
		if width > maxBar {
			width = maxBar
		}
		bar := strings.Repeat("█", width) + strings.Repeat("░", maxBar-width)
		out = append(out, fmt.Sprintf("%-4s %-10s %s", pt.label, pt.value, bar))
	}
	return out
}

func fromStepStats(name string, s *metrics.StepStats) StepReport {
	snap := s.Latency.Snapshot()
	return StepReport{
		Name:       name,
		Requests:   snap.Count,
		Errors:     s.ErrorCount(),
		Status:     s.StatusCodes(),
		ErrorTypes: s.Errors(),
		Min:        snap.Min,
		Avg:        snap.Average,
		Max:        snap.Max,
		P50:        snap.Percentile(0.50),
		P95:        snap.Percentile(0.95),
		P99:        snap.Percentile(0.99),
	}
}

// Build constructs a Report from completed telemetry and scenario config.
//
// Timing integrity: Duration is the monotonic actual elapsed execution time
// captured by telemetry (high-resolution). StartedAt and EndedAt are recorded
// independently as wall-clock timestamps, and EndedAt is normalized to
// StartedAt+Duration so the reported duration always matches the actual elapsed
// execution time and remains internally consistent even when wall-clock and
// monotonic readings differ slightly.
func Build(t *metrics.Telemetry, scenario *config.Scenario) Report {
	reqs := t.TotalRequests()
	errs := t.TotalErrors()
	errPct := 0.0
	if reqs > 0 {
		errPct = float64(errs) / float64(reqs) * 100
	}
	duration := t.Elapsed()
	if duration < 0 {
		duration = 0
	}
	startedAt := t.Start
	endedAt := t.End
	if !startedAt.IsZero() {
		endedAt = startedAt.Add(duration)
	} else if endedAt.IsZero() {
		// Extremely defensive: preserve zero values if telemetry has none.
		endedAt = startedAt
	}
	r := Report{
		Name:          scenario.Name,
		BaseURL:       target(scenario),
		LoadProfile:   scenario.Profile.Type,
		TargetRPS:     scenario.Profile.TargetRPS,
		Gate:          scenario.Profile.Gate,
		StartedAt:     startedAt,
		EndedAt:       endedAt,
		Duration:      duration,
		ActiveUsers:   t.PeakUsers.Load(),
		TotalRequests: reqs,
		TotalErrors:   errs,
		ErrorRatePct:  errPct,
		RPS:           t.RPS(),
		PreWarmTime:   scenario.PreWarmTime,
		Status:        t.StatusCodes(),
		Errors:        t.Errors(),
		Overall:       fromStepStats("overall", t.Overall),
		Timeline:      t.Timeline.Snapshot(),
	}
	// AddStep appends under Telemetry's lock; take a snapshot so building a
	// report never races a concurrent step append (same rule as the /metrics
	// exporter).
	for _, s := range t.StepsSnapshot() {
		r.Steps = append(r.Steps, fromStepStats(s.Name, s))
	}
	r.SLA = EvaluateSLA(&r, scenario.SLA)
	return r
}

// ValidateTimestamps checks that StartedAt/EndedAt/Duration are consistent and
// that Duration represents non-negative actual elapsed execution time.
func (r Report) ValidateTimestamps() error {
	if r.Duration < 0 {
		return fmt.Errorf("duration must be non-negative, got %s", r.Duration)
	}
	if r.StartedAt.IsZero() || r.EndedAt.IsZero() {
		if r.Duration == 0 && r.StartedAt.IsZero() && r.EndedAt.IsZero() {
			return nil
		}
		return fmt.Errorf("started_at and ended_at must be set when duration is recorded")
	}
	if r.EndedAt.Before(r.StartedAt) {
		return fmt.Errorf("ended_at %s is before started_at %s", r.EndedAt.Format(time.RFC3339Nano), r.StartedAt.Format(time.RFC3339Nano))
	}
	expected := r.StartedAt.Add(r.Duration)
	delta := r.EndedAt.Sub(expected)
	if delta < 0 {
		delta = -delta
	}
	// Allow tiny representation/serialization drift; duration is the source of truth.
	const tolerance = 2 * time.Millisecond
	if delta > tolerance {
		return fmt.Errorf("timestamp inconsistency: ended_at-started_at=%s duration=%s (delta %s)", r.EndedAt.Sub(r.StartedAt), r.Duration, delta)
	}
	return nil
}

// Render writes a premium, colorized report to w.
// Colors are only used when w is a terminal (detected via isTerminal).
func (r Report) Render(w io.Writer) {
	c := isTerminal(w) // color enabled?
	rc := rateColor(r.ErrorRatePct)
	health, hColor := healthLabel(r.ErrorRatePct)

	sep := colorize(colorBold, c, "═══════════════════════════════════════════════════════════════════════════════════════")

	// ── Header ──────────────────────────────────────────────────────────
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, sep)
	title := colorize(colorBold, c, fmt.Sprintf("  LOAD TEST REPORT: %s", r.Name))
	_, _ = fmt.Fprintln(w, title)
	_, _ = fmt.Fprintln(w, sep)
	_, _ = fmt.Fprintln(w)

	// ── Target & Config ─────────────────────────────────────────────────
	_, _ = fmt.Fprintf(w, "  %s\n", colorize(colorCyan, c, fmt.Sprintf("Target:     %s", r.BaseURL)))
	if r.TargetRPS > 0 {
		_, _ = fmt.Fprintf(w, "  %s\n", colorize(colorCyan, c, fmt.Sprintf("Profile:    %s | Target RPS: %d | Actual RPS: %s", r.LoadProfile, r.TargetRPS, formatRPS(r.RPS))))
	} else {
		_, _ = fmt.Fprintf(w, "  %s\n", colorize(colorCyan, c, fmt.Sprintf("Profile:    %s | Peak users: %d", r.LoadProfile, r.ActiveUsers)))
	}
	_, _ = fmt.Fprintf(w, "  %s\n", colorize(colorCyan, c, fmt.Sprintf("Duration:   %s | Started: %s",
		r.Duration.Round(time.Millisecond), r.StartedAt.Format(time.RFC3339))))
	if r.PreWarmTime > 0 {
		_, _ = fmt.Fprintf(w, "  %s\n", colorize(colorCyan, c, fmt.Sprintf("Pre-warm:   %s", r.PreWarmTime.Round(time.Millisecond))))
	}
	_, _ = fmt.Fprintln(w)

	// ── Overall ─────────────────────────────────────────────────────────
	overall := r.Overall
	_, _ = fmt.Fprintln(w, colorize(colorBold, c, "  ┌──────────────────────────────────────────────────────────────┐"))
	_, _ = fmt.Fprintf(w, "  │  %-58s │\n", colorize(colorBold, c, "OVERALL RESULTS"))
	_, _ = fmt.Fprintln(w, colorize(colorBold, c, "  ├──────────────────────────────────────────────────────────────┤"))

	reqLine := fmt.Sprintf("  Requests: %s | Errors: %s | RPS: %s",
		formatCount(r.TotalRequests),
		colorize(rc, c, fmt.Sprintf("%s (%.2f%%)", formatCount(r.TotalErrors), r.ErrorRatePct)),
		formatRPS(r.RPS))
	_, _ = fmt.Fprintf(w, "  │  %-58s │\n", reqLine)

	latLine := fmt.Sprintf("  Latency:  avg=%s  p50=%s  p95=%s  p99=%s  max=%s",
		overall.Avg, overall.P50, overall.P95, overall.P99, overall.Max)
	_, _ = fmt.Fprintf(w, "  │  %-58s │\n", latLine)

	healthLine := fmt.Sprintf("  Server health: %s", colorize(hColor, c, health))
	_, _ = fmt.Fprintf(w, "  │  %-58s │\n", healthLine)

	_, _ = fmt.Fprintln(w, colorize(colorBold, c, "  └──────────────────────────────────────────────────────────────┘"))
	_, _ = fmt.Fprintln(w)

	// ── Latency distribution ────────────────────────────────────────────
	if overall.Requests > 0 {
		_, _ = fmt.Fprintln(w, colorize(colorBold, c, "  LATENCY DISTRIBUTION"))
		_, _ = fmt.Fprintln(w, colorize(colorBold, c, "  ──────────────────────────────────────────────────────────────"))
		for _, pt := range renderLatencyBars(overall) {
			_, _ = fmt.Fprintf(w, "    %s\n", pt)
		}
		_, _ = fmt.Fprintln(w)
	}
	// ── Steps table ─────────────────────────────────────────────────────
	if len(r.Steps) > 0 {
		_, _ = fmt.Fprintln(w, colorize(colorBold, c, "  STEP BREAKDOWN"))
		_, _ = fmt.Fprintln(w, colorize(colorBold, c, "  ──────────────────────────────────────────────────────────────"))

		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		header := colorize(colorBold, c, "STEP\tREQUESTS\tERRORS\tAVG\tP50\tP95\tP99\tMAX")
		_, _ = fmt.Fprintln(tw, header)
		for _, s := range r.Steps {
			stepErrPct := 0.0
			if s.Requests > 0 {
				stepErrPct = float64(s.Errors) / float64(s.Requests) * 100
			}
			stepRC := rateColor(stepErrPct)
			errDisplay := colorize(stepRC, c, fmt.Sprintf("%d", s.Errors))
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				s.Name, formatCount(s.Requests), errDisplay, s.Avg, s.P50, s.P95, s.P99, s.Max)
		}
		_ = tw.Flush()
		_, _ = fmt.Fprintln(w)
	}

	// ── Status codes ────────────────────────────────────────────────────
	if len(r.Status) > 0 {
		_, _ = fmt.Fprintln(w, colorize(colorBold, c, "  STATUS CODES"))
		_, _ = fmt.Fprintln(w, colorize(colorBold, c, "  ──────────────────────────────────────────────────────────────"))
		for _, code := range metrics.SortedStatusCodes(r.Status) {
			sc := statusColor(code)
			label := colorize(sc, c, fmt.Sprintf("%d", code))
			_, _ = fmt.Fprintf(w, "    %s  %s\n", label, formatCount(r.Status[code]))
		}
		_, _ = fmt.Fprintln(w)
	}

	// ── Errors ──────────────────────────────────────────────────────────
	if len(r.Errors) > 0 {
		_, _ = fmt.Fprintln(w, colorize(colorBold, c, "  ERRORS (top first)"))
		_, _ = fmt.Fprintln(w, colorize(colorBold, c, "  ──────────────────────────────────────────────────────────────"))
		for _, es := range metrics.TopErrors(r.Errors, 0) {
			share := 0.0
			if r.TotalErrors > 0 {
				share = float64(es.Count) / float64(r.TotalErrors) * 100
			}
			_, _ = fmt.Fprintf(w, "    %-18s %10s  %5.1f%%\n",
				colorize(colorRed, c, es.Name), formatCount(es.Count), share)
		}
		_, _ = fmt.Fprintln(w)
	}

	// ── SLA gate ────────────────────────────────────────────────────────
	if len(r.SLA) > 0 {
		_, _ = fmt.Fprintln(w, colorize(colorBold, c, "  SLA GATE"))
		_, _ = fmt.Fprintln(w, colorize(colorBold, c, "  ──────────────────────────────────────────────────────────────"))
		for _, res := range r.SLA {
			badge := colorize(colorGreen, c, "PASS")
			if !res.Pass {
				badge = colorize(colorRed, true, "FAIL")
			}
			_, _ = fmt.Fprintf(w, "    %s  %-14s target %-12s actual %s\n", badge, res.Metric, res.Target, res.Actual)
		}
		_, _ = fmt.Fprintln(w)
	}

	// ── Summary ─────────────────────────────────────────────────────────
	_, _ = fmt.Fprintln(w, colorize(colorBold, c, "  SUMMARY"))
	_, _ = fmt.Fprintln(w, colorize(colorBold, c, "  ──────────────────────────────────────────────────────────────"))
	_, _ = fmt.Fprintf(w, "    Total requests:  %s\n", formatCount(r.TotalRequests))
	_, _ = fmt.Fprintf(w, "    Total errors:    %s (%.2f%%)\n", formatCount(r.TotalErrors), r.ErrorRatePct)
	_, _ = fmt.Fprintf(w, "    Requests/sec:    %s\n", formatRPS(r.RPS))
	_, _ = fmt.Fprintf(w, "    Latency range:   %s — %s\n", overall.Min, overall.Max)
	_, _ = fmt.Fprintf(w, "    Duration:        %s\n", r.Duration.Round(time.Millisecond))
	if r.Gate {
		_, _ = fmt.Fprintln(w, colorize(colorYellow, c, "    Mode:            simultaneous burst (race window)"))
	}
	if len(r.ResourceEvidence) > 0 && string(r.ResourceEvidence) != "null" {
		_, _ = fmt.Fprintf(w, "    Resource evidence: attached (explicit; unavailable metrics labeled)\n")
	}
	_, _ = fmt.Fprintln(w)

	_, _ = fmt.Fprintln(w, sep)
	verdict := colorize(hColor, c, fmt.Sprintf("  VERDICT: %s", health))
	if len(r.SLA) > 0 {
		if SLAPassed(r.SLA) {
			verdict += colorize(colorGreen, c, " | SLA PASSED")
		} else {
			verdict += colorize(colorRed, true, " | SLA FAILED")
		}
	}
	_, _ = fmt.Fprintln(w, verdict)
	_, _ = fmt.Fprintln(w, sep)
	_, _ = fmt.Fprintln(w)
}

// atomicWriteFile keeps the package-local name used by the other report
// writers (including pdf.go). The durable write itself is centralized in
// shared.Write. Saved reports are archived artifacts, so the directory is
// synced: a crash must not lose the rename and leave a half-written report.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	return shared.Write(path, data, perm, shared.WithDirSync(true))
}

// SaveJSON writes the report as indented JSON and returns the file path.
func (r Report) SaveJSON(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	path := uniquePath(dir, reportFilename(r.Name, "json"))
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	if err := atomicWriteFile(path, data, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// SaveTXT writes the rendered text report and returns the file path.
func (r Report) SaveTXT(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	path := uniquePath(dir, reportFilename(r.Name, "txt"))
	var sb strings.Builder
	r.Render(&sb)
	if err := atomicWriteFile(path, []byte(sb.String()), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// SaveCSV writes the per-second timeline as CSV for external analysis
// (spreadsheets, Grafana annotations, Python notebooks).
func (r Report) SaveCSV(dir string) (string, error) {
	if len(r.Timeline) == 0 {
		return "", nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	path := uniquePath(dir, reportFilename(r.Name, "csv"))
	var sb strings.Builder
	sb.WriteString("second,requests_total,requests_delta,errors_total,errors_delta,active_users\n")
	var prevReq, prevErr uint64
	for _, s := range r.Timeline {
		fmt.Fprintf(&sb, "%d,%d,%d,%d,%d,%d\n",
			s.Second, s.Requests, s.Requests-prevReq, s.Errors, s.Errors-prevErr, s.ActiveUsers)
		prevReq = s.Requests
		prevErr = s.Errors
	}
	if err := atomicWriteFile(path, []byte(sb.String()), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// LoadReport reads a previously saved JSON report (used by --compare).
func LoadReport(path string) (*Report, error) {
	data, err := os.ReadFile(filepath.Clean(path)) // #nosec G304 -- path is an operator-selected report file
	if err != nil {
		return nil, err
	}
	r := &Report{}
	if err := json.Unmarshal(data, r); err != nil {
		return nil, fmt.Errorf("parse baseline %s: %w", path, err)
	}
	return r, nil
}

// msDuration renders milliseconds as a Duration string.
func msDuration(ms float64) time.Duration {
	return time.Duration(ms * float64(time.Millisecond)).Round(time.Millisecond)
}

func uniquePath(dir, filename string) string {
	path := filepath.Join(dir, filename)
	for i := 1; ; i++ {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return path
		}
		ext := filepath.Ext(filename)
		base := strings.TrimSuffix(filename, ext)
		path = filepath.Join(dir, fmt.Sprintf("%s-%d%s", base, i, ext))
	}
}

func target(scenario *config.Scenario) string {
	if scenario.BaseURL != "" {
		return scenario.BaseURL
	}
	if len(scenario.Steps) > 0 {
		return scenario.Steps[0].URL
	}
	return "n/a"
}

func reportFilename(name, ext string) string {
	safe := sanitizeFilename(name)
	if safe == "" {
		safe = "report"
	}
	if len(safe) > 64 {
		safe = safe[:64]
	}
	return fmt.Sprintf("%s_%s.%s", safe, time.Now().Format("20060102-150405"), ext)
}

var filenameSanitizer = strings.NewReplacer(
	"..", "_",
	"/", "_",
	"\\", "_",
	":", "_",
	" ", "_",
	"%", "_",
	"~", "_",
	"*", "_",
	"?", "_",
	"'", "_",
	`"`, "_",
	"<", "_",
	">", "_",
	"&", "_",
	"|", "_",
	"\x00", "_",
	"\n", "_",
	"\r", "_",
	"\t", "_",
)

func sanitizeFilename(name string) string {
	cleaned := filenameSanitizer.Replace(name)
	var b strings.Builder
	for _, r := range cleaned {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
