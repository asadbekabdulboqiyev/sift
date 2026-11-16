package twin

// report.go — deterministic, human- and machine-readable artifacts.
//
// Every artifact is written under the caller's directory with a fixed name, so
// a pipeline can address it without globbing: twin-model.json,
// simulation-<scenario>.json and simulation-report.md. JSON is produced from
// structs only (no maps in the serialized core) and scenarios are sorted by
// name, so the same model and results always produce the same bytes.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Artifact file names.
const (
	// ModelArtifactName is the fitted model written by `twin fit`.
	ModelArtifactName = "twin-model.json"
	// MarkdownArtifactName is the human-readable summary.
	MarkdownArtifactName = "simulation-report.md"
	// simulationPrefix precedes each per-scenario result file.
	simulationPrefix = "simulation-"
)

// ScenarioArtifact records where one scenario's result was written.
type ScenarioArtifact struct {
	Scenario string `json:"scenario"`
	Path     string `json:"path"`
}

// ArtifactPaths lists everything WriteArtifacts produced, in deterministic
// order. It is JSON-serializable so a wrapper tool can consume it.
type ArtifactPaths struct {
	ModelPath       string             `json:"model_path"`
	SimulationPaths []ScenarioArtifact `json:"simulation_paths"`
	ReportPath      string             `json:"report_path"`
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if err := tmp.Chmod(perm); err != nil {
		cleanup()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if df, err := os.Open(dir); err == nil {
		_ = df.Sync()
		_ = df.Close()
	}
	return os.Chmod(path, perm)
}

// WriteModel writes only twin-model.json in dir. It normalizes/validates the
// model and writes the current schema version.
func WriteModel(dir string, m Model) (string, error) {
	if strings.TrimSpace(dir) == "" {
		return "", fmt.Errorf("twin: output directory is required")
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", fmt.Errorf("twin: create output directory %s: %w", dir, err)
	}
	return SaveModel(filepath.Join(dir, ModelArtifactName), m)
}

// SaveModel writes a normalized/validated model to an explicit file path.
// This supports in-place updates (e.g. persisting validation status) while
// preserving schema normalization/validation semantics.
func SaveModel(path string, m Model) (string, error) {
	nm, err := ValidateAndNormalize(m)
	if err != nil {
		return "", fmt.Errorf("twin: refusing to write an invalid model: %w", err)
	}
	m = nm
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("twin: model path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return "", fmt.Errorf("twin: create model directory for %s: %w", path, err)
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", fmt.Errorf("twin: encode model: %w", err)
	}
	if err := atomicWriteFile(path, append(data, '\n'), 0o600); err != nil {
		return "", fmt.Errorf("twin: write %s: %w", path, err)
	}
	return path, nil
}

// WriteArtifacts writes the model, one result file per scenario and the
// Markdown report, and returns their paths. Scenarios are written in sorted
// order so the returned slice is stable.
func WriteArtifacts(dir string, m Model, results map[string]Result) (ArtifactPaths, error) {
	if strings.TrimSpace(dir) == "" {
		return ArtifactPaths{}, fmt.Errorf("twin: output directory is required")
	}

	names := make([]string, 0, len(results))
	seenFiles := make(map[string]string, len(results))
	for name := range results {
		if strings.TrimSpace(name) == "" {
			return ArtifactPaths{}, fmt.Errorf("twin: result map contains an empty scenario name")
		}
		res := results[name]
		if res.SchemaVersion != SchemaVersion && res.SchemaVersion != SchemaVersionV1 {
			return ArtifactPaths{}, fmt.Errorf("twin: scenario %q result has schema %q (want %q or %q)", name, res.SchemaVersion, SchemaVersion, SchemaVersionV1)
		}
		if res.Scenario.Name != name {
			return ArtifactPaths{}, fmt.Errorf("twin: result keyed %q carries scenario name %q", name, res.Scenario.Name)
		}
		file := simulationFilename(name)
		if other, ok := seenFiles[file]; ok {
			return ArtifactPaths{}, fmt.Errorf("twin: scenarios %q and %q map to the same artifact file %q", other, name, file)
		}
		seenFiles[file] = name
		names = append(names, name)
	}
	sort.Strings(names)

	modelPath, err := WriteModel(dir, m)
	if err != nil {
		return ArtifactPaths{}, err
	}

	paths := ArtifactPaths{ModelPath: modelPath}
	for _, name := range names {
		res := results[name]
		// Normalize written schema to current version for reproducibility.
		res.SchemaVersion = SchemaVersion
		path := filepath.Join(dir, simulationFilename(name))
		data, mErr := json.MarshalIndent(res, "", "  ")
		if mErr != nil {
			return ArtifactPaths{}, fmt.Errorf("twin: encode scenario %q: %w", name, mErr)
		}
		if wErr := atomicWriteFile(path, append(data, '\n'), 0o600); wErr != nil {
			return ArtifactPaths{}, fmt.Errorf("twin: write %s: %w", path, wErr)
		}
		paths.SimulationPaths = append(paths.SimulationPaths, ScenarioArtifact{Scenario: name, Path: path})
	}

	reportPath := filepath.Join(dir, MarkdownArtifactName)
	md := renderMarkdown(m, names, results)
	if err := atomicWriteFile(reportPath, []byte(md), 0o600); err != nil {
		return ArtifactPaths{}, fmt.Errorf("twin: write %s: %w", reportPath, err)
	}
	paths.ReportPath = reportPath
	return paths, nil
}

// LoadModel reads a model artifact and normalizes legacy schemas in-memory.
func LoadModel(path string) (Model, error) {
	clean := filepath.Clean(path)
	data, err := os.ReadFile(clean) // #nosec G304 -- operator-selected model artifact
	if err != nil {
		return Model{}, fmt.Errorf("twin: read model %s: %w", clean, err)
	}
	var m Model
	if err := json.Unmarshal(data, &m); err != nil {
		return Model{}, fmt.Errorf("twin: parse model %s: %w", clean, err)
	}
	nm, err := ValidateAndNormalize(m)
	if err != nil {
		return Model{}, fmt.Errorf("twin: model %s is not usable: %w", clean, err)
	}
	return nm, nil
}

// LoadResult parses a simulation artifact.
func LoadResult(path string) (Result, error) {
	clean := filepath.Clean(path)
	data, err := os.ReadFile(clean) // #nosec G304 -- operator-selected simulation artifact
	if err != nil {
		return Result{}, fmt.Errorf("twin: read result %s: %w", clean, err)
	}
	var r Result
	if err := json.Unmarshal(data, &r); err != nil {
		return Result{}, fmt.Errorf("twin: parse result %s: %w", clean, err)
	}
	if r.SchemaVersion != SchemaVersion && r.SchemaVersion != SchemaVersionV1 {
		return Result{}, fmt.Errorf("twin: result %s has schema %q (want %q or %q)", clean, r.SchemaVersion, SchemaVersion, SchemaVersionV1)
	}
	r.SchemaVersion = SchemaVersion
	return r, nil
}

// simulationFilename derives a filesystem-safe name from a scenario name.
// Anything outside [a-z0-9_-] becomes '-', runs of '-' collapse, and an empty
// result falls back to "scenario".
func simulationFilename(name string) string {
	var b strings.Builder
	lastDash := false
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash && b.Len() > 0 {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		out = "scenario"
	}
	return simulationPrefix + out + ".json"
}

// renderMarkdown produces the human-readable artifact. It is intentionally
// plain: the audience is an engineer pasting it into a review, and every claim
// carries its uncertainty.
func renderMarkdown(m Model, names []string, results map[string]Result) string {
	var b strings.Builder

	b.WriteString("# Digital twin capacity simulation\n\n")
	b.WriteString("> **This is a model-based estimate, not a measurement and not a guarantee.**\n")
	b.WriteString("> The twin extrapolates from a single observed load-test operating point. It assumes\n")
	b.WriteString("> steady state, one bottleneck, no autoscaling, no cache warm-up and a traffic mix\n")
	b.WriteString("> matching the source run. Re-measure before making an irreversible capacity decision.\n\n")

	b.WriteString("## Fitted model\n\n")
	fmt.Fprintf(&b, "| Field | Value |\n|---|---|\n")
	fmt.Fprintf(&b, "| Schema | `%s` |\n", m.SchemaVersion)
	if m.ModelInfo != nil {
		fmt.Fprintf(&b, "| Model version | %s (`%s`) |\n", markdownCell(m.ModelInfo.Version, "n/a"), markdownCell(m.ModelInfo.Algorithm, "n/a"))
	}
	fmt.Fprintf(&b, "| Source report | %s |\n", markdownCell(m.Source.ReportName, "n/a"))
	fmt.Fprintf(&b, "| Target | %s |\n", markdownCell(m.Source.TargetURL, "n/a"))
	fmt.Fprintf(&b, "| Load profile | %s |\n", markdownCell(m.Source.LoadProfile, "n/a"))
	fmt.Fprintf(&b, "| Run duration | %s |\n", formatSeconds(m.Source.DurationSeconds))
	fmt.Fprintf(&b, "| Fitted at | %s |\n", formatTime(m.Calibration.FittedAt))
	fmt.Fprintf(&b, "| Observed throughput | %.2f rps |\n", m.Workload.RPS)
	fmt.Fprintf(&b, "| Observed concurrency (Little's law) | %.2f |\n", m.Workload.Concurrency)
	fmt.Fprintf(&b, "| Observed error rate | %.3f%% |\n", m.Workload.ErrorRatePct)
	fmt.Fprintf(&b, "| Baseline latency | p50 %.2f ms / p95 %.2f ms / p99 %.2f ms |\n", m.Curve.Baseline.P50MS, m.Curve.Baseline.P95MS, m.Curve.Baseline.P99MS)
	fmt.Fprintf(&b, "| Estimated capacity | %.2f rps (%.2f - %.2f rps, +/-%.1f%%) |\n", m.Curve.CapacityRPS, m.Curve.CapacityLowRPS, m.Curve.CapacityHighRPS, m.Curve.CapacityRelativeUncertainty*100)
	if m.Capacity != nil {
		fmt.Fprintf(&b, "| Observed capacity | %.2f rps (never treated as maximum) |\n", m.Capacity.ObservedRPS)
		if m.Capacity.Status == CapacityInsufficient || m.Capacity.SustainableRPS == nil {
			fmt.Fprintf(&b, "| Sustainable capacity | INSUFFICIENT_DATA |\n")
		} else {
			s := *m.Capacity.SustainableRPS
			if m.Capacity.SustainableInterval != nil {
				fmt.Fprintf(&b, "| Sustainable capacity | %.2f rps [%.2f, %.2f] (%s, %s) |\n", s, m.Capacity.SustainableInterval.Low, m.Capacity.SustainableInterval.High, m.Capacity.Status, m.Capacity.SustainableInterval.Method)
			} else {
				fmt.Fprintf(&b, "| Sustainable capacity | %.2f rps (%s) |\n", s, m.Capacity.Status)
			}
		}
	}
	fmt.Fprintf(&b, "| Reference utilisation | %.3f |\n", m.Curve.ReferenceUtilization)
	if m.ConfidenceV2 != nil {
		fmt.Fprintf(&b, "| Confidence | %s %.1f/100 (sufficient=%t, data_quality=%s) |\n", m.ConfidenceV2.Level, m.ConfidenceV2.Score, m.ConfidenceV2.Sufficient, m.ConfidenceV2.DataQuality)
	} else {
		fmt.Fprintf(&b, "| Confidence | %s |\n", m.Confidence)
	}
	b.WriteString("\n")

	if m.ConfidenceV2 != nil {
		b.WriteString("### Confidence (evidence-based)\n\n")
		fmt.Fprintf(&b, "%s\n\n", m.ConfidenceV2.Summary)
		if len(m.ConfidenceV2.Factors) > 0 {
			b.WriteString("| Factor | Score | Weight | Status | Evidence | Uncertainty/Missing |\n|---|---:|---:|---|---|---|\n")
			for _, f := range m.ConfidenceV2.Factors {
				fmt.Fprintf(&b, "| %s | %.1f | %.2f | %s | %s | %s |\n", markdownCell(f.Name, ""), f.Score, f.Weight, markdownCell(f.Status, ""), markdownCell(f.Evidence, ""), markdownCell(ternaryStr(f.Uncertainty != "", f.Uncertainty, f.Impact), ""))
			}
			b.WriteString("\n")
		}
		if len(m.ConfidenceV2.MissingData) > 0 {
			b.WriteString("**Missing data (not measured):** " + strings.Join(m.ConfidenceV2.MissingData, ", ") + "\n\n")
		}
	}
	if m.Capacity != nil {
		b.WriteString("### Capacity assessment\n\n")
		fmt.Fprintf(&b, "- Observed RPS: **%.2f** (never treated as maximum capacity)\n", m.Capacity.ObservedRPS)
		if m.Capacity.Status == CapacityInsufficient || m.Capacity.SustainableRPS == nil {
			b.WriteString("- Sustainable capacity: **INSUFFICIENT_DATA**\n")
		} else {
			fmt.Fprintf(&b, "- Sustainable capacity (estimate): **%.2f rps**", *m.Capacity.SustainableRPS)
			if m.Capacity.SustainableInterval != nil {
				fmt.Fprintf(&b, " [%.2f, %.2f]", m.Capacity.SustainableInterval.Low, m.Capacity.SustainableInterval.High)
			}
			b.WriteString("\n")
		}
		if m.Capacity.Uncertainty != "" {
			fmt.Fprintf(&b, "- Uncertainty: %s\n", m.Capacity.Uncertainty)
		}
		if len(m.Capacity.DegradationSignals) > 0 {
			b.WriteString("- Degradation/saturation signals: " + strings.Join(m.Capacity.DegradationSignals, "; ") + "\n")
		}
		for _, n := range m.Capacity.Notes {
			fmt.Fprintf(&b, "- %s\n", n)
		}
		b.WriteString("\n")
	}

	b.WriteString("### How capacity was derived\n\n")
	b.WriteString("Capacity uses an M/M/1 tail approximation anchored to the measured operating point, with uncertainty bounds.\n")
	b.WriteString("Sustainable capacity is an evidence-based estimate (not a guarantee) that may account for degradation/error/saturation signals and may be `INSUFFICIENT_DATA`.\n")
	b.WriteString("Observed throughput is never treated as maximum capacity.\n\n")

	if len(m.Calibration.Notes) > 0 {
		b.WriteString("### Calibration notes\n\n")
		for _, note := range m.Calibration.Notes {
			fmt.Fprintf(&b, "- %s\n", note)
		}
		b.WriteString("\n")
	}
	if m.ResourceEvidence != nil {
		b.WriteString("### Resource monitoring evidence (optional)\n\n")
		fmt.Fprintf(&b, "- Source: `%s`\n", markdownCell(m.ResourceEvidence.Source, "unspecified"))
		fmt.Fprintf(&b, "- Evidence available: `%t`\n", m.ResourceEvidence.Available)
		if len(m.ResourceEvidence.MetricsDetail) > 0 {
			keys := make([]string, 0, len(m.ResourceEvidence.MetricsDetail))
			for k := range m.ResourceEvidence.MetricsDetail {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			b.WriteString("\n| Metric | Status | Value | Unit | Source | Reason |\n|---|---|---:|---|---|---|\n")
			for _, k := range keys {
				d := m.ResourceEvidence.MetricsDetail[k]
				val := "n/a"
				if d.Value != nil {
					val = fmt.Sprintf("%.4g", *d.Value)
				}
				reason := d.Reason
				if reason == "" && len(d.Notes) > 0 {
					reason = strings.Join(d.Notes, "; ")
				}
				fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n", markdownCell(d.Name, k), markdownCell(d.Status, ""), val, markdownCell(d.Unit, ""), markdownCell(d.Source, ""), markdownCell(reason, ""))
			}
		} else {
			if len(m.ResourceEvidence.Metrics) > 0 {
				fmt.Fprintf(&b, "- Available metrics: `%s`\n", strings.Join(m.ResourceEvidence.Metrics, ", "))
			}
			if len(m.ResourceEvidence.Missing) > 0 {
				fmt.Fprintf(&b, "- Missing/unavailable/insufficient: `%s`\n", strings.Join(m.ResourceEvidence.Missing, ", "))
			}
		}
		if len(m.ResourceEvidence.Notes) > 0 {
			b.WriteString("- Notes: " + markdownCell(strings.Join(m.ResourceEvidence.Notes, " | "), "") + "\n")
		}
		b.WriteString("\n> Resource evidence is reported only when provided/derivable; unavailable metrics are explicitly labeled and never fabricated.\n\n")
	}

	b.WriteString("## Scenarios\n\n")
	if len(names) == 0 {
		b.WriteString("No scenarios were simulated.\n")
	} else {
		b.WriteString("| Scenario | Loop | Target | p99 median | p99 p95 | Breach probability | Saturation | Risk |\n")
		b.WriteString("|---|---|---|---|---|---|---|---|\n")
		for _, name := range names {
			res := results[name]
			fmt.Fprintf(&b, "| %s | %s | %s | %.2f ms | %.2f ms | %.1f%% | %s | %s |\n",
				markdownCell(name, "n/a"),
				res.Scenario.Mode,
				scenarioTarget(res.Scenario),
				res.Summary.P99MS.P50,
				res.Summary.P99MS.P95,
				res.Summary.SLAProbabilityBreach*100,
				formatSaturation(res.Summary),
				res.Summary.RiskLevel,
			)
		}
		b.WriteString("\n")

		for _, name := range names {
			renderScenario(&b, results[name])
		}
	}

	b.WriteString("## Interpretation\n\n")
	b.WriteString("- `p99 median` is the median predicted p99 across Monte Carlo draws; `p99 p95` shows how bad a bad draw gets.\n")
	b.WriteString("- `Breach probability` is the share of draws in which the p99 objective, the error-rate objective, or both were exceeded.\n")
	b.WriteString("- Risk vocabulary: **low** is below 5% breach probability, **elevated** is 5-50%, **high** is 50% or more.\n")
	b.WriteString("- A low risk level is not a pass certificate: it quantifies model uncertainty, not the absence of unmodelled failure modes.\n")
	b.WriteString("- Closed-loop scenarios solve for throughput from the user count, so adding users past capacity adds latency, not throughput.\n")
	b.WriteString("\n")

	return b.String()
}

func renderScenario(b *strings.Builder, res Result) {
	fmt.Fprintf(b, "### %s\n\n", res.Scenario.Name)
	fmt.Fprintf(b, "- Load: %s over %s (ramp %s), %d iterations, seed %d.\n",
		scenarioTarget(res.Scenario), formatSeconds(res.Scenario.DurationSeconds), formatSeconds(res.Scenario.RampSeconds), res.Scenario.Iterations, res.Scenario.Seed)
	if res.Scenario.SLAP99MS > 0 {
		fmt.Fprintf(b, "- SLA: p99 <= %.2f ms.\n", res.Scenario.SLAP99MS)
	}
	if res.Scenario.MaxErrorRatePct > 0 {
		fmt.Fprintf(b, "- SLA: error rate <= %.2f%%.\n", res.Scenario.MaxErrorRatePct)
	}
	fmt.Fprintf(b, "- Achieved throughput: median %.2f rps (p95 %.2f rps).\n", res.Summary.AchievedRPS.P50, res.Summary.AchievedRPS.P95)
	fmt.Fprintf(b, "- Utilisation: median %.3f (p95 %.3f).\n", res.Summary.Utilization.P50, res.Summary.Utilization.P95)
	fmt.Fprintf(b, "- Predicted p99: median %.2f ms, p95 %.2f ms (range %.2f - %.2f ms).\n",
		res.Summary.P99MS.P50, res.Summary.P99MS.P95, res.Summary.P99MS.Min, res.Summary.P99MS.Max)
	fmt.Fprintf(b, "- Predicted error rate: median %.3f%%, p95 %.3f%%.\n", res.Summary.ErrorRatePct.P50, res.Summary.ErrorRatePct.P95)
	fmt.Fprintf(b, "- Breach probability: %.1f%% (latency %.1f%%, errors %.1f%%); risk %s.\n",
		res.Summary.SLAProbabilityBreach*100,
		res.Summary.P99BreachProbability*100,
		res.Summary.ErrorBreachProbability*100,
		res.Summary.RiskLevel)
	if res.Summary.PredictedSaturationSeconds != nil {
		fmt.Fprintf(b, "- Predicted saturation: %s into the ramp (in %.1f%% of draws).\n",
			formatSeconds(*res.Summary.PredictedSaturationSeconds), res.Summary.SaturationProbability*100)
	}
	if len(res.Notes) > 0 {
		b.WriteString("- Notes:\n")
		for _, note := range res.Notes {
			fmt.Fprintf(b, "  - %s\n", note)
		}
	}
	b.WriteString("\n")
}

func scenarioTarget(sc Scenario) string {
	if sc.Mode == LoopClosed {
		return fmt.Sprintf("%.2f users (closed)", sc.TargetUsers)
	}
	return fmt.Sprintf("%.2f rps (open)", sc.TargetRPS)
}

func formatSaturation(s Summary) string {
	if s.PredictedSaturationSeconds == nil {
		return "-"
	}
	return formatSeconds(*s.PredictedSaturationSeconds)
}

func formatSeconds(v float64) string {
	if v <= 0 {
		return "0 s"
	}
	if v < 1 {
		return fmt.Sprintf("%.0f ms", v*1000)
	}
	if v < 60 {
		return fmt.Sprintf("%.1f s", v)
	}
	return fmt.Sprintf("%.1f min", v/60)
}

func markdownCell(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return strings.ReplaceAll(v, "|", "\\|")
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "n/a"
	}
	return t.Format("2006-01-02T15:04:05Z07:00")
}
