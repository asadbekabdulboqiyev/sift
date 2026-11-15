// Package twin builds a capacity digital twin from a completed Sift load test
// and answers "what happens at load X?" without sending a single request.
//
// # What the twin is
//
// A Sift run measures one operating point: a throughput, a latency
// distribution and an error rate. The twin turns that point into an
// evidence-driven, versioned model — observed workload, service/capacity
// estimates, confidence and uncertainty — and extrapolates from it with a
// queueing approximation. It is a planning instrument, not a measurement and
// not a guarantee.
//
// # Evidence, uncertainty and honesty
//
// Every derived metric is traceable to collected report evidence. Confidence is
// scored 0-100 with structured reasons based on sample size, duration,
// distribution/stability, missing metrics, model uncertainty and data quality.
// High confidence is never assigned without sufficient evidence. Missing data
// is distinguished from uncertainty. Capacity distinguishes observed RPS from
// estimated sustainable capacity and reports uncertainty intervals; when
// evidence is insufficient the model returns INSUFFICIENT_DATA rather than
// fabricating a number. Simulated outputs are labeled as model-based estimates.
//
// # Capacity derivation
//
// Capacity is extrapolated with an M/M/1 tail approximation anchored to the
// measured operating point. Sustainable capacity additionally accounts for
// latency degradation, errors and saturation signals when available and is
// never treated as a guaranteed maximum.
package twin

import (
	"fmt"
	"math"
	"path/filepath"
	"strings"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/metrics"
	"github.com/asadbekabdulboqiyev/sift/internal/report"
)

// SchemaVersion identifies the on-disk model and result format.
// v2 adds evidence-based confidence/capacity semantics, uncertainty/intervals,
// validation metadata, and explicit data-quality/sufficiency fields while
// retaining legacy v1-compatible core fields for existing consumers.
const SchemaVersion = "sift.twin/v2"

// SchemaVersionV1 is the legacy on-disk format accepted for backward-compatible
// loading; v1 artifacts are upgraded in-memory to v2 semantics where possible.
const SchemaVersionV1 = "sift.twin/v1"

// Confidence/capacity status labels.
const (
	ConfidenceLowLabel    = "LOW"
	ConfidenceMediumLabel = "MEDIUM"
	ConfidenceHighLabel   = "HIGH"

	CapacitySufficient   = "SUFFICIENT"
	CapacityInsufficient = "INSUFFICIENT_DATA"
	CapacityDegraded     = "DEGRADED_EVIDENCE"

	DataQualityOK     = "OK"
	DataQualityWarn   = "WARN"
	DataQualityInsuff = "INSUFFICIENT"
)

// Capacity model constants. They are exported through ServiceCurve and
// Calibration rather than as package API so callers see the fitted numbers,
// not the internal knobs.
const (
	// tailFraction is the share of a run treated as the p99 tail. A run with
	// 100k requests contributes roughly 1k observations to the estimate, which
	// bounds how well p99 can be known at all.
	tailFraction = 0.01

	// minReferenceUtilization and maxReferenceUtilization clamp the utilisation
	// implied by the measured tail. The lower clamp caps extrapolated capacity
	// at 10x the observed load when the tail is flat; the upper clamp stops a
	// single slow outlier from implying infinite capacity pressure.
	minReferenceUtilization = 0.10
	maxReferenceUtilization = 0.98

	// capacityUncertainty clamp: never claim better than +/-2% or worse than
	// +/-60% from a heuristic that only sees aggregate percentiles.
	minCapacityUncertainty = 0.02
	maxCapacityUncertainty = 0.60

	// openLoopProfile is the Sift load profile that enforces a fixed arrival
	// rate. Every other profile is closed-loop: virtual users wait for their
	// own response before issuing the next request.
	openLoopProfile = "constant-rps"

	// maxFitDurationSeconds and maxFitRequests are sanity limits for a report
	// being fitted. They are deliberately far above any practical run: they
	// exist to reject corrupt files, not to police test length.
	maxFitDurationSeconds = 7 * 24 * 60 * 60
	maxFitRequests        = 1_000_000_000_000
)

// Confidence is the legacy grade attached to a fitted model (kept for
// backward compatibility with v1 consumers). v2 consumers should prefer
// ConfidenceAssessment.
type Confidence string

const (
	// ConfidenceHigh means the run was long enough and large enough that p99
	// rests on a meaningful number of tail observations.
	ConfidenceHigh Confidence = "high"
	// ConfidenceMedium means the estimate is usable for planning but carries
	// visible sampling error.
	ConfidenceMedium Confidence = "medium"
	// ConfidenceLow means the run was short or noisy; treat the capacity
	// estimate as an order of magnitude, not a number.
	ConfidenceLow Confidence = "low"
)

// EvidenceFactor records one structured confidence/data-quality factor.
type EvidenceFactor struct {
	Name        string  `json:"name"`
	Score       float64 `json:"score"`       // 0-100 contribution/quality for this factor
	Weight      float64 `json:"weight"`      // relative weight used in scoring
	Status      string  `json:"status"`      // OK/WARN/MISSING/INSUFFICIENT
	Evidence    string  `json:"evidence"`    // traceable value(s) from collected data
	Impact      string  `json:"impact"`      // how it affects confidence/capacity
	Uncertainty string  `json:"uncertainty"` // uncertainty vs missing-data explanation
}

// ConfidenceAssessment is the evidence-based confidence result (P0).
type ConfidenceAssessment struct {
	Score         float64          `json:"score"`                   // 0-100
	Level         string           `json:"level"`                   // LOW/MEDIUM/HIGH
	Summary       string           `json:"summary"`                 // structured explanation
	Factors       []EvidenceFactor `json:"factors"`                 // sample size, duration, distribution/stability, missing metrics, model uncertainty, data quality
	MissingData   []string         `json:"missing_data,omitempty"`  // explicitly missing inputs/metrics
	Uncertainties []string         `json:"uncertainties,omitempty"` // known uncertainty sources (not missing)
	DataQuality   string           `json:"data_quality"`            // OK/WARN/INSUFFICIENT
	Sufficient    bool             `json:"sufficient_evidence"`
}

// Interval is a numeric uncertainty/confidence interval.
type Interval struct {
	Low    float64 `json:"low"`
	High   float64 `json:"high"`
	Level  float64 `json:"level,omitempty"`  // e.g. 0.95
	Method string  `json:"method,omitempty"` // heuristic/bootstrap description
}

// CapacityAssessment distinguishes observed from sustainable capacity (P0).
type CapacityAssessment struct {
	Status              string    `json:"status"` // SUFFICIENT/INSUFFICIENT_DATA/DEGRADED_EVIDENCE
	ObservedRPS         float64   `json:"observed_rps"`
	ObservedIsMax       bool      `json:"observed_is_max"` // always false by design
	SustainableRPS      *float64  `json:"sustainable_rps,omitempty"`
	SustainableInterval *Interval `json:"sustainable_interval,omitempty"`
	Uncertainty         string    `json:"uncertainty,omitempty"`
	DegradationSignals  []string  `json:"degradation_signals,omitempty"` // latency/errors/saturation/resource pressure
	SaturationObserved  bool      `json:"saturation_observed"`
	ErrorPressure       bool      `json:"error_pressure"`
	LatencyDegradation  bool      `json:"latency_degradation"`
	Notes               []string  `json:"notes,omitempty"`
}

// ModelVersion captures model versioning/parameters/assumptions for
// reproducibility and validation traceability (P1 foundation).
type ModelVersion struct {
	Version           string             `json:"version"`
	Algorithm         string             `json:"algorithm"`
	Parameters        map[string]string  `json:"parameters,omitempty"`
	Assumptions       []string           `json:"assumptions,omitempty"`
	FittedFrom        string             `json:"fitted_from,omitempty"`
	BacktestStatus    string             `json:"backtest_status,omitempty"` // NOT_RUN/OK/WARN/DRIFT/OOD/INSUFFICIENT_DATA
	DriftStatus       string             `json:"drift_status,omitempty"`    // UNKNOWN/NONE/DETECTED
	ValidationNotes   []string           `json:"validation_notes,omitempty"`
	LastValidation    *ValidationRecord  `json:"last_validation,omitempty"`
	ValidationHistory []ValidationRecord `json:"validation_history,omitempty"` // bounded, most recent first
}

// EnsureModelInfo initializes model version metadata for validation updates.
func (m *Model) EnsureModelInfo() {
	if m == nil {
		return
	}
	if m.ModelInfo == nil {
		m.ModelInfo = &ModelVersion{
			Version:        "twin-model/2.0",
			Algorithm:      "mm1-tail-extrapolation",
			BacktestStatus: "NOT_RUN",
			DriftStatus:    "UNKNOWN",
		}
	}
	if strings.TrimSpace(m.ModelInfo.BacktestStatus) == "" {
		m.ModelInfo.BacktestStatus = "NOT_RUN"
	}
	if strings.TrimSpace(m.ModelInfo.DriftStatus) == "" {
		m.ModelInfo.DriftStatus = "UNKNOWN"
	}
}

// ApplyValidationOutcome records a validation/backtest outcome in model metadata.
// This is additive and keeps a bounded note history.
func (m *Model) ApplyValidationOutcome(backtestStatus, driftStatus, note string) {
	if m == nil {
		return
	}
	m.EnsureModelInfo()
	if strings.TrimSpace(backtestStatus) != "" {
		m.ModelInfo.BacktestStatus = strings.TrimSpace(backtestStatus)
	}
	if strings.TrimSpace(driftStatus) != "" {
		m.ModelInfo.DriftStatus = strings.TrimSpace(driftStatus)
	}
	note = strings.TrimSpace(note)
	if note == "" {
		return
	}
	stamped := time.Now().UTC().Format(time.RFC3339) + " " + note
	m.ModelInfo.ValidationNotes = append([]string{stamped}, m.ModelInfo.ValidationNotes...)
	if len(m.ModelInfo.ValidationNotes) > 20 {
		m.ModelInfo.ValidationNotes = m.ModelInfo.ValidationNotes[:20]
	}
}

// ApplyValidationRecord persists a canonical validation/backtest record into the
// model for traceability. It updates derived BacktestStatus/DriftStatus,
// stores the last validation, appends bounded history (most recent first, max 10),
// and appends a bounded timestamped note summarizing leakage/provenance. Additive.
func (m *Model) ApplyValidationRecord(rec ValidationRecord) {
	if m == nil {
		return
	}
	m.EnsureModelInfo()

	backtestStatus := strings.TrimSpace(rec.BacktestStatus)
	driftStatus := strings.TrimSpace(rec.DriftStatus)
	if backtestStatus == "" && rec.Backtest != nil {
		backtestStatus, driftStatus = rec.Backtest.ValidationStatus()
	}
	if backtestStatus == "" && rec.Comparison != nil {
		s, d, _ := ComparisonValidationStatus(*rec.Comparison)
		backtestStatus, driftStatus = s, d
	}
	if backtestStatus == "" {
		backtestStatus = m.ModelInfo.BacktestStatus
	}
	if driftStatus == "" {
		driftStatus = m.ModelInfo.DriftStatus
	}
	m.ModelInfo.BacktestStatus = backtestStatus
	m.ModelInfo.DriftStatus = driftStatus

	rec.BacktestStatus = backtestStatus
	rec.DriftStatus = driftStatus
	if rec.SchemaVersion == "" {
		rec.SchemaVersion = "sift.twin-validation/v1"
	}
	if rec.GeneratedAt == "" {
		rec.GeneratedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if rec.Leakage != nil {
		if strings.TrimSpace(rec.VerificationStatus) == "" {
			rec.VerificationStatus = rec.Leakage.Status
		}
		if !rec.Leakage.Verified && rec.Leakage.Status == LeakageStatusVerifiedNoLeakage {
			// never trust inconsistent flags
			rec.Leakage.Status = LeakageStatusUnverified
			rec.Leakage.Proven = false
		}
	}
	if strings.TrimSpace(rec.VerificationStatus) == "" && rec.Verification != nil {
		rec.VerificationStatus = rec.Verification.Status
	}

	stored := rec
	m.ModelInfo.LastValidation = &stored
	m.ModelInfo.ValidationHistory = append([]ValidationRecord{stored}, m.ModelInfo.ValidationHistory...)
	if len(m.ModelInfo.ValidationHistory) > 10 {
		m.ModelInfo.ValidationHistory = m.ModelInfo.ValidationHistory[:10]
	}

	note := fmt.Sprintf("validation_record: kind=%s status=%s drift=%s", fallbackNonEmpty(rec.Kind, "unknown"), fallbackNonEmpty(backtestStatus, "UNKNOWN"), fallbackNonEmpty(driftStatus, "UNKNOWN"))
	note += " " + summarizeValidationProvenance(rec)
	m.ApplyValidationOutcome(backtestStatus, driftStatus, note)
}

func fallbackNonEmpty(v, alt string) string {
	if strings.TrimSpace(v) == "" {
		return alt
	}
	return strings.TrimSpace(v)
}

func summarizeValidationProvenance(rec ValidationRecord) string {
	parts := []string{}
	if rec.Dataset != nil {
		id := rec.Dataset.ID
		if id == "" {
			id = rec.Dataset.Path
		}
		if id == "" {
			id = rec.Dataset.Kind
		}
		if id != "" {
			parts = append(parts, "dataset="+id)
		}
	} else {
		parts = append(parts, "dataset=none")
	}
	if rec.ManifestPath != "" {
		parts = append(parts, "manifest="+filepath.Base(rec.ManifestPath))
	} else if rec.Manifest != nil {
		parts = append(parts, "manifest=embedded")
	} else {
		parts = append(parts, "manifest=none")
	}
	if rec.Split != nil && strings.TrimSpace(rec.Split.Strategy) != "" {
		parts = append(parts, "split="+strings.TrimSpace(rec.Split.Strategy))
	} else {
		parts = append(parts, "split=unspecified")
	}
	if rec.Leakage != nil {
		parts = append(parts, fmt.Sprintf("leakage_enforced=%t leakage_proven=%t", rec.Leakage.Enforced, rec.Leakage.Proven))
		if strings.TrimSpace(rec.Leakage.Status) != "" {
			parts = append(parts, "leakage_status="+strings.TrimSpace(rec.Leakage.Status))
		}
		if strings.TrimSpace(rec.Leakage.Method) != "" {
			parts = append(parts, "leakage_method="+strings.TrimSpace(rec.Leakage.Method))
		}
	} else {
		parts = append(parts, "leakage=unspecified")
	}
	if strings.TrimSpace(rec.VerificationStatus) != "" {
		parts = append(parts, "verification="+strings.TrimSpace(rec.VerificationStatus))
	}
	return strings.Join(parts, " ")
}

// Latency is a latency distribution in milliseconds.
type Latency struct {
	P50MS float64 `json:"p50_ms"`
	P95MS float64 `json:"p95_ms"`
	P99MS float64 `json:"p99_ms"`
	// AvgMS is the arithmetic mean. It is what Little's law needs; percentiles
	// alone cannot recover concurrency.
	AvgMS float64 `json:"avg_ms"`
}

// Source records where the model came from, so an artifact can be traced back
// to the exact report that produced it.
type Source struct {
	ReportName      string    `json:"report_name"`
	TargetURL       string    `json:"target_url"`
	LoadProfile     string    `json:"load_profile"`
	StartedAt       time.Time `json:"started_at"`
	EndedAt         time.Time `json:"ended_at"`
	DurationSeconds float64   `json:"duration_seconds"`
	Producer        string    `json:"producer"`
}

// Workload is the observed operating point the model was fitted to.
type Workload struct {
	RPS             float64 `json:"rps"`
	Concurrency     float64 `json:"concurrency"`
	ActiveUsers     int64   `json:"active_users"`
	DurationSeconds float64 `json:"duration_seconds"`
	// OpenLoop is true when the load generator enforced an arrival rate
	// instead of pacing a fixed number of virtual users.
	OpenLoop      bool    `json:"open_loop"`
	TotalRequests uint64  `json:"total_requests"`
	TotalErrors   uint64  `json:"total_errors"`
	ErrorRatePct  float64 `json:"error_rate_pct"`
}

// ServiceCurve is the fitted latency/capacity relation (legacy-compatible core).
type ServiceCurve struct {
	// Baseline is the latency distribution measured at the observed load.
	Baseline Latency `json:"baseline_latency"`
	// CapacityRPS is a legacy point estimate (kept for compatibility).
	// v2 consumers should prefer CapacityAssessment for sustainable capacity.
	CapacityRPS                 float64 `json:"capacity_rps"`
	CapacityLowRPS              float64 `json:"capacity_low_rps"`
	CapacityHighRPS             float64 `json:"capacity_high_rps"`
	CapacityRelativeUncertainty float64 `json:"capacity_relative_uncertainty"`
	// ReferenceUtilization is the utilisation the fitted run operated at.
	ReferenceUtilization float64 `json:"reference_utilization"`
	// DegradationShape names the approximation used to amplify latency.
	DegradationShape string `json:"degradation_shape"`
	// QueueScaleMS is L0 from the M/M/1 tail model (p50 / ln 2).
	QueueScaleMS float64 `json:"queue_scale_ms"`
}

// Calibration explains how the model was derived.
type Calibration struct {
	Method      string    `json:"method"`
	FittedAt    time.Time `json:"fitted_at"`
	TargetP99MS float64   `json:"target_p99_ms"`
	Notes       []string  `json:"notes"`
}

// Model is the complete digital twin. It is JSON-serializable and versioned.
type Model struct {
	SchemaVersion string       `json:"schema_version"`
	Source        Source       `json:"source"`
	Workload      Workload     `json:"workload"`
	Curve         ServiceCurve `json:"service_curve"`
	// Legacy confidence label for backward compatibility.
	Confidence Confidence `json:"confidence"`
	// Evidence-based confidence (P0).
	ConfidenceV2 *ConfidenceAssessment `json:"confidence_assessment,omitempty"`
	// Observed vs sustainable capacity with uncertainty/insufficiency (P0).
	Capacity *CapacityAssessment `json:"capacity_assessment,omitempty"`
	// Model versioning/parameters/assumptions/validation metadata (P1 foundation).
	ModelInfo *ModelVersion `json:"model_info,omitempty"`
	// Optional resource monitoring evidence (host/run-provided or derived) with
	// explicit unavailable/insufficient labeling. Never fabricated.
	ResourceEvidence *ResourceAvailability `json:"resource_evidence,omitempty"`
	Calibration      Calibration           `json:"calibration"`
}

// FitOptions controls the fit.
type FitOptions struct {
	// TargetP99MS is the latency objective used to describe capacity headroom
	// and to seed scenario SLAs. Zero selects the documented default.
	TargetP99MS float64
	// Producer names the tool that created the model. Empty means "sift".
	Producer string
}

// Fit derives a Model from a completed Sift report.
//
// It fails closed on invalid core timing/latency/request evidence but returns
// an evidence-driven model with INSUFFICIENT_DATA capacity semantics when
// sustainable capacity cannot be responsibly estimated.
func Fit(rep report.Report, opts FitOptions) (Model, error) {
	durationSec := rep.Duration.Seconds()
	if math.IsNaN(durationSec) || math.IsInf(durationSec, 0) || durationSec <= 0 {
		return Model{}, fmt.Errorf("twin: report duration must be a positive number, got %s", rep.Duration)
	}
	if durationSec > maxFitDurationSeconds {
		return Model{}, fmt.Errorf("twin: report duration %.0fs exceeds the %.0fs sanity limit", durationSec, float64(maxFitDurationSeconds))
	}
	if rep.TotalRequests == 0 {
		return Model{}, fmt.Errorf("twin: report %q contains no completed requests; nothing to fit", reportName(rep))
	}
	if rep.TotalRequests > maxFitRequests {
		return Model{}, fmt.Errorf("twin: report request count %d exceeds the %d sanity limit", rep.TotalRequests, uint64(maxFitRequests))
	}

	overall := rep.Overall
	p50 := durationMS(overall.P50)
	p95 := durationMS(overall.P95)
	p99 := durationMS(overall.P99)
	avg := durationMS(overall.Avg)
	switch {
	case p50 <= 0 || p95 <= 0 || p99 <= 0:
		return Model{}, fmt.Errorf("twin: report latency percentiles must all be positive (p50=%.3fms p95=%.3fms p99=%.3fms)", p50, p95, p99)
	case p95 < p50 || p99 < p95:
		return Model{}, fmt.Errorf("twin: report latency percentiles are not monotonic (p50=%.3fms p95=%.3fms p99=%.3fms)", p50, p95, p99)
	}
	meanMissing := avg <= 0
	if meanMissing {
		avg = p50
	}

	errPct := float64(rep.TotalErrors) / float64(rep.TotalRequests) * 100
	if math.IsNaN(errPct) || math.IsInf(errPct, 0) || errPct < 0 || errPct > 100 {
		return Model{}, fmt.Errorf("twin: report error rate is not in [0,100]%% (errors=%d requests=%d)", rep.TotalErrors, rep.TotalRequests)
	}

	rps := float64(rep.TotalRequests) / durationSec
	if math.IsNaN(rps) || math.IsInf(rps, 0) || rps <= 0 {
		return Model{}, fmt.Errorf("twin: derived throughput is not a positive finite number (requests=%d duration=%.3fs)", rep.TotalRequests, durationSec)
	}

	concurrency := rps * (avg / 1000)
	if concurrency <= 0 {
		return Model{}, fmt.Errorf("twin: derived concurrency is not positive (rps=%.3f avg=%.3fms)", rps, avg)
	}

	notes := make([]string, 0, 10)
	if rep.RPS > 0 {
		if rel := math.Abs(rep.RPS-rps) / rps; rel > 0.05 {
			notes = append(notes, fmt.Sprintf("report rps %.2f differs from requests/duration %.2f by %.1f%%; the derived value is used", rep.RPS, rps, rel*100))
		}
	}
	if rep.ErrorRatePct > 0 && math.Abs(rep.ErrorRatePct-errPct) > 0.01 {
		notes = append(notes, fmt.Sprintf("report error rate %.3f%% differs from counts-derived %.3f%%; the counts-derived value is used", rep.ErrorRatePct, errPct))
	}
	if meanMissing {
		notes = append(notes, "average latency missing in report; p50 used as conservative stand-in for mean-based concurrency (uncertainty increased)")
	}

	// M/M/1 tail approximation anchored at measured point.
	queueScale := p50 / math.Ln2
	rawRef := 1 - queueScale/p99
	ref := clamp(rawRef, minReferenceUtilization, maxReferenceUtilization)
	capacity := rps / ref
	uncertainty := capacityUncertainty(rep.TotalRequests, durationSec, errPct)
	clamped := rawRef != ref
	if clamped {
		uncertainty = math.Min(uncertainty+0.05, maxCapacityUncertainty)
		notes = append(notes, fmt.Sprintf("reference utilisation %.3f was clamped to %.3f: measured tail does not follow the M/M/1 shape; extrapolation uncertainty increased", rawRef, ref))
	}

	target := opts.TargetP99MS
	if target <= 0 {
		target = math.Max(p99*1.5, p99+50)
		notes = append(notes, fmt.Sprintf("no --target-p99-ms supplied; defaulting to %.2fms (max(1.5x observed p99, observed p99 + 50ms))", target))
	}

	openLoop := rep.LoadProfile == openLoopProfile
	if openLoop {
		notes = append(notes, "open-loop run: generator enforced arrival rate, measured latency includes queueing delay")
	} else {
		notes = append(notes, "closed-loop run: virtual users paced load; throughput/concurrency reflect client-side pacing")
	}

	producer := opts.Producer
	if producer == "" {
		producer = "sift"
	}
	fittedAt := rep.EndedAt
	if fittedAt.IsZero() {
		fittedAt = rep.StartedAt
	}

	// Evidence-based confidence (P0).
	confLegacy := confidenceGrade(durationSec, rep.TotalRequests, errPct, clamped)
	confV2 := buildConfidenceAssessment(rep, durationSec, rps, errPct, uncertainty, clamped, meanMissing, rawRef)
	// Never assign HIGH without sufficient evidence.
	if !confV2.Sufficient && confV2.Level == ConfidenceHighLabel {
		confV2.Level = ConfidenceMediumLabel
		confV2.Summary += " High label downgraded because sufficient evidence is not present."
	}
	if confV2.Level == ConfidenceHighLabel && confLegacy == ConfidenceLow {
		// Defensive: keep label consistent with evidence thresholds.
		confV2.Level = ConfidenceMediumLabel
	}

	// Sustainable capacity assessment (P0): observed != max, degradation-aware, may be INSUFFICIENT_DATA.
	capAssess := buildCapacityAssessment(rep, rps, capacity, uncertainty, p50, p95, p99, errPct, durationSec, confV2.Sufficient)

	// Keep legacy curve fields populated for compatibility with existing
	// simulators/consumers (raw M/M/1 modeled capacity estimate and uncertainty).
	legacyCap := capacity
	legacyLow := capacity * (1 - uncertainty)
	legacyHigh := capacity * (1 + uncertainty)
	legacyUncertainty := uncertainty
	// When sustainable capacity is insufficient, still retain modeled bounds but
	// CapacityAssessment clearly reports INSUFFICIENT_DATA (no fabricated certainty).
	if capAssess.SustainableInterval != nil && capAssess.Status == CapacityInsufficient {
		// leave modeled legacy fields as-is
	}
	_ = legacyUncertainty

	m := Model{
		SchemaVersion: SchemaVersion,
		Source: Source{
			ReportName:      rep.Name,
			TargetURL:       rep.BaseURL,
			LoadProfile:     rep.LoadProfile,
			StartedAt:       rep.StartedAt,
			EndedAt:         rep.EndedAt,
			DurationSeconds: durationSec,
			Producer:        producer,
		},
		Workload: Workload{
			RPS:             rps,
			Concurrency:     concurrency,
			ActiveUsers:     rep.ActiveUsers,
			DurationSeconds: durationSec,
			OpenLoop:        openLoop,
			TotalRequests:   rep.TotalRequests,
			TotalErrors:     rep.TotalErrors,
			ErrorRatePct:    errPct,
		},
		Curve: ServiceCurve{
			Baseline:                    Latency{P50MS: p50, P95MS: p95, P99MS: p99, AvgMS: avg},
			CapacityRPS:                 legacyCap,
			CapacityLowRPS:              legacyLow,
			CapacityHighRPS:             legacyHigh,
			CapacityRelativeUncertainty: legacyUncertainty,
			ReferenceUtilization:        ref,
			DegradationShape:            "mm1-tail",
			QueueScaleMS:                queueScale,
		},
		Confidence:   confLegacy,
		ConfidenceV2: &confV2,
		Capacity:     &capAssess,
		ModelInfo: &ModelVersion{
			Version:         "twin-model/2.0",
			Algorithm:       "little-law+mm1-tail+evidence-heuristics",
			Parameters:      map[string]string{"tail_fraction": "0.01", "ref_util_min": "0.10", "ref_util_max": "0.98"},
			Assumptions:     []string{"steady-state", "single dominant bottleneck", "no autoscaling/cache warm-up modeled", "traffic mix similar to source run", "model-based estimate, not a guarantee"},
			FittedFrom:      "report",
			BacktestStatus:  "NOT_RUN",
			DriftStatus:     "UNKNOWN",
			ValidationNotes: []string{"Prediction-vs-actual backtesting/drift analysis requires historical observed runs and is reported separately when available."},
		},
		Calibration: Calibration{
			Method:      "little-law + mm1-tail + evidence-based confidence/capacity assessment",
			FittedAt:    fittedAt,
			TargetP99MS: target,
			Notes:       append(notes, capAssess.Notes...),
		},
	}
	if err := m.Validate(); err != nil {
		return Model{}, fmt.Errorf("twin: fitted model failed validation: %w", err)
	}
	return m, nil
}

// Validate reports whether the model is internally consistent enough to simulate.
// Supports v2 and legacy v1 artifacts (v1 is normalized in-memory).
func (m Model) Validate() error {
	if m.SchemaVersion == "" {
		return fmt.Errorf("model schema version is required")
	}
	if m.SchemaVersion != SchemaVersion && m.SchemaVersion != SchemaVersionV1 {
		return fmt.Errorf("unsupported model schema %q (want %q or %q)", m.SchemaVersion, SchemaVersion, SchemaVersionV1)
	}
	c := m.Curve
	if !finite(c.CapacityRPS) || c.CapacityRPS <= 0 {
		return fmt.Errorf("capacity must be a positive finite number, got %v", c.CapacityRPS)
	}
	if c.CapacityLowRPS <= 0 || c.CapacityLowRPS > c.CapacityRPS || c.CapacityHighRPS < c.CapacityRPS {
		return fmt.Errorf("capacity bounds are inconsistent (low=%v point=%v high=%v)", c.CapacityLowRPS, c.CapacityRPS, c.CapacityHighRPS)
	}
	if !finite(c.ReferenceUtilization) || c.ReferenceUtilization <= 0 || c.ReferenceUtilization >= 1 {
		return fmt.Errorf("reference utilisation must be in (0,1), got %v", c.ReferenceUtilization)
	}
	b := c.Baseline
	if b.P50MS <= 0 || b.P95MS <= 0 || b.P99MS <= 0 || b.AvgMS <= 0 {
		return fmt.Errorf("baseline latencies must all be positive (p50=%v p95=%v p99=%v avg=%v)", b.P50MS, b.P95MS, b.P99MS, b.AvgMS)
	}
	if b.P95MS < b.P50MS || b.P99MS < b.P95MS {
		return fmt.Errorf("baseline latencies are not monotonic (p50=%v p95=%v p99=%v)", b.P50MS, b.P95MS, b.P99MS)
	}
	switch m.Confidence {
	case ConfidenceHigh, ConfidenceMedium, ConfidenceLow:
	default:
		return fmt.Errorf("unknown confidence grade %q", m.Confidence)
	}
	if !finite(m.Workload.RPS) || m.Workload.RPS <= 0 {
		return fmt.Errorf("workload rps must be a positive finite number, got %v", m.Workload.RPS)
	}
	if m.Workload.ErrorRatePct < 0 || m.Workload.ErrorRatePct > 100 {
		return fmt.Errorf("workload error rate must be in [0,100]%%, got %v", m.Workload.ErrorRatePct)
	}
	if m.ConfidenceV2 != nil {
		if m.ConfidenceV2.Score < 0 || m.ConfidenceV2.Score > 100 {
			return fmt.Errorf("confidence score must be in [0,100], got %v", m.ConfidenceV2.Score)
		}
		switch m.ConfidenceV2.Level {
		case ConfidenceLowLabel, ConfidenceMediumLabel, ConfidenceHighLabel:
		default:
			return fmt.Errorf("unknown confidence level %q", m.ConfidenceV2.Level)
		}
		if m.ConfidenceV2.Level == ConfidenceHighLabel && !m.ConfidenceV2.Sufficient {
			return fmt.Errorf("confidence HIGH requires sufficient evidence")
		}
	}
	if m.Capacity != nil {
		switch m.Capacity.Status {
		case CapacitySufficient, CapacityInsufficient, CapacityDegraded:
		default:
			return fmt.Errorf("unknown capacity status %q", m.Capacity.Status)
		}
		if m.Capacity.ObservedIsMax {
			return fmt.Errorf("observed capacity must never be treated as maximum")
		}
		if m.Capacity.Status == CapacityInsufficient {
			if m.Capacity.SustainableRPS != nil {
				return fmt.Errorf("insufficient-data capacity must not fabricate sustainable_rps")
			}
		} else {
			if m.Capacity.SustainableRPS == nil || !finite(*m.Capacity.SustainableRPS) || *m.Capacity.SustainableRPS <= 0 {
				return fmt.Errorf("sufficient/degraded capacity requires positive sustainable_rps")
			}
			if m.Capacity.SustainableInterval != nil {
				iv := m.Capacity.SustainableInterval
				if !finite(iv.Low) || !finite(iv.High) || iv.Low <= 0 || iv.High < iv.Low {
					return fmt.Errorf("invalid sustainable capacity interval")
				}
			}
		}
	}
	return nil
}

// NormalizeModel upgrades legacy/partial models to v2 semantics in-memory.
func NormalizeModel(m Model) Model {
	if m.SchemaVersion == SchemaVersionV1 || m.SchemaVersion == "" {
		m.SchemaVersion = SchemaVersion
	}
	if m.ConfidenceV2 == nil {
		assess := legacyConfidenceAssessment(m)
		m.ConfidenceV2 = &assess
	}
	if m.Capacity == nil {
		assess := legacyCapacityAssessment(m)
		m.Capacity = &assess
	}
	if m.ModelInfo == nil {
		m.ModelInfo = &ModelVersion{Version: "twin-model/legacy-upgraded", Algorithm: "legacy-mm1-tail", BacktestStatus: "NOT_RUN", DriftStatus: "UNKNOWN"}
	}
	return m
}

// ValidateAndNormalize validates and returns a normalized v2-compatible model.
func ValidateAndNormalize(m Model) (Model, error) {
	n := NormalizeModel(m)
	if err := n.Validate(); err != nil {
		return Model{}, err
	}
	return n, nil
}

func buildConfidenceAssessment(rep report.Report, durationSec, rps, errPct, modelUncertainty float64, clamped, meanMissing bool, rawRef float64) ConfidenceAssessment {
	var factors []EvidenceFactor
	var missing []string
	var uncertainties []string

	// Sample size
	tailSamples := float64(rep.TotalRequests) * tailFraction
	sampleScore := scoreFromRanges(tailSamples, []rangeScore{{0, 10, 5}, {10, 100, 35}, {100, 1000, 65}, {1000, 1e18, 95}})
	sampleStatus := "OK"
	if rep.TotalRequests < 100 {
		sampleStatus = "INSUFFICIENT"
		uncertainties = append(uncertainties, "Very small sample size increases quantile estimation uncertainty")
	} else if rep.TotalRequests < 1000 {
		sampleStatus = "WARN"
		uncertainties = append(uncertainties, "Limited sample size increases tail-latency uncertainty")
	}
	factors = append(factors, EvidenceFactor{
		Name: "sample_size", Score: sampleScore, Weight: 0.25, Status: sampleStatus,
		Evidence:    fmt.Sprintf("requests=%d, estimated_tail_samples=%.0f", rep.TotalRequests, tailSamples),
		Impact:      "Controls reliability of latency percentiles and capacity extrapolation",
		Uncertainty: ternaryStr(sampleStatus == "OK", "Sampling uncertainty bounded by available observations", "Tail percentiles are uncertain due to limited observations"),
	})

	// Duration
	durScore := scoreFromRanges(durationSec, []rangeScore{{0, 5, 10}, {5, 20, 40}, {20, 60, 70}, {60, 1e18, 95}})
	durStatus := "OK"
	if durationSec < 10 {
		durStatus = "INSUFFICIENT"
		uncertainties = append(uncertainties, "Short run duration reduces confidence in steady-state behavior")
	} else if durationSec < 30 {
		durStatus = "WARN"
		uncertainties = append(uncertainties, "Moderate run duration may not capture stability over time")
	}
	factors = append(factors, EvidenceFactor{
		Name: "duration", Score: durScore, Weight: 0.20, Status: durStatus,
		Evidence:    fmt.Sprintf("duration=%.3fs", durationSec),
		Impact:      "Longer runs better capture steady-state and variability",
		Uncertainty: ternaryStr(durStatus == "OK", "Duration sufficient for basic steady-state estimation", "Steady-state/stability uncertainty remains due to run length"),
	})

	// Distribution/stability (from p50/p95/p99 spread and timeline variability if available)
	spread := 0.0
	if rep.Overall.P50 > 0 {
		spread = float64(rep.Overall.P99) / float64(rep.Overall.P50)
	}
	distScore := 90.0
	distStatus := "OK"
	if spread >= 10 {
		distScore = 35
		distStatus = "WARN"
		uncertainties = append(uncertainties, "Very heavy tail (high p99/p50 spread) increases model uncertainty")
	} else if spread >= 5 {
		distScore = 60
		distStatus = "WARN"
		uncertainties = append(uncertainties, "Heavy latency tail increases extrapolation uncertainty")
	}
	// Timeline stability (coefficient-like signal from RPS variation)
	if len(rep.Timeline) >= 3 {
		cv := timelineRPSCV(rep.Timeline)
		if cv > 0.5 {
			distScore = math.Min(distScore, 40)
			distStatus = "WARN"
			uncertainties = append(uncertainties, fmt.Sprintf("Observed throughput variability is high (timeline RPS CV≈%.2f)", cv))
		} else if cv > 0.25 {
			distScore = math.Min(distScore, 65)
			if distStatus == "OK" {
				distStatus = "WARN"
			}
			uncertainties = append(uncertainties, fmt.Sprintf("Moderate throughput variability observed (timeline RPS CV≈%.2f)", cv))
		}
	} else {
		uncertainties = append(uncertainties, "Timeline data limited; stability over time cannot be fully assessed (uncertainty, not necessarily missing execution evidence)")
	}
	factors = append(factors, EvidenceFactor{
		Name: "distribution_stability", Score: distScore, Weight: 0.20, Status: distStatus,
		Evidence:    fmt.Sprintf("p50=%.3fms p95=%.3fms p99=%.3fms spread_p99_p50=%.2f timeline_points=%d", durationMS(rep.Overall.P50), durationMS(rep.Overall.P95), durationMS(rep.Overall.P99), spread, len(rep.Timeline)),
		Impact:      "Heavy tails and instability reduce confidence in point estimates and extrapolation",
		Uncertainty: ternaryStr(distStatus == "OK", "Distribution appears reasonably stable for model assumptions", "Distribution/stability uncertainty present"),
	})

	// Missing metrics
	missingScore := 95.0
	missingStatus := "OK"
	if meanMissing {
		missing = append(missing, "overall.avg_latency")
		missingScore -= 15
		missingStatus = "WARN"
	}
	if len(rep.Timeline) == 0 {
		missing = append(missing, "timeline_samples")
		missingScore -= 10
		if missingStatus == "OK" {
			missingStatus = "WARN"
		}
	}
	// No resource monitoring in base report
	missing = append(missing, "resource_cpu", "resource_memory", "resource_network", "resource_connections")
	missingScore = math.Max(missingScore-20, 20)
	if missingStatus == "OK" {
		missingStatus = "WARN"
	}
	factors = append(factors, EvidenceFactor{
		Name: "missing_metrics", Score: missingScore, Weight: 0.15, Status: missingStatus,
		Evidence:    fmt.Sprintf("avg_present=%t timeline=%d resource_metrics_in_report=false", !meanMissing, len(rep.Timeline)),
		Impact:      "Missing metrics limit attribution and can hide saturation/resource constraints",
		Uncertainty: "Missing metrics are treated as missing data (not measured), distinct from statistical uncertainty",
	})

	// Model uncertainty
	muScore := clamp((1-modelUncertainty)*100, 5, 95)
	muStatus := "OK"
	if clamped || rawRef <= 0 {
		muStatus = "WARN"
	}
	if modelUncertainty > 0.35 {
		muStatus = "WARN"
	}
	factors = append(factors, EvidenceFactor{
		Name: "model_uncertainty", Score: muScore, Weight: 0.10, Status: muStatus,
		Evidence:    fmt.Sprintf("relative_uncertainty=%.3f clamped=%t raw_ref_util=%.4f", modelUncertainty, clamped, rawRef),
		Impact:      "Model assumptions and tail-shape mismatch increase extrapolation uncertainty",
		Uncertainty: "Uncertainty from model fit/assumptions (not missing measurements)",
	})

	// Data quality
	dqScore := 95.0
	dqStatus := DataQualityOK
	if errPct >= 5 {
		dqScore -= 30
		dqStatus = DataQualityWarn
		uncertainties = append(uncertainties, fmt.Sprintf("Elevated error rate (%.2f%%) indicates degraded/unstable measurement conditions", errPct))
	} else if errPct >= 1 {
		dqScore -= 10
		if dqStatus == DataQualityOK {
			dqStatus = DataQualityWarn
		}
	}
	if rep.TotalErrors == rep.TotalRequests && rep.TotalRequests > 0 {
		dqScore = 10
		dqStatus = DataQualityInsuff
		uncertainties = append(uncertainties, "All requests failed; observed latency/throughput may not represent healthy service behavior")
	}
	if !rep.StartedAt.IsZero() && !rep.EndedAt.IsZero() && rep.StartedAt.Equal(rep.EndedAt) && rep.Duration > 0 {
		dqScore -= 5
	}
	factors = append(factors, EvidenceFactor{
		Name: "data_quality", Score: clamp(dqScore, 0, 100), Weight: 0.10, Status: ternaryStr(dqStatus == DataQualityOK, "OK", "WARN"),
		Evidence:    fmt.Sprintf("error_rate=%.3f%% errors=%d/%d", errPct, rep.TotalErrors, rep.TotalRequests),
		Impact:      "Data quality issues can bias observed and derived metrics",
		Uncertainty: ternaryStr(dqStatus == DataQualityOK, "No major data-quality issues detected from available evidence", "Data-quality uncertainty present"),
	})

	score := 0.0
	weightSum := 0.0
	for _, f := range factors {
		score += f.Score * f.Weight
		weightSum += f.Weight
	}
	if weightSum > 0 {
		score /= weightSum
	}
	score = clamp(score, 0, 100)

	// Sufficiency gates: must have minimum evidence for responsible estimation.
	sufficient := rep.TotalRequests >= 100 && durationSec >= 10 && !(rep.TotalErrors == rep.TotalRequests && rep.TotalRequests > 0)
	if !sufficient {
		dqStatus = DataQualityInsuff
		score = math.Min(score, 45)
	}
	level := confidenceLevel(score)
	if !sufficient && level == ConfidenceHighLabel {
		level = ConfidenceMediumLabel
		score = math.Min(score, 69)
	}
	if clamped && level == ConfidenceHighLabel {
		level = ConfidenceMediumLabel
		score = math.Min(score, 79)
	}

	summary := fmt.Sprintf("Evidence-based confidence %s (%.1f/100). Based on %d requests over %.2fs at %.2f rps with %.3f%% errors; %d structured factors evaluated.",
		level, score, rep.TotalRequests, durationSec, rps, errPct, len(factors))
	if len(missing) > 0 {
		summary += " Missing metrics are reported explicitly and treated separately from uncertainty."
	}

	return ConfidenceAssessment{
		Score:         round2(score),
		Level:         level,
		Summary:       summary,
		Factors:       factors,
		MissingData:   uniqueStrings(missing),
		Uncertainties: uniqueStrings(uncertainties),
		DataQuality:   dqStatus,
		Sufficient:    sufficient,
	}
}

func buildCapacityAssessment(rep report.Report, observedRPS, capacity, uncertainty, p50, p95, p99, errPct, durationSec float64, sufficient bool) CapacityAssessment {
	assess := CapacityAssessment{
		Status:        CapacitySufficient,
		ObservedRPS:   observedRPS,
		ObservedIsMax: false,
	}
	if observedRPS <= 0 {
		assess.Status = CapacityInsufficient
		assess.Uncertainty = "Observed throughput is not positive; sustainable capacity cannot be estimated."
		assess.Notes = append(assess.Notes, "INSUFFICIENT_DATA: no positive observed throughput evidence")
		return assess
	}

	// Degradation signals from available evidence.
	signals := []string{}
	if errPct >= 1 {
		assess.ErrorPressure = true
		signals = append(signals, fmt.Sprintf("error pressure detected (%.3f%% errors)", errPct))
	}
	if p50 > 0 && p99/p50 >= 4 {
		assess.LatencyDegradation = true
		signals = append(signals, fmt.Sprintf("latency degradation/tail spread signal (p99/p50=%.2f)", p99/p50))
	}
	if p95 > 0 && p99 > p95*1.8 {
		assess.SaturationObserved = true
		signals = append(signals, "saturation-like tail amplification signal (p99 materially above p95)")
	}
	assess.DegradationSignals = uniqueStrings(signals)

	// Insufficient evidence gate (P0): do not fabricate.
	if !sufficient || rep.TotalRequests < 100 || durationSec < 10 {
		assess.Status = CapacityInsufficient
		assess.Uncertainty = "Insufficient evidence to estimate sustainable capacity responsibly (sample size/duration/data quality)."
		assess.Notes = append(assess.Notes, "INSUFFICIENT_DATA: sustainable capacity estimate withheld; observed RPS is reported but never treated as maximum")
		return assess
	}
	if !finite(capacity) || capacity <= 0 {
		assess.Status = CapacityInsufficient
		assess.Uncertainty = "Capacity model could not produce a finite estimate from available evidence."
		assess.Notes = append(assess.Notes, "INSUFFICIENT_DATA: invalid or non-finite capacity derivation")
		return assess
	}

	// Sustainable capacity heuristic: start from modeled capacity, apply
	// degradation/error pressure penalties. This is an estimate, not a guarantee.
	penalty := 1.0
	if errPct >= 5 {
		penalty *= 0.80
	} else if errPct >= 1 {
		penalty *= 0.90
	} else if errPct > 0.1 {
		penalty *= 0.97
	}
	if p50 > 0 {
		ratio := p99 / p50
		if ratio >= 8 {
			penalty *= 0.85
		} else if ratio >= 4 {
			penalty *= 0.92
		}
	}
	if assess.SaturationObserved {
		penalty *= 0.93
	}
	penalty = clamp(penalty, 0.5, 1.0)

	sustainable := capacity * penalty
	// Never treat observed as max; sustainable may be above or below observed depending on evidence.
	low := sustainable * (1 - uncertainty)
	high := sustainable * (1 + math.Min(uncertainty*1.2, 0.8))
	if low > sustainable {
		low = sustainable * 0.9
	}
	if high < sustainable {
		high = sustainable * 1.1
	}
	// Keep interval sane and positive.
	low = math.Max(low, observedRPS*0.1)
	high = math.Max(high, sustainable)

	if assess.ErrorPressure || assess.LatencyDegradation || assess.SaturationObserved {
		assess.Status = CapacityDegraded
	}
	assess.SustainableRPS = &sustainable
	assess.SustainableInterval = &Interval{Low: round2(low), High: round2(high), Level: 0.95, Method: "heuristic evidence-based interval from model uncertainty and degradation signals"}
	assess.Uncertainty = fmt.Sprintf("Model-based estimate with %.1f%% relative uncertainty; adjusted for observed degradation/error/saturation signals when present.", clamp(uncertainty*100, 0, 100))
	assess.Notes = append(assess.Notes,
		"Observed RPS is measured evidence and is never treated as maximum capacity.",
		"Sustainable capacity is an estimate with uncertainty, not a guarantee.",
	)
	if penalty < 1.0 {
		assess.Notes = append(assess.Notes, fmt.Sprintf("Sustainability penalty applied (%.2fx) due to latency degradation/error pressure/saturation signals.", penalty))
	}
	return assess
}

func legacyConfidenceAssessment(m Model) ConfidenceAssessment {
	score := 40.0
	level := ConfidenceLowLabel
	switch m.Confidence {
	case ConfidenceHigh:
		score = 85
		level = ConfidenceHighLabel
	case ConfidenceMedium:
		score = 65
		level = ConfidenceMediumLabel
	}
	sufficient := level != ConfidenceLowLabel
	return ConfidenceAssessment{
		Score: score, Level: level, Sufficient: sufficient, DataQuality: ternaryStr(sufficient, DataQualityWarn, DataQualityInsuff),
		Summary:       "Legacy model upgraded in-memory; detailed evidence factors unavailable in v1 artifact.",
		Factors:       []EvidenceFactor{{Name: "legacy_artifact", Score: score, Weight: 1, Status: "WARN", Evidence: "v1 model without structured evidence", Impact: "Limited explainability", Uncertainty: "Upgraded legacy artifact"}},
		Uncertainties: []string{"Legacy artifact lacks structured evidence factors"},
	}
}

func legacyCapacityAssessment(m Model) CapacityAssessment {
	obs := m.Workload.RPS
	s := m.Curve.CapacityRPS
	low := m.Curve.CapacityLowRPS
	high := m.Curve.CapacityHighRPS
	if !finite(obs) || obs <= 0 {
		return CapacityAssessment{Status: CapacityInsufficient, ObservedRPS: 0, ObservedIsMax: false, Uncertainty: "Legacy artifact missing observed throughput", Notes: []string{"INSUFFICIENT_DATA"}}
	}
	if !finite(s) || s <= 0 {
		return CapacityAssessment{Status: CapacityInsufficient, ObservedRPS: obs, ObservedIsMax: false, Uncertainty: "Legacy artifact missing sustainable estimate", Notes: []string{"INSUFFICIENT_DATA"}}
	}
	return CapacityAssessment{
		Status: CapacityDegraded, ObservedRPS: obs, ObservedIsMax: false, SustainableRPS: &s,
		SustainableInterval: &Interval{Low: low, High: high, Method: "legacy interval"}, Uncertainty: "Upgraded from legacy model; evidence-based reassessment unavailable.",
		Notes: []string{"Observed RPS is never treated as maximum capacity."},
	}
}

type rangeScore struct{ lo, hi, score float64 }

func scoreFromRanges(v float64, ranges []rangeScore) float64 {
	for _, r := range ranges {
		if v >= r.lo && v < r.hi {
			return r.score
		}
	}
	if len(ranges) > 0 {
		return ranges[len(ranges)-1].score
	}
	return 0
}

func confidenceLevel(score float64) string {
	switch {
	case score >= 80:
		return ConfidenceHighLabel
	case score >= 55:
		return ConfidenceMediumLabel
	default:
		return ConfidenceLowLabel
	}
}

func timelineRPSCV(samples []metrics.TimelineSample) float64 {
	if len(samples) < 2 {
		return 0
	}
	// Convert cumulative timeline to per-interval RPS-like deltas if possible.
	vals := make([]float64, 0, len(samples))
	prevReq := uint64(0)
	prevSec := 0
	for i, s := range samples {
		sec := s.Second
		if sec <= 0 {
			sec = i + 1
		}
		dReq := float64(s.Requests - prevReq)
		dSec := float64(sec - prevSec)
		if i == 0 {
			// first sample may be cumulative from 0
			if dSec <= 0 {
				dSec = 1
			}
			vals = append(vals, dReq/dSec)
		} else if dSec > 0 && s.Requests >= prevReq {
			vals = append(vals, dReq/dSec)
		}
		prevReq = s.Requests
		prevSec = sec
	}
	if len(vals) < 2 {
		return 0
	}
	mean := 0.0
	for _, v := range vals {
		mean += v
	}
	mean /= float64(len(vals))
	if mean <= 0 {
		return 0
	}
	var sum float64
	for _, v := range vals {
		d := v - mean
		sum += d * d
	}
	std := math.Sqrt(sum / float64(len(vals)))
	return std / mean
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func ternaryStr(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }

// capacityUncertainty is a coarse, documented heuristic, not a confidence
// interval: it combines the standard error of a tail quantile (1/sqrt of the
// effective tail sample count), a short-run penalty, and a penalty for noisy
// runs. It is deliberately conservative because the alternatives imply a
// distribution the report does not carry.
func capacityUncertainty(requests uint64, durationSec, errPct float64) float64 {
	tail := math.Max(float64(requests)*tailFraction, 1)
	base := 1 / math.Sqrt(tail)
	runPenalty := 0.10 / math.Sqrt(math.Max(durationSec/60, 1))
	errPenalty := math.Min(errPct/100*0.5, 0.25)
	return clamp(base+runPenalty+errPenalty, minCapacityUncertainty, maxCapacityUncertainty)
}

// confidenceGrade maps run size, duration and noise onto a three-level grade.
// The thresholds are round numbers chosen so an operator can reason about them
// without a statistics background: a minute, ten thousand requests and one
// percent errors buys a "high".
func confidenceGrade(durationSec float64, requests uint64, errPct float64, clamped bool) Confidence {
	grade := ConfidenceLow
	switch {
	case durationSec >= 60 && requests >= 10_000 && errPct <= 1:
		grade = ConfidenceHigh
	case durationSec >= 20 && requests >= 1_000 && errPct <= 5:
		grade = ConfidenceMedium
	}
	// A clamp means the tail did not fit the assumed shape; the fit is still
	// usable but cannot deserve the top grade.
	if clamped && grade == ConfidenceHigh {
		grade = ConfidenceMedium
	}
	return grade
}

func reportName(rep report.Report) string {
	if rep.Name != "" {
		return rep.Name
	}
	return "unnamed"
}

func durationMS(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}

func finite(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0)
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
