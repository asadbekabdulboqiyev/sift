package twin

import (
	"fmt"
	"math"
	"sort"

	"github.com/asadbekabdulboqiyev/sift/internal/report"
)

// PredictionVsActual compares model/simulation predictions to an observed report.
type PredictionVsActual struct {
	PredictedRPS float64 `json:"predicted_rps,omitempty"`
	ActualRPS    float64 `json:"actual_rps,omitempty"`
	RPSErrorPct  float64 `json:"rps_error_pct,omitempty"`

	PredictedP95 float64 `json:"predicted_p95_ms,omitempty"`
	ActualP95    float64 `json:"actual_p95_ms,omitempty"`
	P95ErrorPct  float64 `json:"p95_error_pct,omitempty"`
	P95MAE       float64 `json:"p95_mae_ms,omitempty"`

	PredictedP99 float64 `json:"predicted_p99_ms,omitempty"`
	ActualP99    float64 `json:"actual_p99_ms,omitempty"`
	P99ErrorPct  float64 `json:"p99_error_pct,omitempty"`
	P99MAE       float64 `json:"p99_mae_ms,omitempty"`

	Insufficient bool     `json:"insufficient,omitempty"`
	Notes        []string `json:"notes,omitempty"`
}

// ComparePredictionToActual computes prediction-vs-actual metrics for one run.
func ComparePredictionToActual(pred Result, actual report.Report) PredictionVsActual {
	out := PredictionVsActual{
		PredictedRPS: pred.Summary.AchievedRPS.P50,
		ActualRPS:    actual.RPS,
		PredictedP95: pred.Summary.P95MS.P50,
		ActualP95:    durationMS(actual.Overall.P95),
		PredictedP99: pred.Summary.P99MS.P50,
		ActualP99:    durationMS(actual.Overall.P99),
		Notes:        []string{"Comparison uses median simulated estimates (model-based) against measured report evidence."},
	}
	// Prefer derived actual RPS when report RPS is missing/invalid but request counts are valid.
	if !isFinitePositive(out.ActualRPS) && actual.TotalRequests > 0 {
		if sec := actual.Duration.Seconds(); isFinitePositive(sec) {
			out.ActualRPS = float64(actual.TotalRequests) / sec
			out.Notes = append(out.Notes, "Actual RPS derived from total_requests/duration because report rps was missing or invalid.")
		}
	}

	valid := true
	for name, v := range map[string]float64{
		"predicted_rps": out.PredictedRPS, "actual_rps": out.ActualRPS,
		"predicted_p95_ms": out.PredictedP95, "actual_p95_ms": out.ActualP95,
		"predicted_p99_ms": out.PredictedP99, "actual_p99_ms": out.ActualP99,
	} {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			out.Notes = append(out.Notes, fmt.Sprintf("Non-finite comparison input (%s); error metrics unavailable for affected fields.", name))
			valid = false
		}
	}
	if valid {
		out.RPSErrorPct = pctError(out.PredictedRPS, out.ActualRPS)
		out.P95ErrorPct = pctError(out.PredictedP95, out.ActualP95)
		out.P99ErrorPct = pctError(out.PredictedP99, out.ActualP99)
		out.P95MAE = math.Abs(out.PredictedP95 - out.ActualP95)
		out.P99MAE = math.Abs(out.PredictedP99 - out.ActualP99)
	} else {
		out.Insufficient = true
		out.PredictedRPS = sanitizeFinite(out.PredictedRPS)
		out.ActualRPS = sanitizeFinite(out.ActualRPS)
		out.PredictedP95 = sanitizeFinite(out.PredictedP95)
		out.ActualP95 = sanitizeFinite(out.ActualP95)
		out.PredictedP99 = sanitizeFinite(out.PredictedP99)
		out.ActualP99 = sanitizeFinite(out.ActualP99)
		out.RPSErrorPct = 0
		out.P95ErrorPct = 0
		out.P99ErrorPct = 0
		out.P95MAE = 0
		out.P99MAE = 0
		out.Notes = append(out.Notes, "INSUFFICIENT_DATA: prediction-vs-actual error metrics withheld because one or more inputs were non-finite.")
	}
	return out
}

// BacktestMetrics summarizes validation/backtesting across observations.
type BacktestMetrics struct {
	Samples     int      `json:"samples"`
	MAE         float64  `json:"mae"`
	RMSE        float64  `json:"rmse"`
	MAPE        float64  `json:"mape_pct"`
	Calibration string   `json:"calibration,omitempty"`
	Drift       string   `json:"drift_status,omitempty"` // NONE/DETECTED/UNKNOWN
	OutOfDomain bool     `json:"out_of_domain"`
	Notes       []string `json:"notes,omitempty"`
}

// BacktestErrors computes MAE/RMSE/MAPE and simple drift/OOD indicators.
func BacktestErrors(predicted, actual []float64, modelRangeLow, modelRangeHigh float64) BacktestMetrics {
	n := len(predicted)
	if n == 0 || len(actual) != n {
		return BacktestMetrics{Samples: 0, Drift: "UNKNOWN", Notes: []string{"No valid paired prediction/actual samples for backtesting."}}
	}
	var sumAbs, sumSq, sumAPE float64
	ood := false
	mapeCount := 0
	validPairs := 0
	for i := 0; i < n; i++ {
		p, a := predicted[i], actual[i]
		if math.IsNaN(p) || math.IsInf(p, 0) || math.IsNaN(a) || math.IsInf(a, 0) {
			continue
		}
		validPairs++
		e := p - a
		sumAbs += math.Abs(e)
		sumSq += e * e
		if a != 0 {
			sumAPE += math.Abs(e/a) * 100
			mapeCount++
		}
		if (modelRangeLow > 0 && a < modelRangeLow*0.8) || (modelRangeHigh > 0 && a > modelRangeHigh*1.2) {
			ood = true
		}
	}
	if validPairs == 0 {
		return BacktestMetrics{Samples: 0, Drift: "UNKNOWN", Notes: []string{"No finite paired prediction/actual samples for backtesting; metrics withheld (INSUFFICIENT_DATA)."}}
	}
	mae := sumAbs / float64(validPairs)
	rmse := math.Sqrt(sumSq / float64(validPairs))
	mape := 0.0
	if mapeCount > 0 {
		mape = sumAPE / float64(mapeCount)
	}
	drift := "NONE"
	if mape > 30 || rmse > mae*2.5 {
		drift = "DETECTED"
	}
	cal := "uncalibrated-insufficient-samples"
	if validPairs >= 5 {
		cal = fmt.Sprintf("heuristic (n=%d): MAPE %.2f%%, RMSE %.4f", validPairs, mape, rmse)
	}
	notes := []string{
		"Backtesting computed on provided paired samples; no leakage assumed by caller (use train/validation split).",
		"Drift/OOD detection is heuristic and should be reviewed with domain context.",
	}
	if validPairs < n {
		notes = append(notes, fmt.Sprintf("%d non-finite pair(s) excluded from metrics.", n-validPairs))
	}
	if mapeCount == 0 {
		notes = append(notes, "MAPE unavailable because all finite actual values were zero; MAE/RMSE reported.")
	}
	if ood {
		notes = append(notes, "Out-of-domain observations detected relative to model range.")
	}
	return BacktestMetrics{Samples: validPairs, MAE: mae, RMSE: rmse, MAPE: mape, Calibration: cal, Drift: drift, OutOfDomain: ood, Notes: notes}
}

// ValidationStatus derives canonical model validation/backtest status from
// backtest metrics (additive helper for P1 integration).
func (bt BacktestMetrics) ValidationStatus() (backtestStatus, driftStatus string) {
	if bt.Samples <= 0 {
		return "INSUFFICIENT_DATA", "UNKNOWN"
	}
	driftStatus = bt.Drift
	if driftStatus == "" {
		driftStatus = "UNKNOWN"
	}
	switch {
	case bt.OutOfDomain:
		return "OOD", "DETECTED"
	case driftStatus == "DETECTED":
		return "DRIFT", "DETECTED"
	case driftStatus == "NONE":
		return "OK", "NONE"
	default:
		return "WARN", driftStatus
	}
}

// ComparisonValidationStatus derives a coarse validation status from one
// prediction-vs-actual comparison. This is heuristic and must not be treated as
// a guarantee; it provides canonical status updates for model metadata.
func ComparisonValidationStatus(cmp PredictionVsActual) (backtestStatus, driftStatus, note string) {
	if cmp.Insufficient {
		return "INSUFFICIENT_DATA", "UNKNOWN", "Comparison had no valid comparable metrics."
	}
	errs := []float64{cmp.RPSErrorPct, cmp.P95ErrorPct, cmp.P99ErrorPct}
	valid := 0
	bad := 0
	for _, e := range errs {
		if math.IsNaN(e) || math.IsInf(e, 0) {
			continue
		}
		valid++
		if e > 40 {
			bad++
		}
	}
	if valid == 0 {
		return "INSUFFICIENT_DATA", "UNKNOWN", "Comparison had no valid comparable metrics."
	}
	if bad >= 2 {
		return "WARN", "DETECTED", fmt.Sprintf("Large prediction-vs-actual error observed (RPS %.2f%%, p95 %.2f%%, p99 %.2f%%).", cmp.RPSErrorPct, cmp.P95ErrorPct, cmp.P99ErrorPct)
	}
	return "OK", "NONE", fmt.Sprintf("Prediction-vs-actual comparison recorded (RPS %.2f%%, p95 %.2f%%, p99 %.2f%% error).", cmp.RPSErrorPct, cmp.P95ErrorPct, cmp.P99ErrorPct)
}

// DatasetRef identifies a dataset used in validation/backtesting provenance.
// Fields are optional and caller-provided; presence does not by itself prove
// no-leakage without an explicit enforced split/leakage proof.
type DatasetRef struct {
	Kind      string `json:"kind,omitempty"` // e.g. "report","pairs","historical","manifest"
	Path      string `json:"path,omitempty"`
	ID        string `json:"id,omitempty"`
	Hash      string `json:"hash,omitempty"`
	Records   int    `json:"records,omitempty"`
	TimeStart string `json:"time_start,omitempty"`
	TimeEnd   string `json:"time_end,omitempty"`
	Notes     string `json:"notes,omitempty"`
}

// SplitSpec describes how train/validation separation was intended/performed.
// Enforcement/proof must be represented separately in LeakageGuard and, when
// possible, verified against dataset manifests/provenance.
type SplitSpec struct {
	Strategy           string   `json:"strategy,omitempty"` // explicit|time_cutoff|ratio_holdout|kfold_fold|unknown
	TrainDataset       string   `json:"train_dataset,omitempty"`
	ValidationSet      string   `json:"validation_dataset,omitempty"`
	TrainIDs           []string `json:"train_ids,omitempty"`
	ValidationIDs      []string `json:"validation_ids,omitempty"`
	TrainEnd           string   `json:"train_end,omitempty"`
	ValidationStart    string   `json:"validation_start,omitempty"`
	BoundaryOrderField string   `json:"boundary_order_field,omitempty"`
	Frozen             *bool    `json:"frozen,omitempty"`
	Notes              string   `json:"notes,omitempty"`
}

// LeakageGuard records whether no-leakage was enforced/proven for validation.
// Status/verification fields are additive; Proven is only meaningful when
// backed by actual provenance/ID verification (not metadata-only claims).
type LeakageGuard struct {
	Enforced           bool     `json:"enforced"`
	Proven             bool     `json:"proven"`
	Verified           bool     `json:"verified,omitempty"`
	Status             string   `json:"status,omitempty"` // verified_no_leakage|leakage_detected|unverified
	Method             string   `json:"method,omitempty"`
	OverlapCount       *int     `json:"overlap_count,omitempty"`
	Checks             []string `json:"checks,omitempty"`
	Reason             string   `json:"reason,omitempty"`
	ManifestPath       string   `json:"manifest_path,omitempty"`
	ManifestSchema     string   `json:"manifest_schema_version,omitempty"`
	ManifestKind       string   `json:"manifest_kind,omitempty"`
	VerificationSource string   `json:"verification_source,omitempty"` // manifest|metadata_unverified|none
}

// ValidationRecord stores validation/backtesting provenance, metrics and status.
// It is additive and intended for canonical traceability; callers must not claim
// no-leakage unless LeakageGuard indicates it was verified/proven by actual
// provenance or manifest checks.
type ValidationRecord struct {
	SchemaVersion      string               `json:"schema_version,omitempty"`
	Kind               string               `json:"kind,omitempty"` // compare|backtest
	GeneratedAt        string               `json:"generated_at,omitempty"`
	ModelVersion       string               `json:"model_version,omitempty"`
	Parameters         map[string]any       `json:"parameters,omitempty"`
	Assumptions        []string             `json:"assumptions,omitempty"`
	Dataset            *DatasetRef          `json:"dataset,omitempty"`
	Split              *SplitSpec           `json:"split,omitempty"`
	Leakage            *LeakageGuard        `json:"leakage,omitempty"`
	Manifest           *DatasetManifest     `json:"manifest,omitempty"`
	ManifestPath       string               `json:"manifest_path,omitempty"`
	VerificationStatus string               `json:"verification_status,omitempty"`
	Verification       *LeakageVerification `json:"verification,omitempty"`
	Backtest           *BacktestMetrics     `json:"backtest,omitempty"`
	Comparison         *PredictionVsActual  `json:"comparison,omitempty"`
	DriftStatus        string               `json:"drift_status,omitempty"`
	BacktestStatus     string               `json:"backtest_status,omitempty"`
	ValidationNotes    []string             `json:"validation_notes,omitempty"`
}

// ResourceMetricEvidence is an explainable, non-fabricated resource metric assessment.
// Non-available metrics must carry explicit status and reason; unit/source are
// included when known. Observation timestamps/window metadata is included only
// when available from samples/derivation (never fabricated).
type ResourceMetricEvidence struct {
	Name                   string   `json:"name"`
	Status                 string   `json:"status"` // available|unavailable|insufficient_data
	Value                  *float64 `json:"value,omitempty"`
	Unit                   string   `json:"unit,omitempty"`
	Source                 string   `json:"source,omitempty"`
	Reason                 string   `json:"reason,omitempty"`
	Notes                  []string `json:"notes,omitempty"`
	ObservedAt             string   `json:"observed_at,omitempty"`
	ObservedWindowStart    string   `json:"observed_window_start,omitempty"`
	ObservedWindowEnd      string   `json:"observed_window_end,omitempty"`
	ObservationSampleCount int      `json:"observation_sample_count,omitempty"`
}

// ResourceAvailability labels resource monitoring evidence availability.
type ResourceAvailability struct {
	Available           bool                              `json:"available"`
	Metrics             []string                          `json:"metrics,omitempty"`
	Missing             []string                          `json:"missing,omitempty"`
	Source              string                            `json:"source,omitempty"`
	Notes               []string                          `json:"notes,omitempty"`
	Values              map[string]float64                `json:"values,omitempty"`
	MetricsDetail       map[string]ResourceMetricEvidence `json:"metrics_detail,omitempty"`
	SchemaVersion       string                            `json:"schema_version,omitempty"`
	SampleCount         int                               `json:"sample_count,omitempty"`
	ObservedAt          string                            `json:"observed_at,omitempty"`
	ObservedWindowStart string                            `json:"observed_window_start,omitempty"`
	ObservedWindowEnd   string                            `json:"observed_window_end,omitempty"`
}

// AssessResourceMonitoring reports supported/unavailable resource metrics clearly.
// Backward-compatible wrapper; for memory growth support use AssessResourceMonitoringExtended.
func AssessResourceMonitoring(cpu, mem, net, conns, respTime *float64) ResourceAvailability {
	return AssessResourceMonitoringExtended(cpu, mem, net, conns, respTime, nil)
}

// AssessResourceMonitoringExtended reports supported/unavailable resource metrics
// including memory growth. Unavailable metrics are explicitly labeled and never
// fabricated.
func AssessResourceMonitoringExtended(cpu, mem, net, conns, respTime, memGrowth *float64) ResourceAvailability {
	ra := ResourceAvailability{Values: map[string]float64{}, MetricsDetail: map[string]ResourceMetricEvidence{}, Source: "manual/provided", SchemaVersion: "sift.resource-evidence/v1"}
	unitFor := func(name string) string {
		switch name {
		case "connections":
			return "count"
		case "server_response_time":
			return "ms"
		default:
			return "percent"
		}
	}
	add := func(name string, v *float64) {
		d := ResourceMetricEvidence{Name: name, Unit: unitFor(name), Source: "manual/provided"}
		if v == nil || math.IsNaN(*v) || math.IsInf(*v, 0) {
			ra.Missing = append(ra.Missing, name)
			d.Status = "unavailable"
			d.Reason = "not provided"
			ra.MetricsDetail[name] = d
			return
		}
		ra.Available = true
		ra.Metrics = append(ra.Metrics, name)
		ra.Values[name] = *v
		vv := *v
		d.Status = "available"
		d.Value = &vv
		ra.MetricsDetail[name] = d
	}
	add("cpu", cpu)
	add("memory", mem)
	add("network", net)
	add("connections", conns)
	add("server_response_time", respTime)
	add("memory_growth", memGrowth)
	sort.Strings(ra.Metrics)
	sort.Strings(ra.Missing)
	if !ra.Available {
		ra.Notes = append(ra.Notes, "No direct resource monitoring metrics available in this context; unavailable metrics are explicitly labeled.")
	} else if len(ra.Missing) > 0 {
		ra.Notes = append(ra.Notes, "Partial resource monitoring available; missing metrics labeled explicitly.")
	}
	return ra
}

func pctError(pred, actual float64) float64 {
	if math.IsNaN(pred) || math.IsInf(pred, 0) || math.IsNaN(actual) || math.IsInf(actual, 0) {
		return math.NaN()
	}
	if actual == 0 {
		if pred == 0 {
			return 0
		}
		return 100
	}
	return math.Abs(pred-actual) / math.Abs(actual) * 100
}

func isFinitePositive(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0) && v > 0
}

func sanitizeFinite(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0
	}
	return v
}
