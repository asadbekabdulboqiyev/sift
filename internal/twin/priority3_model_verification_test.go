package twin

import (
	"encoding/json"
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/metrics"
	"github.com/asadbekabdulboqiyev/sift/internal/report"
)

func deterministicReport(name string, requests, errors uint64, dur time.Duration, rps float64, p50, p95, p99, avg time.Duration, timeline []metrics.TimelineSample) report.Report {
	if dur <= 0 {
		dur = 60 * time.Second
	}
	if rps <= 0 && requests > 0 {
		rps = float64(requests) / dur.Seconds()
	}
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	errPct := 0.0
	if requests > 0 {
		errPct = float64(errors) / float64(requests) * 100
	}
	return report.Report{
		Name:          name,
		BaseURL:       "https://example.test",
		LoadProfile:   "constant-rps",
		StartedAt:     start,
		EndedAt:       start.Add(dur),
		Duration:      dur,
		TotalRequests: requests,
		TotalErrors:   errors,
		ErrorRatePct:  errPct,
		RPS:           rps,
		Overall:       report.StepReport{P50: p50, P95: p95, P99: p99, Avg: avg, Requests: requests, Errors: errors},
		Timeline:      timeline,
	}
}

func TestPriority3_DigitalTwinPredictionsAgainstHistoricalBenchmarks(t *testing.T) {
	// Deterministic synthetic "historical-like" benchmark dataset encoded in tests.
	baseModel, err := Fit(syntheticReport(), FitOptions{Producer: "priority3-test"})
	if err != nil {
		t.Fatalf("Fit benchmark model: %v", err)
	}
	basePred, err := Simulate(baseModel, openScenario(), 4242)
	if err != nil {
		t.Fatalf("Simulate benchmark prediction: %v", err)
	}
	actualSame := syntheticReport()
	actualSame.Name = "historical-benchmark-same"

	cmpSame := ComparePredictionToActual(basePred, actualSame)
	if cmpSame.ActualRPS != actualSame.RPS || cmpSame.ActualP95 <= 0 || cmpSame.ActualP99 <= 0 {
		t.Fatalf("comparison missing actual evidence: %+v", cmpSame)
	}
	if len(cmpSame.Notes) == 0 {
		t.Fatal("comparison should include explanatory notes")
	}
	statusOK, driftOK, noteOK := ComparisonValidationStatus(cmpSame)
	if statusOK != "OK" || driftOK != "NONE" {
		t.Fatalf("expected OK/NONE for aligned historical benchmark, got %s/%s (%s) cmp=%+v", statusOK, driftOK, noteOK, cmpSame)
	}

	// Out-of-domain / materially different actual to verify status behavior.
	actualWorse := actualSame
	actualWorse.Name = "historical-benchmark-degraded"
	actualWorse.RPS = actualSame.RPS * 0.4
	actualWorse.Overall.P95 = time.Duration(float64(actualSame.Overall.P95) * 3)
	actualWorse.Overall.P99 = time.Duration(float64(actualSame.Overall.P99) * 3)
	cmpBad := ComparePredictionToActual(basePred, actualWorse)
	statusBad, driftBad, _ := ComparisonValidationStatus(cmpBad)
	if statusBad == "OK" || driftBad != "DETECTED" {
		t.Fatalf("expected non-OK detected drift for degraded benchmark, got %s/%s cmp=%+v", statusBad, driftBad, cmpBad)
	}

	// Backtest flow on known paired data: perfect predictions produce zero error metrics.
	perfect := BacktestErrors([]float64{100, 120, 140, 160, 180}, []float64{100, 120, 140, 160, 180}, 90, 190)
	if perfect.Samples != 5 || perfect.MAE != 0 || perfect.RMSE != 0 || perfect.MAPE != 0 {
		t.Fatalf("perfect backtest should have zero error metrics: %+v", perfect)
	}
	if perfect.Drift != "NONE" || perfect.OutOfDomain {
		t.Fatalf("perfect in-domain backtest should not indicate drift/OOD: %+v", perfect)
	}
	st, dr := perfect.ValidationStatus()
	if st != "OK" || dr != "NONE" {
		t.Fatalf("perfect backtest status = %s/%s", st, dr)
	}

	// Known biased predictions: deterministic expected MAE/RMSE/MAPE.
	biasedPred := []float64{110, 130, 150}
	biasedAct := []float64{100, 100, 100}
	biased := BacktestErrors(biasedPred, biasedAct, 80, 160)
	wantMAE := (10.0 + 30.0 + 50.0) / 3.0
	wantRMSE := math.Sqrt((100.0 + 900.0 + 2500.0) / 3.0)
	wantMAPE := ((10.0 / 100.0) + (30.0 / 100.0) + (50.0 / 100.0)) / 3.0 * 100.0
	if math.Abs(biased.MAE-wantMAE) > 1e-9 || math.Abs(biased.RMSE-wantRMSE) > 1e-9 || math.Abs(biased.MAPE-wantMAPE) > 1e-9 {
		t.Fatalf("biased backtest metrics mismatch: got %+v want MAE=%v RMSE=%v MAPE=%v", biased, wantMAE, wantRMSE, wantMAPE)
	}
}

func TestPriority3_ConfidenceCalibrationSemantics(t *testing.T) {
	highRep := deterministicReport("high-evidence", 12000, 0, 90*time.Second, 200, 20*time.Millisecond, 40*time.Millisecond, 60*time.Millisecond, 25*time.Millisecond,
		[]metrics.TimelineSample{{Second: 1, Requests: 200}, {Second: 2, Requests: 400}, {Second: 3, Requests: 600}, {Second: 4, Requests: 800}})
	highModel, err := Fit(highRep, FitOptions{})
	if err != nil {
		t.Fatalf("Fit high evidence: %v", err)
	}
	if highModel.ConfidenceV2 == nil {
		t.Fatal("expected confidence assessment")
	}
	if !highModel.ConfidenceV2.Sufficient {
		t.Fatalf("expected sufficient evidence for strong benchmark: %+v", highModel.ConfidenceV2)
	}
	if highModel.ConfidenceV2.Level == ConfidenceHighLabel && !highModel.ConfidenceV2.Sufficient {
		t.Fatal("HIGH without sufficient evidence")
	}

	type tc struct {
		name         string
		rep          report.Report
		wantLevel    []string
		wantSuff     *bool
		wantDQ       []string
		mustNotHigh  bool
		missingCheck func(ConfidenceAssessment) bool
	}
	boolPtr := func(b bool) *bool { return &b }
	tests := []tc{
		{
			name:        "insufficient_sample_and_duration_low",
			rep:         deterministicReport("tiny", 20, 0, 2*time.Second, 10, 10*time.Millisecond, 20*time.Millisecond, 30*time.Millisecond, 12*time.Millisecond, nil),
			wantLevel:   []string{ConfidenceLowLabel},
			wantSuff:    boolPtr(false),
			wantDQ:      []string{DataQualityInsuff},
			mustNotHigh: true,
		},
		{
			name:        "medium_evidence_stability_missing_timeline_warn",
			rep:         deterministicReport("medium", 2000, 10, 30*time.Second, 66, 30*time.Millisecond, 70*time.Millisecond, 120*time.Millisecond, 40*time.Millisecond, nil),
			wantLevel:   []string{ConfidenceLowLabel, ConfidenceMediumLabel},
			mustNotHigh: true,
			missingCheck: func(c ConfidenceAssessment) bool {
				for _, m := range c.MissingData {
					if m == "timeline_samples" || m == "resource_cpu" {
						return true
					}
				}
				return false
			},
		},
		{
			name: "unstable_distribution_and_poor_data_quality",
			rep: func() report.Report {
				r := deterministicReport("unstable", 5000, 1500, 45*time.Second, 111, 10*time.Millisecond, 120*time.Millisecond, 600*time.Millisecond, 20*time.Millisecond,
					[]metrics.TimelineSample{{Second: 1, Requests: 20}, {Second: 2, Requests: 300}, {Second: 3, Requests: 40}, {Second: 4, Requests: 350}})
				r.ErrorRatePct = float64(r.TotalErrors) / float64(r.TotalRequests) * 100
				r.Overall.Errors = r.TotalErrors
				return r
			}(),
			wantLevel:   []string{ConfidenceLowLabel, ConfidenceMediumLabel},
			wantDQ:      []string{DataQualityWarn, DataQualityInsuff},
			mustNotHigh: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := Fit(tt.rep, FitOptions{})
			if err != nil {
				t.Fatalf("Fit: %v", err)
			}
			if m.ConfidenceV2 == nil {
				t.Fatal("missing confidence assessment")
			}
			c := *m.ConfidenceV2
			if c.Level == ConfidenceHighLabel && !c.Sufficient {
				t.Fatalf("HIGH assigned without sufficient evidence: %+v", c)
			}
			if tt.mustNotHigh && c.Level == ConfidenceHighLabel {
				t.Fatalf("expected non-HIGH confidence: %+v", c)
			}
			if len(tt.wantLevel) > 0 && !containsString(tt.wantLevel, c.Level) {
				t.Fatalf("level=%s want one of %v (score=%.2f sufficient=%v dq=%s)", c.Level, tt.wantLevel, c.Score, c.Sufficient, c.DataQuality)
			}
			if tt.wantSuff != nil && c.Sufficient != *tt.wantSuff {
				t.Fatalf("sufficient=%v want %v: %+v", c.Sufficient, *tt.wantSuff, c)
			}
			if len(tt.wantDQ) > 0 && !containsString(tt.wantDQ, c.DataQuality) {
				t.Fatalf("data quality=%s want one of %v: %+v", c.DataQuality, tt.wantDQ, c)
			}
			if tt.missingCheck != nil && !tt.missingCheck(c) {
				t.Fatalf("missing data/evidence semantics not reflected: %+v", c)
			}
			foundSample, foundDuration, foundDist, foundMissing, foundModelU, foundDQ := false, false, false, false, false, false
			for _, f := range c.Factors {
				switch f.Name {
				case "sample_size":
					foundSample = true
				case "duration":
					foundDuration = true
				case "distribution_stability":
					foundDist = true
				case "missing_metrics":
					foundMissing = true
				case "model_uncertainty":
					foundModelU = true
				case "data_quality":
					foundDQ = true
				}
			}
			if !foundSample || !foundDuration || !foundDist || !foundMissing || !foundModelU || !foundDQ {
				t.Fatalf("confidence factors must cover sample size, duration, distribution/stability, missing metrics, model uncertainty, data quality: %+v", c.Factors)
			}
		})
	}
}

func containsString(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func TestPriority3_BreachProbabilityAndWilsonIntervals(t *testing.T) {
	m := fittedModel(t)

	// NOT_CONFIGURED: no thresholds => no computable breach risk.
	unconf := Scenario{Name: "unconfigured", Mode: LoopOpen, TargetRPS: 300, DurationSeconds: 60, Iterations: 120, Seed: 99}
	resNC, err := Simulate(m, unconf, 99)
	if err != nil {
		t.Fatalf("simulate unconfigured: %v", err)
	}
	if resNC.Summary.ThresholdsConfigured || resNC.Summary.RiskLevel != "NOT_CONFIGURED" {
		t.Fatalf("expected NOT_CONFIGURED summary: %+v", resNC.Summary)
	}
	for name, b := range map[string]BreachAssessment{
		"p95": resNC.Summary.BreachP95, "p99": resNC.Summary.BreachP99,
		"error": resNC.Summary.BreachErrorRate, "throughput": resNC.Summary.BreachThroughput,
	} {
		if b.Status != "NOT_CONFIGURED" {
			t.Fatalf("%s breach assessment must be NOT_CONFIGURED when uncomputable: %+v", name, b)
		}
		if b.Probability != 0 || b.Breaches != 0 || b.CI.Method != "" || b.Threshold != 0 {
			t.Fatalf("%s uncomputable breach must not be reported as computed/low: %+v", name, b)
		}
		if b.Trials != unconf.Iterations {
			t.Fatalf("%s trials=%d want %d (run context) for NOT_CONFIGURED: %+v", name, b.Trials, unconf.Iterations, b)
		}
	}

	// Configured thresholds: per-iteration evaluation, Wilson CI bounds and trials.
	conf := openScenario()
	conf.TargetRPS = m.Curve.CapacityRPS * 0.95
	conf.SLAP99MS = m.Curve.Baseline.P99MS * 1.01 // tight, should often breach
	conf.SLAP95MS = m.Curve.Baseline.P95MS * 1.01
	conf.MaxErrorRatePct = 0.001
	conf.MinThroughputRPS = conf.TargetRPS * 0.99
	conf.Iterations = 200
	resC, err := Simulate(m, conf, 123)
	if err != nil {
		t.Fatalf("simulate configured: %v", err)
	}
	if !resC.Summary.ThresholdsConfigured {
		t.Fatal("expected thresholds configured")
	}
	checkBA := func(name string, b BreachAssessment, threshold float64, expectConfigured bool) {
		t.Helper()
		if !expectConfigured {
			if b.Status != "NOT_CONFIGURED" {
				t.Fatalf("%s should be NOT_CONFIGURED: %+v", name, b)
			}
			return
		}
		if b.Status != "OK" {
			t.Fatalf("%s should be OK/computable: %+v", name, b)
		}
		if b.Trials != conf.Iterations {
			t.Fatalf("%s trials=%d want %d", name, b.Trials, conf.Iterations)
		}
		if b.Breaches < 0 || b.Breaches > b.Trials {
			t.Fatalf("%s breaches out of range: %+v", name, b)
		}
		wantP := float64(b.Breaches) / float64(b.Trials)
		if math.Abs(b.Probability-wantP) > 1e-12 {
			t.Fatalf("%s probability=%v want %v", name, b.Probability, wantP)
		}
		if b.Threshold != threshold {
			t.Fatalf("%s threshold=%v want %v", name, b.Threshold, threshold)
		}
		if b.CI.Low < 0 || b.CI.High > 1 || b.CI.Low > b.CI.High {
			t.Fatalf("%s invalid CI bounds: %+v", name, b.CI)
		}
		if b.CI.Low > b.Probability+1e-12 || b.CI.High+1e-12 < b.Probability {
			t.Fatalf("%s CI should contain point estimate: %+v", name, b.CI)
		}
		if b.CI.Method == "" {
			t.Fatalf("%s CI method must be reported: %+v", name, b.CI)
		}
	}
	checkBA("p95", resC.Summary.BreachP95, conf.SLAP95MS, true)
	checkBA("p99", resC.Summary.BreachP99, conf.SLAP99MS, true)
	checkBA("error", resC.Summary.BreachErrorRate, conf.MaxErrorRatePct, true)
	checkBA("throughput", resC.Summary.BreachThroughput, conf.MinThroughputRPS, true)
	if resC.Summary.OverallBreachCI.Low < 0 || resC.Summary.OverallBreachCI.High > 1 || resC.Summary.OverallBreachCI.Low > resC.Summary.OverallBreachCI.High {
		t.Fatalf("overall CI invalid: %+v", resC.Summary.OverallBreachCI)
	}

	// Monotonic/reasonable: tightening p99 threshold should not reduce breach probability for same draws? Deterministic same seed+scenario except threshold.
	loose := conf
	loose.SLAP99MS = m.Curve.Baseline.P99MS * 10
	loose.Iterations = 200
	resLoose, err := Simulate(m, loose, 123)
	if err != nil {
		t.Fatalf("simulate loose: %v", err)
	}
	if resLoose.Summary.BreachP99.Probability > resC.Summary.BreachP99.Probability {
		t.Fatalf("looser p99 threshold should not breach more: loose=%v tight=%v", resLoose.Summary.BreachP99.Probability, resC.Summary.BreachP99.Probability)
	}

	// Wilson interval monotonic sanity: more breaches at same n => higher probability/CI center tendency.
	ci0 := wilsonInterval(0, 100, 0.95)
	ci50 := wilsonInterval(50, 100, 0.95)
	ci100 := wilsonInterval(100, 100, 0.95)
	for _, ci := range []Interval{ci0, ci50, ci100} {
		if ci.Low < 0 || ci.High > 1 || ci.Low > ci.High {
			t.Fatalf("wilson bounds invalid: %+v", ci)
		}
	}
	if !(ci0.High < ci50.High && ci50.Low < ci100.Low) {
		t.Fatalf("wilson intervals should move reasonably with breaches: 0=%+v 50=%+v 100=%+v", ci0, ci50, ci100)
	}
}

func TestPriority3_DeterministicSeededSimulations(t *testing.T) {
	m := fittedModel(t)
	sc := openScenario()
	sc.Iterations = 150
	r1, err := Simulate(m, sc, 777)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := Simulate(m, sc, 777)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r1, r2) {
		t.Fatal("same model+scenario+seed must produce identical results across runs")
	}
	if r1.SimulationSeed != 777 || !r1.Simulated || r1.EstimateType != "MODEL_ESTIMATE" {
		t.Fatalf("simulation should be labeled deterministic estimate: seed=%d simulated=%v type=%q", r1.SimulationSeed, r1.Simulated, r1.EstimateType)
	}
	r3, err := Simulate(m, sc, 778)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(r1.Summary, r3.Summary) && reflect.DeepEqual(r1.Iterations, r3.Iterations) {
		t.Fatal("different seeds should be able to differ")
	}
}

func TestPriority3_OutOfDistributionAndDriftHeuristics(t *testing.T) {
	tests := []struct {
		name         string
		pred, act    []float64
		lo, hi       float64
		wantDrift    []string
		wantOOD      bool
		wantBacktest string
	}{
		{"in_domain_no_drift", []float64{100, 105, 98, 102, 101}, []float64{100, 100, 100, 100, 100}, 90, 110, []string{"NONE"}, false, "OK"},
		{"drift_detected_high_mape", []float64{200, 220, 210, 230, 240}, []float64{100, 100, 100, 100, 100}, 90, 250, []string{"DETECTED"}, false, "DRIFT"},
		{"ood_detected", []float64{100, 100, 100}, []float64{50, 100, 250}, 90, 200, []string{"NONE", "DETECTED"}, true, "OOD"},
		{"insufficient_samples", nil, nil, 0, 0, []string{"UNKNOWN"}, false, "INSUFFICIENT_DATA"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bt := BacktestErrors(tt.pred, tt.act, tt.lo, tt.hi)
			if !containsString(tt.wantDrift, bt.Drift) {
				t.Fatalf("drift=%q want one of %v bt=%+v", bt.Drift, tt.wantDrift, bt)
			}
			if bt.OutOfDomain != tt.wantOOD {
				t.Fatalf("ood=%v want %v bt=%+v", bt.OutOfDomain, tt.wantOOD, bt)
			}
			st, dr := bt.ValidationStatus()
			if st != tt.wantBacktest {
				t.Fatalf("status=%q want %q (drift=%q) bt=%+v", st, tt.wantBacktest, dr, bt)
			}
			if tt.wantOOD && st != "OOD" {
				t.Fatalf("out-of-domain samples must yield OOD validation status, got %s/%s", st, dr)
			}
			if tt.wantBacktest == "DRIFT" && dr != "DETECTED" {
				t.Fatalf("drift status must be DETECTED when backtest drift detected: %s/%s", st, dr)
			}
		})
	}

	// Integration path: model validation record application and history.
	m := fittedModel(t)
	rec := ValidationRecord{
		Kind:     "backtest",
		Backtest: &BacktestMetrics{Samples: 5, MAPE: 45, Drift: "DETECTED", OutOfDomain: false},
	}
	m.ApplyValidationRecord(rec)
	if m.ModelInfo == nil || m.ModelInfo.BacktestStatus != "DRIFT" || m.ModelInfo.DriftStatus != "DETECTED" {
		t.Fatalf("ApplyValidationRecord should persist drift status: %+v", m.ModelInfo)
	}
	if m.ModelInfo.LastValidation == nil || len(m.ModelInfo.ValidationHistory) == 0 {
		t.Fatalf("validation record/history not persisted: %+v", m.ModelInfo)
	}
}

func TestPriority3_CapacityEstimatesKnownSaturationAndInsufficiency(t *testing.T) {
	// Known synthetic saturation/degradation characteristics.
	satRep := deterministicReport("saturated", 20000, 1200, 120*time.Second, 166.6, 20*time.Millisecond, 180*time.Millisecond, 900*time.Millisecond, 30*time.Millisecond,
		[]metrics.TimelineSample{{Second: 1, Requests: 160}, {Second: 2, Requests: 330}, {Second: 3, Requests: 500}, {Second: 4, Requests: 660}})
	satModel, err := Fit(satRep, FitOptions{})
	if err != nil {
		t.Fatalf("Fit saturated: %v", err)
	}
	if satModel.Capacity == nil {
		t.Fatal("missing capacity assessment")
	}
	if satModel.Capacity.ObservedIsMax {
		t.Fatal("observed capacity must never be treated as max")
	}
	if satModel.Capacity.Status == CapacityInsufficient {
		t.Fatalf("strong saturated dataset should yield sustainable estimate or degraded evidence, not fabricated insufficiency: %+v", satModel.Capacity)
	}
	if satModel.Capacity.SustainableRPS == nil || *satModel.Capacity.SustainableRPS <= 0 {
		t.Fatalf("sustainable capacity must be present with uncertainty: %+v", satModel.Capacity)
	}
	if satModel.Capacity.SustainableInterval == nil {
		t.Fatalf("uncertainty interval required: %+v", satModel.Capacity)
	}
	if satModel.Capacity.SustainableInterval.Low <= 0 || satModel.Capacity.SustainableInterval.High < satModel.Capacity.SustainableInterval.Low {
		t.Fatalf("invalid sustainable interval: %+v", satModel.Capacity.SustainableInterval)
	}
	// Degradation/saturation/error pressure should be reflected for this known dataset.
	if !satModel.Capacity.ErrorPressure || !satModel.Capacity.LatencyDegradation {
		t.Fatalf("expected degradation signals on saturated dataset: %+v", satModel.Capacity)
	}

	// Insufficient evidence dataset: must not fabricate sustainable capacity.
	insuffRep := deterministicReport("insufficient", 30, 0, 3*time.Second, 10, 15*time.Millisecond, 30*time.Millisecond, 40*time.Millisecond, 18*time.Millisecond, nil)
	insuffModel, err := Fit(insuffRep, FitOptions{})
	if err != nil {
		t.Fatalf("Fit insufficient: %v", err)
	}
	if insuffModel.Capacity == nil || insuffModel.Capacity.Status != CapacityInsufficient {
		t.Fatalf("expected INSUFFICIENT_DATA capacity: %+v", insuffModel.Capacity)
	}
	if insuffModel.Capacity.SustainableRPS != nil || insuffModel.Capacity.SustainableInterval != nil {
		t.Fatalf("must not fabricate sustainable value/interval when insufficient: %+v", insuffModel.Capacity)
	}
	if insuffModel.Capacity.ObservedRPS <= 0 {
		t.Fatal("observed RPS should still be reported")
	}
	if insuffModel.Capacity.ObservedIsMax {
		t.Fatal("observed must never be treated as max")
	}

	// Sanity: sustainable estimate differs from observed by model logic (not asserted equal).
	if satModel.Capacity.ObservedRPS == 0 {
		t.Fatal("expected observed RPS")
	}
	_ = math.Abs(*satModel.Capacity.SustainableRPS - satModel.Capacity.ObservedRPS)
}

func TestPriority3_SensitivityDeterminismAndLabeling(t *testing.T) {
	m := fittedModel(t)
	base, err := Preset("normal", m)
	if err != nil {
		t.Fatal(err)
	}
	s1, err := AnalyzeSensitivity(m, base, 31415)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := AnalyzeSensitivity(m, base, 31415)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s1, s2) {
		t.Fatal("sensitivity analysis must be deterministic for same model+base+seed")
	}
	if !s1.Simulated || len(s1.Points) == 0 {
		t.Fatalf("sensitivity report must be labeled and populated: %+v", s1)
	}
}

// Ensure confidence assessment JSON carries explicit semantics useful for audits.
func TestPriority3_ConfidenceAssessmentSerializable(t *testing.T) {
	m := fittedModel(t)
	b, err := json.Marshal(m.ConfidenceV2)
	if err != nil {
		t.Fatalf("marshal confidence: %v", err)
	}
	s := string(b)
	if s == "" || !containsAll(s, []string{"score", "level", "summary", "factors", "data_quality", "sufficient_evidence"}) {
		t.Fatalf("confidence assessment missing required semantic fields: %s", s)
	}
}

func containsAll(s string, parts []string) bool {
	for _, p := range parts {
		found := false
		for i := 0; i+len(p) <= len(s); i++ {
			if s[i:i+len(p)] == p {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func TestPriority3_BacktestValidationRecordLeakageMetadata(t *testing.T) {
	bt := BacktestErrors([]float64{1, 2, 3}, []float64{1, 2, 3}, 0.5, 3.5)
	st, dr := bt.ValidationStatus()
	if st != "OK" || dr != "NONE" {
		t.Fatalf("expected OK/NONE: %s/%s", st, dr)
	}
	// Compare status helper insufficient/large error behavior.
	cmp := PredictionVsActual{RPSErrorPct: 60, P95ErrorPct: 70, P99ErrorPct: 10}
	s, d, note := ComparisonValidationStatus(cmp)
	if s != "WARN" || d != "DETECTED" || note == "" {
		t.Fatalf("expected WARN/DETECTED comparison status: %s/%s %q", s, d, note)
	}
	cmp2 := PredictionVsActual{RPSErrorPct: math.NaN(), P95ErrorPct: math.NaN(), P99ErrorPct: math.NaN()}
	s2, d2, _ := ComparisonValidationStatus(cmp2)
	if s2 != "INSUFFICIENT_DATA" || d2 != "UNKNOWN" {
		t.Fatalf("expected insufficient comparison status for non-comparable metrics: %s/%s", s2, d2)
	}
	cmp3 := PredictionVsActual{}
	s3, d3, _ := ComparisonValidationStatus(cmp3)
	if s3 != "OK" || d3 != "NONE" {
		t.Fatalf("zero-error comparison should be OK/NONE by current semantics: %s/%s", s3, d3)
	}
	_ = bt
}
