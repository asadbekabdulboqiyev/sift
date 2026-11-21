package twin

import (
	"math"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/report"
)

func TestConfidenceAssessmentEvidenceBased(t *testing.T) {
	m := fittedModel(t)
	if m.ConfidenceV2 == nil {
		t.Fatal("expected confidence assessment")
	}
	if m.ConfidenceV2.Score < 0 || m.ConfidenceV2.Score > 100 {
		t.Fatalf("score out of range: %v", m.ConfidenceV2.Score)
	}
	if m.ConfidenceV2.Level == "" || m.ConfidenceV2.Summary == "" {
		t.Fatalf("missing level/summary: %+v", m.ConfidenceV2)
	}
	if len(m.ConfidenceV2.Factors) == 0 {
		t.Fatal("expected structured factors")
	}
	if m.ConfidenceV2.Level == ConfidenceHighLabel && !m.ConfidenceV2.Sufficient {
		t.Fatal("HIGH confidence must not be assigned without sufficient evidence")
	}
	// possible if downgraded, but our label should match score semantics in general
}

func TestCapacityInsufficientDataAndObservedNotMax(t *testing.T) {
	rep := syntheticReport()
	rep.Duration = 2 * time.Second
	rep.TotalRequests = 20
	rep.TotalErrors = 0
	rep.RPS = 10
	rep.Overall = report.StepReport{P50: 10 * time.Millisecond, P95: 20 * time.Millisecond, P99: 30 * time.Millisecond, Avg: 12 * time.Millisecond, Requests: 20}
	m, err := Fit(rep, FitOptions{})
	if err != nil {
		t.Fatalf("Fit: %v", err)
	}
	if m.Capacity == nil {
		t.Fatal("expected capacity assessment")
	}
	if m.Capacity.ObservedIsMax {
		t.Fatal("observed capacity must never be treated as max")
	}
	if m.Capacity.Status != CapacityInsufficient {
		t.Fatalf("expected INSUFFICIENT_DATA, got %+v", m.Capacity)
	}
	if m.Capacity.SustainableRPS != nil {
		t.Fatal("must not fabricate sustainable capacity when insufficient")
	}
	if m.Capacity.ObservedRPS <= 0 {
		t.Fatal("observed RPS should be reported")
	}
}

func TestBreachProbabilityNotConfiguredAndCI(t *testing.T) {
	m := fittedModel(t)
	sc := openScenario()
	sc.SLAP99MS = 0
	sc.MaxErrorRatePct = 0
	sc.SLAP95MS = 0
	sc.MinThroughputRPS = 0
	sc.Iterations = 120
	res, err := Simulate(m, sc, 7)
	if err != nil {
		t.Fatalf("Simulate: %v", err)
	}
	if res.Summary.ThresholdsConfigured {
		t.Fatal("thresholds should be not configured")
	}
	if res.Summary.RiskLevel != "NOT_CONFIGURED" {
		t.Fatalf("risk must be NOT_CONFIGURED, got %q", res.Summary.RiskLevel)
	}
	if res.Summary.BreachP99.Status != "NOT_CONFIGURED" {
		t.Fatalf("p99 breach status = %q", res.Summary.BreachP99.Status)
	}

	sc2 := openScenario()
	sc2.SLAP99MS = m.Calibration.TargetP99MS
	sc2.Iterations = 200
	res2, err := Simulate(m, sc2, 7)
	if err != nil {
		t.Fatalf("Simulate configured: %v", err)
	}
	if !res2.Summary.ThresholdsConfigured {
		t.Fatal("expected configured thresholds")
	}
	if res2.Summary.OverallBreachCI.High < res2.Summary.OverallBreachCI.Low {
		t.Fatalf("invalid CI: %+v", res2.Summary.OverallBreachCI)
	}
	if res2.Summary.BreachP99.Status != "OK" || res2.Summary.BreachP99.CI.Method == "" {
		t.Fatalf("expected configured breach assessment with CI: %+v", res2.Summary.BreachP99)
	}
}

func TestRequiredScenarioPresetsAndSensitivity(t *testing.T) {
	m := fittedModel(t)
	for _, name := range RequiredScenarioPresetNames() {
		sc, err := Preset(name, m)
		if err != nil {
			t.Fatalf("preset %s: %v", name, err)
		}
		if sc.Name == "" {
			t.Fatalf("preset %s missing name", name)
		}
		res, err := Simulate(m, sc, 42)
		if err != nil {
			t.Fatalf("simulate %s: %v", name, err)
		}
		if !res.Simulated || res.EstimateType == "" {
			t.Fatalf("result must be labeled as simulated estimate: %+v", res)
		}
	}
	base, _ := Preset("normal", m)
	sens, err := AnalyzeSensitivity(m, base, 42)
	if err != nil {
		t.Fatalf("AnalyzeSensitivity: %v", err)
	}
	if len(sens.Points) == 0 {
		t.Fatal("expected sensitivity points")
	}
}

func TestPredictionVsActualAndBacktest(t *testing.T) {
	m := fittedModel(t)
	sc := openScenario()
	sc.TargetRPS = m.Workload.RPS
	res, err := Simulate(m, sc, 1)
	if err != nil {
		t.Fatal(err)
	}
	actual := syntheticReport()
	cmp := ComparePredictionToActual(res, actual)
	if math.IsNaN(cmp.P99ErrorPct) || cmp.ActualP99 <= 0 {
		t.Fatalf("invalid comparison: %+v", cmp)
	}
	bt := BacktestErrors([]float64{10, 12, 11}, []float64{10, 13, 10}, 5, 20)
	if bt.Samples != 3 || bt.MAE < 0 || bt.RMSE < 0 || bt.MAPE < 0 {
		t.Fatalf("invalid backtest: %+v", bt)
	}
}
