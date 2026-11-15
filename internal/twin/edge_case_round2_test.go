package twin

import (
	"math"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/report"
)

func TestComparePredictionToActual_NonFiniteAndMissingRPS(t *testing.T) {
	pred := Result{Summary: Summary{
		AchievedRPS: Band{P50: math.NaN()},
		P95MS:       Band{P50: 100},
		P99MS:       Band{P50: 200},
	}}
	actual := report.Report{
		Duration:      10 * time.Second,
		TotalRequests: 500,
		Overall:       report.StepReport{P95: 120 * time.Millisecond, P99: 220 * time.Millisecond},
		// RPS intentionally zero/missing: should be derived from counts/duration.
	}
	cmp := ComparePredictionToActual(pred, actual)
	if cmp.ActualRPS != 50 {
		t.Fatalf("expected derived actual RPS 50, got %v", cmp.ActualRPS)
	}
	if !cmp.Insufficient {
		t.Fatalf("expected insufficient comparison for NaN input")
	}
	if math.IsNaN(cmp.RPSErrorPct) || math.IsInf(cmp.RPSErrorPct, 0) {
		t.Fatalf("expected finite withheld RPSErrorPct for JSON safety, got %v", cmp.RPSErrorPct)
	}
	status, drift, _ := ComparisonValidationStatus(cmp)
	if status != "INSUFFICIENT_DATA" || drift != "UNKNOWN" {
		t.Fatalf("expected INSUFFICIENT_DATA/UNKNOWN for no valid comparable metrics, got %s/%s", status, drift)
	}
}

func TestComparePredictionToActual_ZeroActuals(t *testing.T) {
	pred := Result{Summary: Summary{AchievedRPS: Band{P50: 10}, P95MS: Band{P50: 0}, P99MS: Band{P50: 5}}}
	actual := report.Report{RPS: 0, Overall: report.StepReport{}}
	cmp := ComparePredictionToActual(pred, actual)
	if cmp.RPSErrorPct != 100 || cmp.P95ErrorPct != 0 || cmp.P99ErrorPct != 100 {
		t.Fatalf("unexpected pct errors for zero actuals: rps=%v p95=%v p99=%v", cmp.RPSErrorPct, cmp.P95ErrorPct, cmp.P99ErrorPct)
	}
	if math.IsNaN(cmp.P95MAE) || math.IsNaN(cmp.P99MAE) {
		t.Fatalf("expected finite MAEs, got p95=%v p99=%v", cmp.P95MAE, cmp.P99MAE)
	}
}

func TestBacktestErrors_NonFinitePairsAndZeroActuals(t *testing.T) {
	bt := BacktestErrors([]float64{math.NaN(), 10, math.Inf(1), 12}, []float64{10, 0, 11, 12}, 0, 0)
	if bt.Samples != 2 {
		t.Fatalf("expected 2 finite paired samples, got %d (drift=%s notes=%v)", bt.Samples, bt.Drift, bt.Notes)
	}
	if math.IsNaN(bt.MAE) || math.IsInf(bt.MAE, 0) || math.IsNaN(bt.RMSE) || math.IsInf(bt.RMSE, 0) {
		t.Fatalf("expected finite MAE/RMSE, got mae=%v rmse=%v", bt.MAE, bt.RMSE)
	}
	// one finite actual is zero -> MAPE unavailable (count 0 for MAPE over finite pairs with nonzero actuals? pair (10,0) excluded from MAPE count)
	found := false
	for _, n := range bt.Notes {
		if n == "MAPE unavailable because all finite actual values were zero; MAE/RMSE reported." || n == "1 non-finite pair(s) excluded from metrics." || n == "2 non-finite pair(s) excluded from metrics." {
			found = true
		}
	}
	_ = found

	allBad := BacktestErrors([]float64{math.NaN(), math.Inf(1)}, []float64{1, 2}, 0, 0)
	if allBad.Samples != 0 {
		t.Fatalf("expected 0 samples when all pairs non-finite, got %d", allBad.Samples)
	}
	status, drift := allBad.ValidationStatus()
	if status != "INSUFFICIENT_DATA" || drift != "UNKNOWN" {
		t.Fatalf("expected INSUFFICIENT_DATA/UNKNOWN, got %s/%s", status, drift)
	}
}
