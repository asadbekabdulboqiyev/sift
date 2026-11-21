package metrics

// aggregate_test.go — checks that the O(1) aggregate counters stay exact when
// samples are recorded before and after AddStep, including concurrent records.

import (
	"sync"
	"testing"
	"time"
)

func TestTelemetryAggregateCountsBeforeAndAfterAddStep(t *testing.T) {
	tel := NewTelemetry()
	step := NewStepStats("step")

	step.Record(time.Millisecond, 200, "")
	step.Record(time.Millisecond, 500, "boom")
	tel.AddStep(step)

	if got := tel.TotalRequests(); got != 2 {
		t.Fatalf("requests after AddStep = %d, want 2", got)
	}
	if got := tel.TotalErrors(); got != 1 {
		t.Fatalf("errors after AddStep = %d, want 1", got)
	}

	step.Record(time.Millisecond, 200, "")
	if got := tel.TotalRequests(); got != 3 {
		t.Fatalf("requests after wired success = %d, want 3", got)
	}
	if got := tel.TotalErrors(); got != 1 {
		t.Fatalf("errors after wired success = %d, want 1", got)
	}

	step.Record(time.Millisecond, 500, "boom")
	if got := tel.TotalRequests(); got != 4 {
		t.Fatalf("requests after wired error = %d, want 4", got)
	}
	if got := tel.TotalErrors(); got != 2 {
		t.Fatalf("errors after wired error = %d, want 2", got)
	}
}

func TestTelemetryAggregateExcludesOverall(t *testing.T) {
	tel := NewTelemetry()
	tel.Overall.Record(time.Millisecond, 200, "")
	tel.Overall.Record(time.Millisecond, 500, "boom")

	if got := tel.TotalRequests(); got != 0 {
		t.Errorf("requests = %d, want 0 (overall is not a step)", got)
	}
	if got := tel.TotalErrors(); got != 0 {
		t.Errorf("errors = %d, want 0 (overall is not a step)", got)
	}
}

func TestTelemetryAddStepDuplicateDoesNotDoubleCount(t *testing.T) {
	tel := NewTelemetry()
	step := NewStepStats("duplicate")
	step.Record(time.Millisecond, 200, "")
	tel.AddStep(step)
	tel.AddStep(step)

	if got := tel.TotalRequests(); got != 1 {
		t.Errorf("requests = %d, want 1 after duplicate AddStep", got)
	}
}

func TestTelemetryAggregateConcurrentRecordAndAddStep(t *testing.T) {
	tel := NewTelemetry()
	step := NewStepStats("concurrent")
	const total = 1000

	for i := 0; i < 10; i++ {
		step.Record(time.Millisecond, 200, "")
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 10; i < total; i++ {
			step.Record(time.Millisecond, 200, "")
		}
	}()
	tel.AddStep(step)
	wg.Wait()

	if got := tel.TotalRequests(); got != total {
		t.Errorf("requests = %d, want %d", got, total)
	}
	if got := tel.TotalErrors(); got != 0 {
		t.Errorf("errors = %d, want 0", got)
	}
}
