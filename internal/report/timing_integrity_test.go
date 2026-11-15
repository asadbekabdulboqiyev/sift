package report

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/config"
	"github.com/asadbekabdulboqiyev/sift/internal/metrics"
)

func TestBuildReportTimingConsistency(t *testing.T) {
	tel := metrics.NewTelemetry()
	step := metrics.NewStepStats("req")
	step.Record(5*time.Millisecond, 200, "")
	tel.AddStep(step)
	tel.Overall.Record(5*time.Millisecond, 200, "")
	time.Sleep(20 * time.Millisecond)
	tel.Finish()

	sc := &config.Scenario{Name: "timing", BaseURL: "http://example.test", Profile: config.Profile{Type: config.ProfileSteady}}
	r := Build(tel, sc)

	if r.Duration <= 0 {
		t.Fatalf("duration must be positive, got %s", r.Duration)
	}
	if r.StartedAt.IsZero() || r.EndedAt.IsZero() {
		t.Fatalf("timestamps must be set: started=%v ended=%v", r.StartedAt, r.EndedAt)
	}
	if got := r.EndedAt.Sub(r.StartedAt); got != r.Duration {
		t.Fatalf("ended_at-started_at=%s want duration=%s", got, r.Duration)
	}
	if err := r.ValidateTimestamps(); err != nil {
		t.Fatalf("ValidateTimestamps: %v", err)
	}
	// Duration must reflect actual elapsed (monotonic capture), not be rounded to zero.
	if r.Duration < 10*time.Millisecond {
		t.Fatalf("duration %s too small; expected actual elapsed >= 10ms", r.Duration)
	}
}

func TestBuildReportTimingJSONRoundTripConsistency(t *testing.T) {
	tel := metrics.NewTelemetry()
	step := metrics.NewStepStats("req")
	step.Record(1*time.Millisecond, 200, "")
	tel.AddStep(step)
	tel.Overall.Record(1*time.Millisecond, 200, "")
	time.Sleep(15 * time.Millisecond)
	tel.Finish()

	r := Build(tel, &config.Scenario{Name: "rt", BaseURL: "http://x", Profile: config.Profile{Type: config.ProfileSteady}})
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got Report
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Duration != r.Duration {
		t.Fatalf("duration changed after JSON round trip: got %s want %s", got.Duration, r.Duration)
	}
	if !got.StartedAt.Equal(r.StartedAt) || !got.EndedAt.Equal(r.EndedAt) {
		t.Fatalf("timestamps changed after JSON round trip: got %s..%s want %s..%s", got.StartedAt, got.EndedAt, r.StartedAt, r.EndedAt)
	}
	if err := got.ValidateTimestamps(); err != nil {
		t.Fatalf("round-tripped report invalid timestamps: %v", err)
	}
}

func TestReportValidateTimestampsRejectsInconsistency(t *testing.T) {
	now := time.Now()
	r := Report{StartedAt: now, EndedAt: now.Add(2 * time.Second), Duration: 1 * time.Second}
	if err := r.ValidateTimestamps(); err == nil {
		t.Fatal("expected inconsistency error")
	}
}

func TestReportValidateTimestampsRejectsNegativeDuration(t *testing.T) {
	now := time.Now()
	r := Report{StartedAt: now, EndedAt: now, Duration: -time.Millisecond}
	if err := r.ValidateTimestamps(); err == nil {
		t.Fatal("expected negative duration error")
	}
}

func TestBuildReportInterruptedRunUsesActualElapsed(t *testing.T) {
	// Simulate an interrupted/early-finished run: telemetry finished before a
	// nominal long duration would elapse, so Duration must reflect actual elapsed.
	tel := metrics.NewTelemetry()
	step := metrics.NewStepStats("req")
	step.Record(2*time.Millisecond, 200, "")
	tel.AddStep(step)
	tel.Overall.Record(2*time.Millisecond, 200, "")
	time.Sleep(25 * time.Millisecond)
	tel.Finish()

	r := Build(tel, &config.Scenario{Name: "interrupted", BaseURL: "http://x", Profile: config.Profile{Type: config.ProfileSteady, Duration: 30}})
	if r.Duration >= 30*time.Second {
		t.Fatalf("interrupted/short run must not report planned duration, got %s", r.Duration)
	}
	if r.Duration < 10*time.Millisecond {
		t.Fatalf("expected actual elapsed duration, got %s", r.Duration)
	}
	if err := r.ValidateTimestamps(); err != nil {
		t.Fatalf("timestamps invalid for interrupted run: %v", err)
	}
}
