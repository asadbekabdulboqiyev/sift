package coordinator

import (
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/config"
	distproto "github.com/asadbekabdulboqiyev/sift/internal/dist/proto"
	"github.com/asadbekabdulboqiyev/sift/internal/report"
)

func TestReportFromProtoTiming_UnsetTimestampsNotEpoch(t *testing.T) {
	r := ReportFromProto(&distproto.Report{DurationMs: 1500})
	if !r.StartedAt.IsZero() || !r.EndedAt.IsZero() {
		t.Fatalf("expected unset timestamps, got %s..%s", r.StartedAt, r.EndedAt)
	}
	if r.Duration != 1500*time.Millisecond {
		t.Fatalf("duration=%s want 1.5s", r.Duration)
	}
}

func TestReportFromProtoTiming_NormalizesEndFromStartAndDuration(t *testing.T) {
	start := time.Now().Add(-5 * time.Second).Truncate(time.Millisecond)
	r := ReportFromProto(&distproto.Report{
		StartedAt:  start.UnixMilli(),
		EndedAt:    start.Add(999 * time.Millisecond).UnixMilli(), // inconsistent/ignored in favor of duration
		DurationMs: 2500,
	})
	if !r.StartedAt.Equal(start) {
		t.Fatalf("started_at=%s want %s", r.StartedAt, start)
	}
	if got := r.EndedAt.Sub(r.StartedAt); got != r.Duration {
		t.Fatalf("ended-started=%s want duration=%s", got, r.Duration)
	}
	if err := r.ValidateTimestamps(); err != nil {
		t.Fatalf("ValidateTimestamps: %v", err)
	}
}

func TestReportFromProtoTiming_InfersStartFromEndAndDuration(t *testing.T) {
	end := time.Now().Truncate(time.Millisecond)
	r := ReportFromProto(&distproto.Report{EndedAt: end.UnixMilli(), DurationMs: 1200})
	if r.EndedAt.IsZero() || r.StartedAt.IsZero() {
		t.Fatalf("expected inferred bounds, got %s..%s", r.StartedAt, r.EndedAt)
	}
	if got := r.EndedAt.Sub(r.StartedAt); got != r.Duration {
		t.Fatalf("ended-started=%s want duration=%s", got, r.Duration)
	}
	if err := r.ValidateTimestamps(); err != nil {
		t.Fatalf("ValidateTimestamps: %v", err)
	}
}

func TestMergeReportsTiming_NormalizesWhenStartKnownEndMissing(t *testing.T) {
	start := time.Now().Add(-3 * time.Second).Truncate(time.Millisecond)
	r1 := &report.Report{Name: "r", StartedAt: start, Duration: 1500 * time.Millisecond, TotalRequests: 10}
	r2 := &report.Report{Name: "r", StartedAt: start, Duration: 900 * time.Millisecond, TotalRequests: 5}
	merged := MergeReports(&config.Scenario{}, []*report.Report{r1, r2})
	if merged.StartedAt.IsZero() || merged.EndedAt.IsZero() {
		t.Fatalf("expected normalized timestamps, got %s..%s", merged.StartedAt, merged.EndedAt)
	}
	if merged.Duration != 1500*time.Millisecond {
		t.Fatalf("duration=%s want 1.5s", merged.Duration)
	}
	if got := merged.EndedAt.Sub(merged.StartedAt); got != merged.Duration {
		t.Fatalf("ended-started=%s want %s", got, merged.Duration)
	}
	if err := merged.ValidateTimestamps(); err != nil {
		t.Fatalf("ValidateTimestamps: %v", err)
	}
}

func TestMergeReportsTiming_InfersStartWhenOnlyEndAndDurationKnown(t *testing.T) {
	end := time.Now().Truncate(time.Millisecond)
	r1 := &report.Report{Name: "r", EndedAt: end, Duration: 2 * time.Second, TotalRequests: 10}
	merged := MergeReports(&config.Scenario{}, []*report.Report{r1})
	if merged.StartedAt.IsZero() || merged.EndedAt.IsZero() {
		t.Fatalf("expected inferred timestamps, got %s..%s", merged.StartedAt, merged.EndedAt)
	}
	if merged.Duration != 2*time.Second {
		t.Fatalf("duration=%s want 2s", merged.Duration)
	}
	if err := merged.ValidateTimestamps(); err != nil {
		t.Fatalf("ValidateTimestamps: %v", err)
	}
}
