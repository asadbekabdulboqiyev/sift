package hostxray

import (
	"math"
	"testing"
	"time"
)

func TestCorrelate_HandlesNaNInfSignals(t *testing.T) {
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	samples := []Sample{
		{Timestamp: base.Add(-2 * time.Second), CPU: CPUStats{Available: true, UtilizationPct: 90}, Mem: MemoryStats{Available: true, UsedPct: 10}, Source: SourceLinuxProc},
		{Timestamp: base.Add(-1 * time.Second), CPU: CPUStats{Available: true, UtilizationPct: 92}, Mem: MemoryStats{Available: true, UsedPct: 10}, Source: SourceLinuxProc},
		{Timestamp: base, CPU: CPUStats{Available: true, UtilizationPct: 95}, Mem: MemoryStats{Available: true, UsedPct: 10}, Source: SourceLinuxProc},
	}
	signals := []Signal{
		{Timestamp: base.Add(-1 * time.Second), P99Ms: math.NaN(), ErrorRate: math.Inf(1)},
		{Timestamp: base, P99Ms: 200, ErrorRate: 0.05},
		{Timestamp: base.Add(time.Second), P99Ms: 250, ErrorRate: 0.05},
	}
	// Must not panic or fabricate impossible correlations from NaN/Inf inputs.
	_ = Correlate(samples, signals, CorrelateOptions{Window: 5 * time.Second, MinOverlap: 1, MinSamples: 1})
}

func TestCorrelate_IgnoresNonFiniteSampleMetrics(t *testing.T) {
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	samples := []Sample{
		{Timestamp: base.Add(-2 * time.Second), CPU: CPUStats{Available: true, UtilizationPct: math.NaN()}, Source: SourceLinuxProc},
		{Timestamp: base.Add(-1 * time.Second), CPU: CPUStats{Available: true, UtilizationPct: math.Inf(1)}, Source: SourceLinuxProc},
		{Timestamp: base, CPU: CPUStats{Available: true, UtilizationPct: 50}, Source: SourceLinuxProc},
	}
	signals := []Signal{
		{Timestamp: base.Add(-1 * time.Second), P99Ms: 100},
		{Timestamp: base, P99Ms: 120},
	}
	ind := Correlate(samples, signals, CorrelateOptions{Window: 5 * time.Second, MinOverlap: 1, MinSamples: 1})
	// Non-finite CPU samples must not be treated as valid saturation evidence.
	for _, in := range ind {
		if in.ID == "hostxray.cpu-latency" {
			t.Fatalf("unexpected cpu-latency indicator from non-finite/low CPU evidence: %+v", in)
		}
	}
}
