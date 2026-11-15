package hostxray

import (
	"testing"
	"time"
)

func TestDeriveResourceEvidence_StandardizedMetadataAndStatuses(t *testing.T) {
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	samples := []Sample{
		{Timestamp: base, CPU: CPUStats{UtilizationPct: 40, Available: true}, Mem: MemoryStats{UsedPct: 50, Available: true}},
		{Timestamp: base.Add(2 * time.Second), CPU: CPUStats{UtilizationPct: 60, Available: true}, Mem: MemoryStats{UsedPct: 54, Available: true}},
	}
	ev := DeriveResourceEvidence(samples, Capabilities{ProcStat: true, ProcMemInfo: true, ProcNetDev: true})
	if ev.SchemaVersion == "" || ev.Source == "" {
		t.Fatalf("expected schema/source metadata: %+v", ev)
	}
	if ev.SampleCount != 2 || ev.ObservedWindowStart == "" || ev.ObservedWindowEnd == "" || ev.ObservedAt == "" {
		t.Fatalf("expected observation window metadata: %+v", ev)
	}
	for _, name := range []string{"cpu_utilization_pct", "memory_utilization_pct", "network_utilization", "active_connections", "server_response_time_ms", "memory_growth_pct"} {
		m, ok := ev.Metrics[name]
		if !ok {
			t.Fatalf("missing metric %s", name)
		}
		if m.Name != name || m.Status == "" || m.Unit == "" || m.Source == "" {
			t.Fatalf("metric %s missing standardized fields: %+v", name, m)
		}
		if m.Status != ResourceStatusAvailable && m.Reason == "" {
			t.Fatalf("non-available metric %s must have explicit reason: %+v", name, m)
		}
		if m.ObservedWindowStart == "" || m.ObservedWindowEnd == "" {
			t.Fatalf("metric %s missing observation window: %+v", name, m)
		}
	}
	if ev.Metrics["memory_growth_pct"].Status != ResourceStatusAvailable {
		t.Fatalf("memory growth expected available with >=2 samples: %+v", ev.Metrics["memory_growth_pct"])
	}
	if ev.Metrics["network_utilization"].Status != ResourceStatusUnavailable {
		t.Fatalf("network utilization must be unavailable without capacity: %+v", ev.Metrics["network_utilization"])
	}
}

func TestDeriveResourceEvidence_MemoryGrowthInsufficientWithSingleMemorySample(t *testing.T) {
	samples := []Sample{{Timestamp: time.Now().UTC(), Mem: MemoryStats{UsedPct: 50, Available: true}}}
	ev := DeriveResourceEvidence(samples, Capabilities{ProcMemInfo: true})
	mg := ev.Metrics["memory_growth_pct"]
	if mg.Status != ResourceStatusInsufficientData {
		t.Fatalf("want insufficient_data, got %+v", mg)
	}
	if mg.Reason == "" || mg.Unit == "" || mg.Source == "" {
		t.Fatalf("insufficient_data metric must have explicit reason/unit/source: %+v", mg)
	}
}
