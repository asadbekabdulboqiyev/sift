package hostxray

import (
	"testing"
	"time"
)

func TestDeriveResourceEvidence_InsufficientSamples(t *testing.T) {
	ev := DeriveResourceEvidence(nil, Capabilities{})
	if ev.SampleCount != 0 {
		t.Fatalf("sample count = %d, want 0", ev.SampleCount)
	}
	// CPU/memory/network/connections/server_response_time should be unavailable without samples
	for _, name := range []string{"cpu_utilization_pct", "memory_utilization_pct", "network_utilization", "active_connections", "server_response_time_ms"} {
		m, ok := ev.Metrics[name]
		if !ok {
			t.Fatalf("missing metric %s", name)
		}
		if m.Status == ResourceStatusAvailable {
			t.Fatalf("metric %s should not be available without samples", name)
		}
	}
	mg := ev.Metrics["memory_growth_pct"]
	if mg.Status != ResourceStatusInsufficientData {
		t.Fatalf("memory_growth status = %s, want insufficient_data", mg.Status)
	}
}

func TestDeriveResourceEvidence_CPUAndMemoryAverages(t *testing.T) {
	base := time.Now()
	samples := []Sample{
		{Timestamp: base, CPU: CPUStats{UtilizationPct: 40, Available: true}, Mem: MemoryStats{UsedPct: 50, Available: true}},
		{Timestamp: base.Add(2 * time.Second), CPU: CPUStats{UtilizationPct: 60, Available: true}, Mem: MemoryStats{UsedPct: 54, Available: true}},
	}
	ev := DeriveResourceEvidence(samples, Capabilities{ProcStat: true, ProcMemInfo: true, ProcNetDev: true})
	cpu := ev.Metrics["cpu_utilization_pct"]
	if cpu.Status != ResourceStatusAvailable || cpu.Value == nil || *cpu.Value != 50 {
		t.Fatalf("cpu = %+v, want available 50", cpu)
	}
	mem := ev.Metrics["memory_utilization_pct"]
	if mem.Status != ResourceStatusAvailable || mem.Value == nil || *mem.Value != 52 {
		t.Fatalf("memory = %+v, want available 52", mem)
	}
	mg := ev.Metrics["memory_growth_pct"]
	if mg.Status != ResourceStatusAvailable || mg.Value == nil {
		t.Fatalf("memory growth should be available with >=2 samples: %+v", mg)
	}
	if *mg.Value != 4 { // 54-50 percentage points
		t.Fatalf("memory growth = %v, want 4", *mg.Value)
	}
	if mg.Unit != "percentage_points" {
		t.Fatalf("memory growth unit = %q, want percentage_points", mg.Unit)
	}
	// unsupported by hostxray aggregate sampler
	if ev.Metrics["active_connections"].Status != ResourceStatusUnavailable {
		t.Fatalf("active_connections should be unavailable")
	}
	if ev.Metrics["server_response_time_ms"].Status != ResourceStatusUnavailable {
		t.Fatalf("server_response_time_ms should be unavailable")
	}
	if ev.Metrics["network_utilization"].Status != ResourceStatusUnavailable {
		t.Fatalf("network_utilization should be unavailable without capacity")
	}
}

func TestDeriveResourceEvidence_MemoryGrowthInsufficientSingleSample(t *testing.T) {
	samples := []Sample{{Timestamp: time.Now(), Mem: MemoryStats{UsedPct: 50, Available: true}}}
	ev := DeriveResourceEvidence(samples, Capabilities{ProcMemInfo: true})
	if ev.Metrics["memory_growth_pct"].Status != ResourceStatusInsufficientData {
		t.Fatalf("memory growth with 1 sample should be insufficient_data, got %+v", ev.Metrics["memory_growth_pct"])
	}
}
