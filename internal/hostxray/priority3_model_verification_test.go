package hostxray

import (
	"math"
	"testing"
	"time"
)

func TestPriority3_DeriveResourceEvidenceNoFabrication(t *testing.T) {
	// Unsupported metrics must never be fabricated as available values.
	ev := DeriveResourceEvidence(nil, Capabilities{})
	unsupported := []string{"network_utilization", "active_connections", "server_response_time_ms"}
	for _, name := range unsupported {
		m, ok := ev.Metrics[name]
		if !ok {
			t.Fatalf("missing metric %s", name)
		}
		if m.Status == ResourceStatusAvailable || m.Value != nil {
			t.Fatalf("%s must not be fabricated without evidence: %+v", name, m)
		}
		if m.Status != ResourceStatusUnavailable {
			t.Fatalf("%s should be explicitly unavailable when not derivable: %+v", name, m)
		}
		if m.Reason == "" {
			t.Fatalf("%s should explain unavailability: %+v", name, m)
		}
	}
	mg := ev.Metrics["memory_growth_pct"]
	if mg.Status != ResourceStatusInsufficientData {
		t.Fatalf("memory growth without sufficient samples must be insufficient_data: %+v", mg)
	}
	if mg.Value != nil {
		t.Fatalf("memory growth value must not be fabricated: %+v", mg)
	}
}

func TestPriority3_DeriveResourceEvidenceKnownDatasetCharacteristics(t *testing.T) {
	base := time.Unix(1700000000, 0).UTC()
	samples := []Sample{
		{Timestamp: base, CPU: CPUStats{UtilizationPct: 20, Available: true}, Mem: MemoryStats{UsedPct: 40, Available: true}},
		{Timestamp: base.Add(10 * time.Second), CPU: CPUStats{UtilizationPct: 60, Available: true}, Mem: MemoryStats{UsedPct: 55, Available: true}},
		{Timestamp: base.Add(20 * time.Second), CPU: CPUStats{UtilizationPct: 40, Available: true}, Mem: MemoryStats{UsedPct: 46, Available: true}},
	}
	ev := DeriveResourceEvidence(samples, Capabilities{ProcStat: true, ProcMemInfo: true, ProcNetDev: true})
	cpu := ev.Metrics["cpu_utilization_pct"]
	if cpu.Status != ResourceStatusAvailable || cpu.Value == nil || math.Abs(*cpu.Value-40) > 1e-9 {
		t.Fatalf("cpu average mismatch: %+v", cpu)
	}
	mem := ev.Metrics["memory_utilization_pct"]
	wantMemAvg := (40.0 + 55.0 + 46.0) / 3.0
	if mem.Status != ResourceStatusAvailable || mem.Value == nil || math.Abs(*mem.Value-wantMemAvg) > 1e-9 {
		t.Fatalf("memory average mismatch: %+v want %v", mem, wantMemAvg)
	}
	mg := ev.Metrics["memory_growth_pct"]
	if mg.Status != ResourceStatusAvailable || mg.Value == nil {
		t.Fatalf("memory growth should be derivable from >=2 samples: %+v", mg)
	}
	if math.Abs(*mg.Value-(46.0-40.0)) > 1e-9 { // first->last available memory sample delta
		t.Fatalf("memory growth delta mismatch: %+v", mg)
	}
	// Network utilization % still unavailable without link capacity even if counters capability exists.
	if ev.Metrics["network_utilization"].Status != ResourceStatusUnavailable || ev.Metrics["network_utilization"].Value != nil {
		t.Fatalf("network utilization must remain unavailable (not fabricated): %+v", ev.Metrics["network_utilization"])
	}
}

func TestPriority3_DeriveResourceEvidenceMemoryGrowthInsufficientTemporalSeparation(t *testing.T) {
	ts := time.Unix(1700000000, 0).UTC()
	samples := []Sample{
		{Timestamp: ts, Mem: MemoryStats{UsedPct: 40, Available: true}},
		{Timestamp: ts, Mem: MemoryStats{UsedPct: 42, Available: true}},
	}
	ev := DeriveResourceEvidence(samples, Capabilities{ProcMemInfo: true})
	mg := ev.Metrics["memory_growth_pct"]
	if mg.Status != ResourceStatusInsufficientData || mg.Value != nil {
		t.Fatalf("memory growth needs temporal separation: %+v", mg)
	}
}

func TestPriority3_DeriveResourceEvidencePartialCapabilities(t *testing.T) {
	ev := DeriveResourceEvidence([]Sample{{Timestamp: time.Now(), CPU: CPUStats{Available: false}, Mem: MemoryStats{Available: false}}}, Capabilities{ProcStat: false, ProcMemInfo: false, ProcNetDev: false})
	for _, name := range []string{"cpu_utilization_pct", "memory_utilization_pct", "network_utilization"} {
		if ev.Metrics[name].Status != ResourceStatusUnavailable {
			t.Fatalf("%s should be unavailable without capabilities/data: %+v", name, ev.Metrics[name])
		}
	}
	if len(ev.Notes) == 0 {
		t.Fatal("derivation should include explanatory notes")
	}
}
