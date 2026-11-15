package hostxray

import (
	"fmt"
	"math"
	"sort"
	"time"
)

// ResourceMetricStatus describes availability of a resource metric.
type ResourceMetricStatus string

const (
	ResourceStatusAvailable        ResourceMetricStatus = "available"
	ResourceStatusUnavailable      ResourceMetricStatus = "unavailable"
	ResourceStatusInsufficientData ResourceMetricStatus = "insufficient_data"
)

// ResourceMetricEvidence is an explainable, non-fabricated metric assessment.
// Status/reason/unit/source are explicit for every non-available metric when
// known; timestamps/window metadata is included only when observed from samples
// or derivation inputs (never fabricated).
type ResourceMetricEvidence struct {
	Name                   string               `json:"name"`
	Status                 ResourceMetricStatus `json:"status"`
	Value                  *float64             `json:"value,omitempty"`
	Unit                   string               `json:"unit,omitempty"`
	Source                 string               `json:"source,omitempty"`
	Reason                 string               `json:"reason,omitempty"`
	Notes                  []string             `json:"notes,omitempty"`
	ObservedAt             string               `json:"observed_at,omitempty"`
	ObservedWindowStart    string               `json:"observed_window_start,omitempty"`
	ObservedWindowEnd      string               `json:"observed_window_end,omitempty"`
	ObservationSampleCount int                  `json:"observation_sample_count,omitempty"`
}

// DerivedResourceEvidence is the result of deriving resource evidence from
// hostxray samples/capabilities. Unsupported or insufficient metrics are
// explicitly labeled and never fabricated.
type DerivedResourceEvidence struct {
	SchemaVersion       string                            `json:"schema_version,omitempty"`
	Source              string                            `json:"source,omitempty"`
	Metrics             map[string]ResourceMetricEvidence `json:"metrics"`
	SampleCount         int                               `json:"sample_count"`
	ObservedWindowStart string                            `json:"observed_window_start,omitempty"`
	ObservedWindowEnd   string                            `json:"observed_window_end,omitempty"`
	ObservedAt          string                            `json:"observed_at,omitempty"`
	Notes               []string                          `json:"notes,omitempty"`
}

// DeriveResourceEvidence derives supported resource metrics from hostxray
// samples and capabilities. It is pure over provided inputs and does not read
// host state or fabricate values.
func DeriveResourceEvidence(samples []Sample, caps Capabilities) DerivedResourceEvidence {
	out := DerivedResourceEvidence{
		SchemaVersion: "sift.resource-evidence/v1",
		Source:        "hostxray-derived",
		Metrics:       make(map[string]ResourceMetricEvidence),
		SampleCount:   len(samples),
	}
	// Defaults: unavailable unless supported/derived.
	set := func(m ResourceMetricEvidence) { out.Metrics[m.Name] = m }

	sorted := append([]Sample(nil), samples...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Timestamp.Before(sorted[j].Timestamp) })
	if len(sorted) > 0 {
		if !sorted[0].Timestamp.IsZero() {
			out.ObservedWindowStart = sorted[0].Timestamp.UTC().Format(time.RFC3339Nano)
		}
		if !sorted[len(sorted)-1].Timestamp.IsZero() {
			out.ObservedWindowEnd = sorted[len(sorted)-1].Timestamp.UTC().Format(time.RFC3339Nano)
			out.ObservedAt = out.ObservedWindowEnd
		}
	}
	windowStart, windowEnd, observedAt := out.ObservedWindowStart, out.ObservedWindowEnd, out.ObservedAt
	withObs := func(m ResourceMetricEvidence, n int) ResourceMetricEvidence {
		m.ObservedWindowStart = windowStart
		m.ObservedWindowEnd = windowEnd
		m.ObservedAt = observedAt
		if n > 0 {
			m.ObservationSampleCount = n
		}
		return m
	}

	// CPU utilization (%): average of available sample CPU utilization.
	cpuVals := make([]float64, 0, len(sorted))
	for _, s := range sorted {
		if s.CPU.Available && isFinite(s.CPU.UtilizationPct) {
			cpuVals = append(cpuVals, s.CPU.UtilizationPct)
		}
	}
	if len(cpuVals) > 0 {
		v := avg(cpuVals)
		set(withObs(ResourceMetricEvidence{Name: "cpu_utilization_pct", Status: ResourceStatusAvailable, Value: &v, Unit: "percent", Source: "hostxray.proc", Notes: []string{fmt.Sprintf("average over %d sample(s)", len(cpuVals))}}, len(cpuVals)))
	} else {
		reason := "cpu utilization unavailable in provided hostxray samples/capabilities"
		if !caps.ProcStat {
			reason = "cpu counters unavailable (proc/stat not available)"
		}
		set(withObs(ResourceMetricEvidence{Name: "cpu_utilization_pct", Status: ResourceStatusUnavailable, Unit: "percent", Source: "hostxray", Reason: reason}, len(sorted)))
	}

	// Memory utilization (% used): average of available sample memory used percent.
	memVals := make([]float64, 0, len(sorted))
	for _, s := range sorted {
		if s.Mem.Available && isFinite(s.Mem.UsedPct) {
			memVals = append(memVals, s.Mem.UsedPct)
		}
	}
	if len(memVals) > 0 {
		v := avg(memVals)
		set(withObs(ResourceMetricEvidence{Name: "memory_utilization_pct", Status: ResourceStatusAvailable, Value: &v, Unit: "percent", Source: "hostxray.proc", Notes: []string{fmt.Sprintf("average used percent over %d memory sample(s)", len(memVals))}}, len(memVals)))
	} else {
		reason := "memory utilization unavailable in provided hostxray samples/capabilities"
		if !caps.ProcMemInfo {
			reason = "memory counters unavailable (proc/meminfo not available)"
		}
		set(withObs(ResourceMetricEvidence{Name: "memory_utilization_pct", Status: ResourceStatusUnavailable, Unit: "percent", Source: "hostxray", Reason: reason}, len(sorted)))
	}

	// Network utilization: hostxray provides byte counters, not link capacity;
	// utilization percent is not defensibly derivable without capacity. Mark unavailable.
	if caps.ProcNetDev {
		set(withObs(ResourceMetricEvidence{Name: "network_utilization", Status: ResourceStatusUnavailable, Unit: "percent", Source: "hostxray.proc", Reason: "network utilization percent unavailable without link capacity; aggregate counters alone are insufficient (not fabricated)"}, len(sorted)))
	} else {
		set(withObs(ResourceMetricEvidence{Name: "network_utilization", Status: ResourceStatusUnavailable, Unit: "percent", Source: "hostxray", Reason: "network counters unavailable (proc/net/dev not available)"}, len(sorted)))
	}

	// Active connections: not collected by aggregate hostxray sampler.
	set(withObs(ResourceMetricEvidence{Name: "active_connections", Status: ResourceStatusUnavailable, Unit: "count", Source: "hostxray", Reason: "active connection count not collected by hostxray aggregate sampler (no per-connection data)"}, len(sorted)))

	// Server response time: not measured by hostxray (host-side sampler).
	set(withObs(ResourceMetricEvidence{Name: "server_response_time_ms", Status: ResourceStatusUnavailable, Unit: "ms", Source: "hostxray", Reason: "server-side response time not measured by hostxray; provide measured server/client response evidence explicitly if available"}, len(sorted)))

	// Memory growth: defensible only as delta of used percent between first/last
	// available memory samples when >=2 samples exist.
	memSamples := make([]Sample, 0, len(sorted))
	for _, s := range sorted {
		if s.Mem.Available && isFinite(s.Mem.UsedPct) {
			memSamples = append(memSamples, s)
		}
	}
	if len(memSamples) >= 2 {
		first := memSamples[0]
		last := memSamples[len(memSamples)-1]
		if last.Timestamp.After(first.Timestamp) {
			v := last.Mem.UsedPct - first.Mem.UsedPct
			notes := []string{fmt.Sprintf("delta of memory used%% between first and last of %d memory sample(s)", len(memSamples)), "indicates change over observation window, not a guaranteed leak or capacity limit"}
			mg := withObs(ResourceMetricEvidence{Name: "memory_growth_pct", Status: ResourceStatusAvailable, Value: &v, Unit: "percentage_points", Source: "derived:hostxray.mem_used_pct_delta", Notes: notes}, len(memSamples))
			if !first.Timestamp.IsZero() {
				mg.ObservedWindowStart = first.Timestamp.UTC().Format(time.RFC3339Nano)
			}
			if !last.Timestamp.IsZero() {
				mg.ObservedWindowEnd = last.Timestamp.UTC().Format(time.RFC3339Nano)
				mg.ObservedAt = mg.ObservedWindowEnd
			}
			set(mg)
		} else {
			set(withObs(ResourceMetricEvidence{Name: "memory_growth_pct", Status: ResourceStatusInsufficientData, Unit: "percentage_points", Source: "hostxray", Reason: "insufficient temporal separation in memory samples to derive growth"}, len(memSamples)))
		}
	} else {
		set(withObs(ResourceMetricEvidence{Name: "memory_growth_pct", Status: ResourceStatusInsufficientData, Unit: "percentage_points", Source: "hostxray", Reason: "need >=2 memory samples with used percent to derive memory growth"}, len(memSamples)))
	}

	out.Notes = append(out.Notes,
		"Evidence derived from provided hostxray samples/capabilities only; no host reads performed during derivation.",
		"Unavailable or insufficient metrics are explicitly labeled and never fabricated.",
	)
	return out
}

func avg(vs []float64) float64 {
	if len(vs) == 0 {
		return 0
	}
	var sum float64
	for _, v := range vs {
		sum += v
	}
	return sum / float64(len(vs))
}

func isFinite(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }
