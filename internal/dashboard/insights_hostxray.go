package dashboard

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/hostxray"
	"github.com/asadbekabdulboqiyev/sift/internal/twin"
)

type xrayCorrelateRequest struct {
	Samples []hostxray.Sample `json:"samples"`
	Signals []hostxray.Signal `json:"signals"`
	Window  string            `json:"window,omitempty"`
}

type resourceAssessmentRequest struct {
	CPU                *float64               `json:"cpu,omitempty"`
	Memory             *float64               `json:"memory,omitempty"`
	Network            *float64               `json:"network,omitempty"`
	Connections        *float64               `json:"connections,omitempty"`
	ServerResponseTime *float64               `json:"server_response_time,omitempty"`
	MemoryGrowth       *float64               `json:"memory_growth,omitempty"`
	Samples            []hostxray.Sample      `json:"samples,omitempty"`
	Capabilities       *hostxray.Capabilities `json:"capabilities,omitempty"`
	// Derived accepts pre-derived CLI evidence (e.g. sift xray report --evidence-out,
	// schema sift.resource-evidence/v1) and maps it to the dashboard/twin form.
	Derived          *hostxray.DerivedResourceEvidence `json:"derived,omitempty"`
	ResourceEvidence *hostxray.DerivedResourceEvidence `json:"resource_evidence,omitempty"`
	Source           string                            `json:"source,omitempty"`
}

func (s *Server) handleInsightsXRayCapabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	caps := hostxray.DetectCapabilities()
	insightsJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"capabilities": caps,
		"note":         "Informational only. This server never loads eBPF programs and never escalates privileges.",
	})
}

func (s *Server) handleInsightsXRayCorrelate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin requests are not allowed", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, insightsMaxBody)
	defer r.Body.Close()

	var req xrayCorrelateRequest
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid JSON: " + err.Error()})
		return
	}
	if len(req.Samples) == 0 || len(req.Signals) == 0 {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "samples and signals are required"})
		return
	}
	const maxCorrelateSamples = 50000
	const maxCorrelateSignals = 50000
	if len(req.Samples) > maxCorrelateSamples || len(req.Signals) > maxCorrelateSignals {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "too many samples or signals"})
		return
	}

	opts := hostxray.CorrelateOptions{}
	if strings.TrimSpace(req.Window) != "" {
		d, err := time.ParseDuration(req.Window)
		if err != nil {
			insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid window: " + err.Error()})
			return
		}
		opts.Window = d
	}
	indicators := hostxray.Correlate(req.Samples, req.Signals, opts)
	insightsJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"indicators": indicators,
		"note":       "Indicators highlight time-correlated host and workload evidence to guide investigation.",
	})
}

func resourceEvidenceToTwin(derived hostxray.DerivedResourceEvidence, source string) twin.ResourceAvailability {
	if strings.TrimSpace(source) == "" {
		source = derived.Source
	}
	ra := twin.ResourceAvailability{
		Values:              map[string]float64{},
		MetricsDetail:       make(map[string]twin.ResourceMetricEvidence, len(derived.Metrics)),
		Notes:               append([]string(nil), derived.Notes...),
		Source:              source,
		SchemaVersion:       derived.SchemaVersion,
		SampleCount:         derived.SampleCount,
		ObservedAt:          derived.ObservedAt,
		ObservedWindowStart: derived.ObservedWindowStart,
		ObservedWindowEnd:   derived.ObservedWindowEnd,
	}
	names := make([]string, 0, len(derived.Metrics))
	for n := range derived.Metrics {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		m := derived.Metrics[n]
		detail := twin.ResourceMetricEvidence{
			Name:                   m.Name,
			Status:                 string(m.Status),
			Value:                  m.Value,
			Unit:                   m.Unit,
			Source:                 m.Source,
			Reason:                 m.Reason,
			Notes:                  append([]string(nil), m.Notes...),
			ObservedAt:             m.ObservedAt,
			ObservedWindowStart:    m.ObservedWindowStart,
			ObservedWindowEnd:      m.ObservedWindowEnd,
			ObservationSampleCount: m.ObservationSampleCount,
		}
		// Preserve metric identity/name as provided by hostxray evidence.
		if strings.TrimSpace(detail.Name) == "" {
			detail.Name = n
		}
		ra.MetricsDetail[n] = detail
		if m.Status == hostxray.ResourceStatusAvailable && m.Value != nil && !math.IsNaN(*m.Value) && !math.IsInf(*m.Value, 0) {
			ra.Available = true
			ra.Metrics = append(ra.Metrics, n)
			ra.Values[n] = *m.Value
		} else {
			ra.Missing = append(ra.Missing, n)
			// Never report contradictory evidence: non-finite/missing values are not available.
			if detail.Status == "available" {
				detail.Status = "insufficient_data"
				if strings.TrimSpace(detail.Reason) == "" {
					detail.Reason = "derived value missing or non-finite"
				}
				detail.Value = nil
			}
			ra.MetricsDetail[n] = detail
		}
	}
	sort.Strings(ra.Metrics)
	sort.Strings(ra.Missing)
	if strings.TrimSpace(ra.Source) == "" {
		ra.Source = "hostxray-derived"
	}
	if strings.TrimSpace(ra.SchemaVersion) == "" {
		ra.SchemaVersion = "sift.resource-evidence/v1"
	}
	return ra
}

func (s *Server) handleInsightsResourceAssessment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin requests are not allowed", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, insightsMaxBody)
	defer r.Body.Close()
	var req resourceAssessmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid JSON: " + err.Error()})
		return
	}
	source := strings.TrimSpace(req.Source)
	preDerived := req.Derived
	if preDerived == nil {
		preDerived = req.ResourceEvidence
	}
	if len(req.Samples) > 0 {
		const maxResourceSamples = 50000
		if len(req.Samples) > maxResourceSamples {
			insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": fmt.Sprintf("too many samples (max %d)", maxResourceSamples)})
			return
		}
		caps := hostxray.Capabilities{}
		if req.Capabilities != nil {
			caps = *req.Capabilities
		}
		derived := hostxray.DeriveResourceEvidence(req.Samples, caps)
		if source == "" {
			source = "hostxray-derived"
		}
		ra := resourceEvidenceToTwin(derived, source)
		// Allow explicit manual overrides/supplements (measured evidence) to take precedence.
		if req.CPU != nil || req.Memory != nil || req.Network != nil || req.Connections != nil || req.ServerResponseTime != nil || req.MemoryGrowth != nil {
			manual := twin.AssessResourceMonitoringExtended(req.CPU, req.Memory, req.Network, req.Connections, req.ServerResponseTime, req.MemoryGrowth)
			for k, v := range manual.Values {
				ra.Values[k] = v
				if !containsStr(ra.Metrics, k) {
					ra.Metrics = append(ra.Metrics, k)
				}
				ra.Missing = removeStr(ra.Missing, k)
				ra.Available = true
				vv := v
				d := ra.MetricsDetail[k]
				d.Name = k
				d.Status = "available"
				d.Value = &vv
				d.Source = "manual/provided"
				d.Reason = ""
				if d.Unit == "" {
					d.Unit = guessResourceUnit(k)
				}
				// Manual override is explicit evidence but not observed from hostxray samples.
				d.ObservedAt = ""
				d.ObservedWindowStart = ""
				d.ObservedWindowEnd = ""
				d.ObservationSampleCount = 0
				ra.MetricsDetail[k] = d
			}
			sort.Strings(ra.Metrics)
			sort.Strings(ra.Missing)
			ra.Notes = append([]string{"Manual/measured overrides applied for provided metrics (explicit evidence)."}, ra.Notes...)
			ra.Source = "mixed:hostxray+manual"
		}
		insightsJSON(w, http.StatusOK, map[string]any{
			"ok": true, "resource_monitoring": ra,
			"derived_from_samples": true,
			"sample_count":         len(req.Samples),
			"note":                 "Resource metrics are derived from provided hostxray samples and/or explicit evidence; unavailable/insufficient metrics are labeled and never fabricated.",
		})
		return
	}
	if preDerived != nil {
		if source == "" {
			source = strings.TrimSpace(preDerived.Source)
		}
		if source == "" {
			source = "hostxray-derived"
		}
		ra := resourceEvidenceToTwin(*preDerived, source)
		if req.CPU != nil || req.Memory != nil || req.Network != nil || req.Connections != nil || req.ServerResponseTime != nil || req.MemoryGrowth != nil {
			manual := twin.AssessResourceMonitoringExtended(req.CPU, req.Memory, req.Network, req.Connections, req.ServerResponseTime, req.MemoryGrowth)
			for k, v := range manual.Values {
				ra.Values[k] = v
				if !containsStr(ra.Metrics, k) {
					ra.Metrics = append(ra.Metrics, k)
				}
				ra.Missing = removeStr(ra.Missing, k)
				ra.Available = true
				vv := v
				d := ra.MetricsDetail[k]
				d.Name = k
				d.Status = "available"
				d.Value = &vv
				d.Source = "manual/provided"
				d.Reason = ""
				if d.Unit == "" {
					d.Unit = guessResourceUnit(k)
				}
				d.ObservedAt = ""
				d.ObservedWindowStart = ""
				d.ObservedWindowEnd = ""
				d.ObservationSampleCount = 0
				ra.MetricsDetail[k] = d
			}
			sort.Strings(ra.Metrics)
			sort.Strings(ra.Missing)
			ra.Notes = append([]string{"Manual/measured overrides applied for provided metrics (explicit evidence)."}, ra.Notes...)
			ra.Source = "mixed:hostxray-derived+manual"
		}
		insightsJSON(w, http.StatusOK, map[string]any{
			"ok": true, "resource_monitoring": ra,
			"derived_from_samples":      false,
			"derived_from_cli_evidence": true,
			"sample_count":              preDerived.SampleCount,
			"note":                      "Resource metrics mapped from provided derived CLI/Web evidence (sift.resource-evidence/v1); unavailable/insufficient metrics remain labeled and never fabricated.",
		})
		return
	}
	if source == "" {
		source = "manual/provided"
	}
	ra := twin.AssessResourceMonitoringExtended(req.CPU, req.Memory, req.Network, req.Connections, req.ServerResponseTime, req.MemoryGrowth)
	if ra.Source == "" {
		ra.Source = source
	}
	// Ensure standardized detail/metadata consistency (additive; no fabricated timestamps).
	if ra.MetricsDetail == nil {
		ra.MetricsDetail = make(map[string]twin.ResourceMetricEvidence)
	}
	for _, n := range []string{"cpu", "memory", "network", "connections", "server_response_time", "memory_growth"} {
		if d, ok := ra.MetricsDetail[n]; ok {
			if strings.TrimSpace(d.Unit) == "" {
				d.Unit = guessResourceUnit(n)
			}
			if strings.TrimSpace(d.Source) == "" {
				d.Source = source
			}
			if strings.TrimSpace(d.Status) == "" {
				d.Status = "unavailable"
				if strings.TrimSpace(d.Reason) == "" {
					d.Reason = "not provided"
				}
			}
			ra.MetricsDetail[n] = d
			continue
		}
		v, ok := ra.Values[n]
		d := twin.ResourceMetricEvidence{Name: n, Unit: guessResourceUnit(n), Source: source}
		if ok {
			vv := v
			d.Status = "available"
			d.Value = &vv
		} else {
			d.Status = "unavailable"
			d.Reason = "not provided"
		}
		ra.MetricsDetail[n] = d
	}
	if strings.TrimSpace(ra.SchemaVersion) == "" {
		ra.SchemaVersion = "sift.resource-evidence/v1"
	}
	insightsJSON(w, http.StatusOK, map[string]any{
		"ok": true, "resource_monitoring": ra,
		"derived_from_samples": false,
		"note":                 "Resource metrics are reported only when provided; unavailable metrics are explicitly labeled and never fabricated.",
	})
}

func containsStr(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
func removeStr(ss []string, s string) []string {
	out := ss[:0]
	for _, x := range ss {
		if x != s {
			out = append(out, x)
		}
	}
	return out
}
func guessResourceUnit(name string) string {
	switch name {
	case "cpu", "memory", "network", "memory_growth":
		return "percent"
	case "connections":
		return "count"
	case "server_response_time":
		return "ms"
	default:
		return ""
	}
}
