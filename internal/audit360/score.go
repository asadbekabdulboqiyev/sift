package audit360

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/url"
	"sort"
	"strings"
)

// ScoringVersion identifies the scoring/capacity-assessment rules used.
// Additive and deterministic; older reports may omit this field.
const ScoringVersion = "sift.audit360-scoring/v2"

func normalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "high", "medium", "low", "info":
		return strings.ToLower(strings.TrimSpace(s))
	case "warning":
		return "medium"
	case "fail":
		return "high"
	default:
		return "info"
	}
}

func severityPenalty(sev string) int {
	switch normalizeSeverity(sev) {
	case "critical":
		return 30
	case "high":
		return 18
	case "medium":
		return 10
	case "low":
		return 4
	default:
		return 1
	}
}

func dedupeFindings(in []Finding) []Finding {
	seen := make(map[string]bool, len(in))
	out := make([]Finding, 0, len(in))
	for _, f := range in {
		f.Severity = normalizeSeverity(f.Severity)
		if strings.TrimSpace(f.ImpactSummary) == "" {
			f.ImpactSummary = defaultImpact(f.Severity)
		}
		if strings.TrimSpace(f.Remediation) == "" {
			f.Remediation = "Review this issue and apply the recommended fix before production use."
		}
		if strings.TrimSpace(f.Evidence) == "" {
			f.Evidence = defaultEvidence(f)
		}
		key := strings.ToLower(strings.TrimSpace(f.Title)) + "|" + f.Severity + "|" + strings.ToLower(strings.TrimSpace(f.Remediation)) + "|" + strings.ToLower(strings.TrimSpace(f.Source))
		if strings.TrimSpace(f.Title) == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if severityPenalty(out[i].Severity) != severityPenalty(out[j].Severity) {
			return severityPenalty(out[i].Severity) > severityPenalty(out[j].Severity)
		}
		return strings.ToLower(out[i].Title) < strings.ToLower(out[j].Title)
	})
	return out
}

func defaultEvidence(f Finding) string {
	switch strings.ToLower(strings.TrimSpace(f.Source)) {
	case "security_scan":
		return "Observed during automated security scan checks (headers/TLS/OWASP/lightweight probes) for the target."
	case "stress_test":
		return "Observed from measured load-test telemetry during the audit run."
	case "evidence_quality":
		return "Derived from audit execution coverage and evidence availability for this run."
	default:
		return "Reported by audit analysis for this run; verify against raw evidence/artifacts when available."
	}
}

func defaultImpact(sev string) string {
	switch normalizeSeverity(sev) {
	case "critical":
		return "This can expose sensitive data or allow serious compromise if exploited."
	case "high":
		return "This significantly increases security or reliability risk for users and operations."
	case "medium":
		return "This weakens protection and can be abused in common attack scenarios."
	case "low":
		return "This is a smaller gap but can contribute to larger issues over time."
	default:
		return "Informational signal; review for context and hardening opportunities."
	}
}

func clampScore(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

func finiteOrZero(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0
	}
	return v
}

func nonNegFinite(v float64) float64 {
	v = finiteOrZero(v)
	if v < 0 {
		return 0
	}
	return v
}

func riskForOverall(score int) string {
	switch {
	case score >= 80:
		return RiskLow
	case score >= 55:
		return RiskModerate
	default:
		return RiskCritical
	}
}

// ComputeAssessment calculates component scores, overall score/risk, findings and notes.
// No values are fabricated: capacity metrics are only scored/labeled when measured.
func ComputeAssessment(secFindings []Finding, securityPartial bool, stress StressOutcome) (ScoreBreakdown, string, []Finding, []string) {
	// Normalize measured stress inputs so NaN/Infinity/negative values cannot
	// leak into scoring, notes, or cross-module assessment state.
	stress.MaxSafeRPS = nonNegFinite(stress.MaxSafeRPS)
	stress.MaxObservedRPS = nonNegFinite(stress.MaxObservedRPS)
	if stress.MaxObservedUsers < 0 {
		stress.MaxObservedUsers = 0
	}
	stress.PeakErrorRatePct = nonNegFinite(stress.PeakErrorRatePct)
	stress.PeakP99MS = nonNegFinite(stress.PeakP99MS)
	stress.RejectSharePct = nonNegFinite(stress.RejectSharePct)

	findings := dedupeFindings(secFindings)
	notes := []string{}

	securityScore := 100
	capacityScore := 100
	resilienceScore := 100
	evidenceScore := 100

	// Security component: penalties from security findings and partial coverage.
	if securityPartial {
		securityScore -= 8
		evidenceScore -= 10
		notes = append(notes, "Security scan completed partially; some checks may be unavailable or not tested.")
		findings = append(findings, Finding{
			Title:         "Security scan coverage incomplete",
			Severity:      "medium",
			ImpactSummary: "Some security checks did not complete, so the risk picture may be incomplete.",
			Remediation:   "Rerun the audit with a reachable target and sufficient time/budget to complete all checks.",
			Evidence:      "Security scan stage reported partial coverage or did not complete all checks within the audit budget.",
			Source:        "evidence_quality",
		})
	}
	for _, f := range findings {
		if strings.EqualFold(strings.TrimSpace(f.Source), "security_scan") || (f.Source == "" && !strings.Contains(strings.ToLower(f.Title), "capacity") && !strings.Contains(strings.ToLower(f.Title), "evidence")) {
			securityScore -= severityPenalty(f.Severity)
		}
	}

	// Capacity/resilience/evidence components from stress outcome.
	switch {
	case stress.RejectedByTarget:
		// Access gate refused load: capacity/breaking point is unmeasurable (not a measured capacity failure).
		// Penalize evidence quality (we could not obtain capacity evidence) but do not score capacity as poor.
		evidenceScore -= 20
		findings = append(findings, Finding{
			Title:    fmt.Sprintf("Capacity not measurable — target refused load (HTTP %d)", stress.RejectStatusCode),
			Severity: "medium",
			ImpactSummary: fmt.Sprintf(
				"The target rejected %.0f%% of audit requests with HTTP %d, so its real breaking point could not be measured. This is an access-control/rate-limit response, not proof of a capacity limit.",
				stress.RejectSharePct, stress.RejectStatusCode),
			Remediation: "Re-run the audit against a target that accepts the load generator (allowlist its IP, disable the WAF/bot gate, or use a dedicated staging endpoint), then measure capacity.",
			Evidence: fmt.Sprintf(
				"Measured during ramp: dominant rejection status HTTP %d observed for %.1f%% of requests; peak observed users=%d (capacity/breaking-point figures suppressed as unmeasurable).",
				stress.RejectStatusCode, stress.RejectSharePct, stress.MaxObservedUsers),
			Source: "stress_test",
		})
		notes = append(notes, "Observed throughput/capacity figures suppressed because the target refused load traffic (access gate, not service capacity).")
		notes = append(notes, "Capacity and resilience-under-load were not measured due to target refusal; capacity score reflects no adverse measured capacity evidence in this run.")
	case stress.Skipped:
		// Intentionally not executed (e.g. passive mode): no capacity measurement, not a failure.
		evidenceScore -= 15
		notes = append(notes, "Capacity/load testing skipped in passive mode (non-intrusive checks only); capacity metrics not measured.")
		notes = append(notes, "Sustainable capacity and breaking point were not measured in Passive mode; capacity score reflects no adverse measured capacity evidence.")
	case !stress.Available:
		capacityScore -= 30
		resilienceScore -= 15
		evidenceScore -= 20
		notes = append(notes, "Load/stress evidence unavailable: capacity could not be measured in this run.")
		findings = append(findings, Finding{
			Title:         "Capacity test unavailable",
			Severity:      "high",
			ImpactSummary: "Without a measured load test, the system's real breaking point is unknown.",
			Remediation:   "Run the stress test against an authorized, reachable target to measure safe capacity and failure thresholds.",
			Evidence:      "Stress test stage did not produce measurable telemetry (unreachable target, execution error, or no samples).",
			Source:        "evidence_quality",
		})
	default:
		// Measured stress evidence available.
		if stress.Breached {
			capacityScore -= 30
			resilienceScore -= 25
			impact := "The service reached a failure threshold during ramp-up, which means users may see errors or severe slowdowns under load."
			rem := "Increase capacity, optimize slow endpoints, add caching/queueing, and tune timeouts/autoscaling before higher traffic."
			if stress.BreakingPointUsers > 0 {
				impact = fmt.Sprintf("The service hit failure thresholds around %d concurrent users, so higher traffic can cause errors or severe slowdowns.", stress.BreakingPointUsers)
			}
			findings = append(findings, Finding{
				Title:         "Capacity limit reached during stress test",
				Severity:      "high",
				ImpactSummary: impact,
				Remediation:   rem,
				Evidence: fmt.Sprintf(
					"Measured ramp result: breached=%v, breaking_point_users=%d, peak_observed_rps=%.2f, safe_rps_estimate=%.2f, peak_error_rate=%.2f%%, peak_p99_ms=%.0f, reason=%q.",
					stress.Breached, stress.BreakingPointUsers, stress.MaxObservedRPS, stress.MaxSafeRPS, stress.PeakErrorRatePct, stress.PeakP99MS, stress.BreachReason),
				Source: "stress_test",
			})
			notes = append(notes, fmt.Sprintf("Breaking point detected from measured telemetry: %s", stress.BreachReason))
		} else {
			notes = append(notes, "No failure threshold breached within the audit's time/load window (not a guarantee under higher load).")
			if stress.MaxObservedUsers >= 200 {
				resilienceScore += 2
			}
		}

		// Penalize poor observed reliability/latency (resilience) even without formal breach.
		if stress.PeakErrorRatePct > 1.0 {
			pen := int(math.Min(12, math.Round(stress.PeakErrorRatePct)))
			resilienceScore -= pen
			capacityScore -= pen / 2
		}
		if stress.PeakP99MS > 1000 {
			pen := int(math.Min(10, math.Round((stress.PeakP99MS-1000)/300)))
			resilienceScore -= pen
			capacityScore -= pen / 2
		}

		notes = append(notes, fmt.Sprintf(
			"Measured capacity evidence: observed peak throughput=%.2f RPS, observed peak users=%d, sustainable/safe capacity estimate=%.2f RPS (from samples meeting thresholds), peak error=%.2f%%, peak p99=%.0fms.",
			stress.MaxObservedRPS, stress.MaxObservedUsers, stress.MaxSafeRPS, stress.PeakErrorRatePct, stress.PeakP99MS))
		if stress.MaxSafeRPS > 0 && stress.MaxObservedRPS > stress.MaxSafeRPS {
			notes = append(notes, "Observed peak throughput can exceed sustainable/safe capacity estimate; sustainable/safe estimate is derived only from measured samples meeting error/latency thresholds.")
		}
	}

	securityScore = clampScore(securityScore)
	capacityScore = clampScore(capacityScore)
	resilienceScore = clampScore(resilienceScore)
	evidenceScore = clampScore(evidenceScore)
	overall := clampScore(int(math.Round(0.35*float64(securityScore) + 0.25*float64(resilienceScore) + 0.25*float64(capacityScore) + 0.15*float64(evidenceScore))))

	findings = dedupeFindings(findings)

	// Enforce logical consistency: overall/risk must not contradict the most
	// severe measured/reported finding. A single critical or high finding cannot
	// coexist with a "low risk" or overly optimistic overall score.
	hasCritical, hasHigh := false, false
	for _, f := range findings {
		switch normalizeSeverity(f.Severity) {
		case "critical":
			hasCritical = true
		case "high":
			hasHigh = true
		}
	}
	risk := riskForOverall(overall)
	switch {
	case hasCritical:
		if overall > 54 {
			overall = 54
		}
		risk = RiskCritical
	case hasHigh:
		if overall > 79 {
			overall = 79
		}
		if risk == RiskLow {
			risk = RiskModerate
		}
	}
	overall = clampScore(overall)

	breakdown := ScoreBreakdown{
		Overall:         overall,
		Security:        securityScore,
		Resilience:      resilienceScore,
		Capacity:        capacityScore,
		EvidenceQuality: evidenceScore,
	}
	return breakdown, risk, findings, notes
}

// ComputeResilience calculates score/risk from scan and stress outcomes.
// Backward-compatible wrapper around ComputeAssessment.
// No values are fabricated: capacity metrics are only scored when measured.
func ComputeResilience(secFindings []Finding, securityPartial bool, stress StressOutcome) (score int, risk string, findings []Finding, notes []string) {
	breakdown, risk, findings, notes := ComputeAssessment(secFindings, securityPartial, stress)
	return breakdown.Overall, risk, findings, notes
}

// StressOutcome captures measured load-test results (no fabricated values).
type StressOutcome struct {
	Available          bool
	Breached           bool
	BreakingPointUsers int
	MaxSafeRPS         float64 // measured sustainable/safe RPS estimate from samples meeting thresholds
	MaxObservedRPS     float64 // measured observed peak throughput
	MaxObservedUsers   int
	PeakErrorRatePct   float64
	PeakP99MS          float64
	BreachReason       string
	// RejectedByTarget is set when the target refused the traffic itself
	// (dominant 401/403/407/429), making capacity unmeasurable in this run.
	RejectedByTarget bool
	RejectStatusCode int
	RejectSharePct   float64
	// Skipped indicates the stress/load stage was intentionally not executed
	// (e.g. passive mode). No capacity penalty or fabricated measurement applies.
	Skipped bool
	Notes   []string
}

// RawEvidenceInput captures measured inputs for deterministic evidence hashing.
// Only observed/measured or explicitly provided configuration fields are included.
type RawEvidenceInput struct {
	TargetURL               string        `json:"target_url"`
	Mode                    string        `json:"mode,omitempty"`
	RequestedMaxDurationSec int           `json:"requested_max_duration_sec,omitempty"`
	SecurityPartial         bool          `json:"security_scan_partial"`
	SecurityFindings        []Finding     `json:"security_findings,omitempty"`
	Stress                  StressOutcome `json:"stress"`
}

// ComputeRawEvidenceHash returns a deterministic SHA-256 hash of measured/raw
// evidence inputs and executed test configuration context. No synthetic metrics
// are added; fields are included as observed/provided.
func ComputeRawEvidenceHash(in RawEvidenceInput) (hash string, format string, err error) {
	// Normalize for determinism.
	normFindings := append([]Finding(nil), in.SecurityFindings...)
	sort.SliceStable(normFindings, func(i, j int) bool {
		if normFindings[i].Source != normFindings[j].Source {
			return normFindings[i].Source < normFindings[j].Source
		}
		if normFindings[i].Severity != normFindings[j].Severity {
			return normFindings[i].Severity < normFindings[j].Severity
		}
		if normFindings[i].Title != normFindings[j].Title {
			return normFindings[i].Title < normFindings[j].Title
		}
		return normFindings[i].Evidence < normFindings[j].Evidence
	})
	in.SecurityFindings = normFindings
	b, err := json.Marshal(in)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), "sha256(json:sift.audit360.raw-evidence/v1)", nil
}

// IsDemoStoreTarget reports whether targetURL matches the configured demo-store URL.
func IsDemoStoreTarget(targetURL, demoStoreURL string) bool {
	u, err := url.Parse(strings.TrimSpace(targetURL))
	if err != nil || u.Host == "" {
		return false
	}
	d, err := url.Parse(strings.TrimSpace(demoStoreURL))
	if err != nil || d.Host == "" {
		return false
	}
	uh := strings.ToLower(u.Hostname())
	dh := strings.ToLower(d.Hostname())
	up := effectivePort(u)
	dp := effectivePort(d)
	if up != dp {
		return false
	}
	if sameHost(uh, dh) {
		return true
	}
	// Accept localhost/127.0.0.1/::1 equivalence for demo store host.
	if isLoopbackHost(uh) && isLoopbackHost(dh) {
		return true
	}
	return false
}

func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return "443"
	case "http":
		return "80"
	default:
		return ""
	}
}

func sameHost(a, b string) bool { return strings.Trim(a, "[]") == strings.Trim(b, "[]") }

func isLoopbackHost(h string) bool {
	h = strings.Trim(h, "[]")
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// ParseTargetHostPort extracts host and port for scanners that need them.
func ParseTargetHostPort(targetURL string) (host string, port int, scheme string, err error) {
	u, err := url.Parse(strings.TrimSpace(targetURL))
	if err != nil {
		return "", 0, "", err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", 0, "", fmt.Errorf("target must use http:// or https://")
	}
	if u.Host == "" {
		return "", 0, "", fmt.Errorf("target has no host")
	}
	if u.User != nil {
		return "", 0, "", fmt.Errorf("target must not embed credentials")
	}
	scheme = strings.ToLower(u.Scheme)
	host = u.Hostname()
	p := u.Port()
	if p == "" {
		if scheme == "https" {
			port = 443
		} else {
			port = 80
		}
	} else {
		_, err = fmt.Sscanf(p, "%d", &port)
		if err != nil || port <= 0 || port > 65535 {
			return "", 0, "", fmt.Errorf("invalid target port")
		}
	}
	return host, port, scheme, nil
}
