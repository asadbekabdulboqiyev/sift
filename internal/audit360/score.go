package audit360

import (
	"fmt"
	"math"
	"net"
	"net/url"
	"sort"
	"strings"
)

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
		key := strings.ToLower(strings.TrimSpace(f.Title)) + "|" + normalizeSeverity(f.Severity) + "|" + strings.ToLower(strings.TrimSpace(f.Remediation))
		if key == "||" || seen[key] {
			continue
		}
		seen[key] = true
		f.Severity = normalizeSeverity(f.Severity)
		if strings.TrimSpace(f.ImpactSummary) == "" {
			f.ImpactSummary = defaultImpact(f.Severity)
		}
		if strings.TrimSpace(f.Remediation) == "" {
			f.Remediation = "Review this issue and apply the recommended fix before production use."
		}
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return severityPenalty(out[i].Severity) > severityPenalty(out[j].Severity)
	})
	return out
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

// ComputeResilience calculates score/risk from scan and stress outcomes.
// No values are fabricated: capacity metrics are only scored when measured.
func ComputeResilience(secFindings []Finding, securityPartial bool, stress StressOutcome) (score int, risk string, findings []Finding, notes []string) {
	findings = dedupeFindings(secFindings)
	score = 100

	if securityPartial {
		score -= 8
		notes = append(notes, "Security scan completed partially; some checks may be unavailable or not tested.")
		findings = append(findings, Finding{
			Title:         "Security scan coverage incomplete",
			Severity:      "medium",
			ImpactSummary: "Some security checks did not complete, so the risk picture may be incomplete.",
			Remediation:   "Rerun the audit with a reachable target and sufficient time/budget to complete all checks.",
			Source:        "security_scan",
		})
	}

	for _, f := range findings {
		score -= severityPenalty(f.Severity)
	}

	if !stress.Available {
		score -= 20
		notes = append(notes, "Load/stress evidence unavailable: capacity could not be measured in this run.")
		findings = append(findings, Finding{
			Title:         "Capacity test unavailable",
			Severity:      "high",
			ImpactSummary: "Without a measured load test, the system's real breaking point is unknown.",
			Remediation:   "Run the stress test against an authorized, reachable target to measure safe capacity and failure thresholds.",
			Source:        "stress_test",
		})
	} else {
		if stress.Breached {
			score -= 20
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
				Source:        "stress_test",
			})
			notes = append(notes, fmt.Sprintf("Breaking point detected: %s", stress.BreachReason))
		} else {
			// No breach observed within test window; modest credit only, not a guarantee.
			if stress.MaxObservedUsers >= 200 {
				score += 2
			}
			notes = append(notes, "No failure threshold breached within the audit's time/load window (not a guarantee under higher load).")
		}

		// Penalize poor observed reliability/latency even without formal breach.
		if stress.PeakErrorRatePct > 1.0 {
			score -= int(math.Min(12, math.Round(stress.PeakErrorRatePct)))
		}
		if stress.PeakP99MS > 1000 {
			score -= int(math.Min(10, math.Round((stress.PeakP99MS-1000)/300)))
		}
	}

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	switch {
	case score >= 80:
		risk = RiskLow
	case score >= 55:
		risk = RiskModerate
	default:
		risk = RiskCritical
	}

	findings = dedupeFindings(findings)
	return score, risk, findings, notes
}

// StressOutcome captures measured load-test results (no fabricated values).
type StressOutcome struct {
	Available          bool
	Breached           bool
	BreakingPointUsers int
	MaxSafeRPS         float64
	MaxObservedRPS     float64
	MaxObservedUsers   int
	PeakErrorRatePct   float64
	PeakP99MS          float64
	BreachReason       string
	Notes              []string
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
