// Package shared holds the canonical copies of logic that more than one
// command or package used to keep as hand-maintained duplicates. Callers must
// delegate here instead of re-implementing a rule locally: a second copy is a
// second opinion, and the two will drift the first time one of them is fixed.
package shared

import (
	"fmt"
	"strings"

	"github.com/asadbekabdulboqiyev/sift/internal/scanner/core"
)

// CalculateVulns derives the finding list from one scan result.
//
// This is the canonical rule set, taken verbatim from the scanner path. The
// standalone sift-scan CLI used to carry a shorter copy that omitted weak
// ciphers, the deprecated-TLS-version finding and the no-WAF finding, and that
// uppercased SEC-* IDs while the scanner lowercased them. Both entry points now
// call this function, so a target scanned through either path produces the same
// IDs, severities and descriptions.
func CalculateVulns(r *core.ScanResult) []core.Vuln {
	if r == nil {
		return nil
	}
	var vulns []core.Vuln

	// TLS vulnerabilities.
	if r.TLS != nil {
		if r.TLS.Certificate != nil && r.TLS.Certificate.IsExpired {
			vulns = append(vulns, core.Vuln{
				ID:          "TLS-001",
				Severity:    "critical",
				Title:       "Expired SSL/TLS Certificate",
				Description: fmt.Sprintf("Certificate expired on %s", r.TLS.Certificate.NotAfter.Format("2006-01-02")),
				Remediation: "Renew the certificate immediately",
			})
		}
		if r.TLS.Certificate != nil && r.TLS.Certificate.IsSelfSigned {
			vulns = append(vulns, core.Vuln{
				ID:          "TLS-002",
				Severity:    "high",
				Title:       "Self-Signed Certificate",
				Description: "Certificate is self-signed, not trusted by browsers",
				Remediation: "Use a certificate from a trusted CA (Let's Encrypt, DigiCert, etc.)",
			})
		}
		// Weak protocols/ciphers reported by the TLS scanner: one finding per
		// reported vulnerability, canonical ID TLS-003.
		for _, v := range r.TLS.Vulnerabilities {
			vulns = append(vulns, core.Vuln{
				ID:          "TLS-003",
				Severity:    "high",
				Title:       v,
				Description: v,
				Remediation: "Disable weak cipher suites and protocols",
			})
		}
		if r.TLS.Version == "TLS 1.0" || r.TLS.Version == "TLS 1.1" {
			vulns = append(vulns, core.Vuln{
				ID:          "TLS-004",
				Severity:    "high",
				Title:       "Deprecated TLS Version",
				Description: fmt.Sprintf("Server supports %s which has known vulnerabilities", r.TLS.Version),
				Remediation: "Disable TLS 1.0 and TLS 1.1, use TLS 1.2+",
			})
		}
	}

	// Security header vulnerabilities. IDs are lowercase: a header name is
	// case-insensitive in HTTP, so the derived ID must not depend on how the
	// scanner capitalised it.
	if r.Security != nil {
		for _, h := range r.Security.MissingHeaders {
			vulns = append(vulns, core.Vuln{
				ID:          "SEC-" + strings.ReplaceAll(strings.ToLower(h), "-", ""),
				Severity:    "medium",
				Title:       fmt.Sprintf("Missing %s header", h),
				Description: fmt.Sprintf("The %s security header is not set", h),
				Remediation: fmt.Sprintf("Add '%s' header to HTTP responses", h),
			})
		}
	}

	// CORS vulnerabilities.
	if r.HTTP != nil && r.HTTP.CORS != nil && r.HTTP.CORS.IsPermissive {
		vulns = append(vulns, core.Vuln{
			ID:          "CORS-001",
			Severity:    "medium",
			Title:       "Permissive CORS Policy",
			Description: fmt.Sprintf("Access-Control-Allow-Origin: %s", r.HTTP.CORS.AllowOrigin),
			Remediation: "Restrict CORS to specific trusted origins",
		})
	}

	// WAF absence is informational, but it is still a finding.
	if r.WAF != nil && !r.WAF.Detected {
		vulns = append(vulns, core.Vuln{
			ID:          "WAF-001",
			Severity:    "info",
			Title:       "No WAF Detected",
			Description: "No Web Application Firewall detected in front of the server",
			Remediation: "Consider deploying a WAF (Cloudflare, AWS WAF, ModSecurity, etc.)",
		})
	}

	return vulns
}

// CalculateRiskScore returns the 0..100 risk score for a scan result. It starts
// at 100 and subtracts for weak TLS, header gaps and each finding, clamped to
// [0, 100]. The scanner and the standalone CLI both use this exact rule.
func CalculateRiskScore(r *core.ScanResult) int {
	if r == nil {
		return 100
	}
	score := 100

	if r.TLS != nil {
		if !r.TLS.IsSecure {
			score -= 20
		}
		if r.TLS.Certificate != nil && r.TLS.Certificate.IsExpired {
			score -= 30
		}
		if r.TLS.Certificate != nil && r.TLS.Certificate.IsSelfSigned {
			score -= 15
		}
		if r.TLS.Version == "TLS 1.0" || r.TLS.Version == "TLS 1.1" {
			score -= 15
		}
	}

	if r.Security != nil {
		score -= (100 - r.Security.Score) / 5
	}

	for _, v := range r.Vulns {
		switch v.Severity {
		case "critical":
			score -= 25
		case "high":
			score -= 15
		case "medium":
			score -= 8
		case "low":
			score -= 3
		}
	}

	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}
