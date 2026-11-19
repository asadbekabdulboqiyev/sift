package scanner

import (
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync/atomic"
)

// ---------------------------------------------------------------------------
// 5. Security Headers
// ---------------------------------------------------------------------------

func (vs *VulnScanner) scanSecurityHeaders() {
	if vs.Results == nil {
		return
	}
	target := normalizeURL(vs.Target)
	resp, err := vs.get(target)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
	atomic.AddInt64(&vs.Results.URLsChecked, 1)

	type headerCheck struct {
		name      string
		required  bool
		severity  string
		checkFunc func(string) string
	}

	checks := []headerCheck{
		{
			name:     "Strict-Transport-Security",
			required: true,
			severity: "medium",
			checkFunc: func(v string) string {
				if v == "" {
					return "Missing HSTS header - allows HTTP downgrade attacks and SSL stripping"
				}
				return ""
			},
		},
		{
			name:     "Content-Security-Policy",
			required: true,
			severity: "medium",
			checkFunc: func(v string) string {
				if v == "" {
					return "Missing CSP header - no protection against XSS"
				}
				if strings.Contains(v, "'unsafe-inline'") || strings.Contains(v, "'unsafe-eval'") {
					return "CSP contains 'unsafe-inline' or 'unsafe-eval' - significantly weakens XSS protection"
				}
				return ""
			},
		},
		{
			name:     "X-Frame-Options",
			required: true,
			severity: "medium",
			checkFunc: func(v string) string {
				if v == "" {
					return "Missing X-Frame-Options - vulnerable to clickjacking"
				}
				return ""
			},
		},
		{
			name:     "X-Content-Type-Options",
			required: true,
			severity: "low",
			checkFunc: func(v string) string {
				if v == "" {
					return "Missing X-Content-Type-Options - MIME type sniffing possible"
				}
				return ""
			},
		},
		{
			name:     "Referrer-Policy",
			required: true,
			severity: "low",
			checkFunc: func(v string) string {
				if v == "" {
					return "Missing Referrer-Policy - sensitive URL data may leak in Referer header"
				}
				return ""
			},
		},
		{
			name:     "Permissions-Policy",
			required: false,
			severity: "low",
			checkFunc: func(v string) string {
				if v == "" {
					return "Missing Permissions-Policy - browser features not restricted"
				}
				return ""
			},
		},
	}

	for _, hc := range checks {
		atomic.AddInt64(&vs.Results.TotalChecks, 1)
		value := resp.Header.Get(hc.name)
		if msg := hc.checkFunc(value); msg != "" {
			vs.addFinding(Vulnerability{
				ID:          vs.nextVulnID("HDR"),
				Title:       fmt.Sprintf("Missing/Weak Security Header: %s", hc.name),
				Severity:    hc.severity,
				Category:    "A05:2021 Security Misconfiguration",
				CVSS:        5.3,
				CWE:         "CWE-693",
				URL:         target,
				Evidence:    msg,
				Impact:      msg,
				Remediation: fmt.Sprintf("Add '%s' header to HTTP responses", hc.name),
				References:  []string{"https://owasp.org/Top10/A05_2021-Security_Misconfiguration/", "https://securityheaders.com/"},
			})
		}
	}

	// Server header version leak
	atomic.AddInt64(&vs.Results.TotalChecks, 1)
	serverHeader := resp.Header.Get("Server")
	if serverHeader != "" {
		versionPattern := regexp.MustCompile(`[\d]+\.[\d]+[\d.]*`)
		if versionPattern.MatchString(serverHeader) {
			vs.addFinding(Vulnerability{
				ID:          vs.nextVulnID("HDR"),
				Title:       "Server Header Leaks Version Information",
				Severity:    "low",
				Category:    "A05:2021 Security Misconfiguration",
				CVSS:        2.6,
				CWE:         "CWE-200",
				URL:         target,
				Evidence:    fmt.Sprintf("Server header reveals: %s", serverHeader),
				Impact:      "Version info helps attackers identify known vulnerabilities for the specific server version",
				Remediation: "Remove or obfuscate version information from the Server header",
				References:  []string{"https://cwe.mitre.org/data/definitions/200.html"},
			})
		}
	}

	// X-Powered-By leak
	xPoweredBy := resp.Header.Get("X-Powered-By")
	if xPoweredBy != "" {
		atomic.AddInt64(&vs.Results.TotalChecks, 1)
		vs.addFinding(Vulnerability{
			ID:          vs.nextVulnID("HDR"),
			Title:       "X-Powered-By Header Reveals Technology Stack",
			Severity:    "low",
			Category:    "A05:2021 Security Misconfiguration",
			CVSS:        2.6,
			CWE:         "CWE-200",
			URL:         target,
			Evidence:    fmt.Sprintf("X-Powered-By: %s", xPoweredBy),
			Impact:      "Technology fingerprinting helps attackers target known vulnerabilities",
			Remediation: "Remove the X-Powered-By header",
			References:  []string{"https://cwe.mitre.org/data/definitions/200.html"},
		})
	}
}

// ---------------------------------------------------------------------------
// 6. Information Disclosure
// ---------------------------------------------------------------------------

func (vs *VulnScanner) scanInfoDisclosure() {
	if vs.Results == nil {
		return
	}
	target := normalizeURL(vs.Target)

	type disclosureCheck struct {
		path     string
		title    string
		severity string
		cvss     float64
		cwe      string
		impact   string
		fix      string
		sigs     []string
	}

	checks := []disclosureCheck{
		{
			path:     "/robots.txt",
			title:    "robots.txt May Reveal Sensitive Paths",
			severity: "info",
			cvss:     0.0,
			cwe:      "CWE-200",
			impact:   "Disallowed paths may reveal admin panels, backup files, or internal endpoints",
			fix:      "Review robots.txt and ensure it does not expose sensitive paths",
			sigs:     []string{"Disallow:", "allow:", "Sitemap:"},
		},
		{
			path:     "/.env",
			title:    "Exposed .env File",
			severity: "critical",
			cvss:     9.1,
			cwe:      "CWE-200",
			impact:   "Environment variables often contain database credentials, API keys, and secrets",
			fix:      "Move .env outside web root, block access with web server configuration",
			sigs:     []string{"APP_KEY=", "DB_PASSWORD=", "API_KEY=", "SECRET=", "AWS_", "DATABASE_URL=", "MAIL_PASSWORD="},
		},
		{
			path:     "/wp-config.php.bak",
			title:    "WordPress Config Backup Exposed",
			severity: "critical",
			cvss:     9.1,
			cwe:      "CWE-200",
			impact:   "WordPress configuration contains database credentials and authentication keys",
			fix:      "Remove backup files from web-accessible directories",
			sigs:     []string{"DB_NAME", "DB_USER", "DB_PASSWORD", "table_prefix"},
		},
		{
			path:     "/server-status",
			title:    "Apache Server-Status Page Exposed",
			severity: "medium",
			cvss:     5.3,
			cwe:      "CWE-200",
			impact:   "Reveals connected IPs, request rates, server load, and active connections",
			fix:      "Restrict access to server-status with IP allowlisting or disable mod_status",
			sigs:     []string{"Apache Server Status", "Server Version:", "Current Time:", "Total accesses:"},
		},
		{
			path:     "/.git/HEAD",
			title:    "Git Repository Exposed",
			severity: "critical",
			cvss:     7.5,
			cwe:      "CWE-200",
			impact:   "Attackers can clone the entire repository and extract source code, secrets, and history",
			fix:      "Block access to .git directory in web server configuration",
			sigs:     []string{"ref: refs/heads/"},
		},
		{
			path:     "/debug/",
			title:    "Debug Endpoint Exposed",
			severity: "high",
			cvss:     7.5,
			cwe:      "CWE-215",
			impact:   "Debug endpoints may expose stack traces, environment variables, and internal state",
			fix:      "Disable debug endpoints in production, restrict with authentication",
			sigs:     []string{"debug", "stack trace", "TRACE", "DEBUG", "Exception"},
		},
		{
			path:     "/api/swagger.json",
			title:    "API Documentation Exposed (Swagger/OpenAPI)",
			severity: "medium",
			cvss:     5.3,
			cwe:      "CWE-200",
			impact:   "Full API schema revealed - attackers can map all endpoints and parameters",
			fix:      "Restrict API documentation to authenticated users or internal networks",
			sigs:     []string{"swagger", "openapi", "info", "paths", "definitions"},
		},
		{
			path:     "/.git/config",
			title:    "Git Configuration Exposed",
			severity: "critical",
			cvss:     7.5,
			cwe:      "CWE-200",
			impact:   "Reveals repository URLs, user names, and remote configurations",
			fix:      "Block access to .git directory in web server configuration",
			sigs:     []string{"[core]", "repositoryformatversion", "[remote"},
		},
		{
			path:     "/.svn/entries",
			title:    "SVN Repository Exposed",
			severity: "high",
			cvss:     7.5,
			cwe:      "CWE-200",
			impact:   "SVN metadata reveals source code structure and revision history",
			fix:      "Block access to .svn directory",
			sigs:     []string{"svn:", "dir", "file"},
		},
		{
			path:     "/composer.json",
			title:    "Composer Dependencies Exposed",
			severity: "low",
			cvss:     3.1,
			cwe:      "CWE-200",
			impact:   "Reveals PHP dependencies and versions, aiding vulnerability research",
			fix:      "Move composer.json outside web root or block access",
			sigs:     []string{"require", "autoload", "php"},
		},
		{
			path:     "/package.json",
			title:    "Node.js package.json Exposed",
			severity: "low",
			cvss:     3.1,
			cwe:      "CWE-200",
			impact:   "Reveals Node.js dependencies, scripts, and project configuration",
			fix:      "Move package.json outside web root or block access",
			sigs:     []string{"\"dependencies\"", "\"scripts\"", "\"devDependencies\""},
		},
		{
			path:     "/web.config",
			title:    "IIS Web.config Exposed",
			severity: "high",
			cvss:     7.5,
			cwe:      "CWE-200",
			impact:   "May contain connection strings, app settings, and machine keys",
			fix:      "Restrict access to web.config in IIS configuration",
			sigs:     []string{"connectionStrings", "appSettings", "system.web"},
		},
	}

	for _, check := range checks {
		atomic.AddInt64(&vs.Results.TotalChecks, 1)
		checkURL := target + check.path
		resp, err := vs.get(checkURL)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		bodyStr := string(body)

		if resp.StatusCode == 200 {
			for _, sig := range check.sigs {
				if strings.Contains(bodyStr, sig) || strings.Contains(strings.ToLower(bodyStr), strings.ToLower(sig)) {
					vs.addFinding(Vulnerability{
						ID:          vs.nextVulnID("INFO"),
						Title:       check.title,
						Severity:    check.severity,
						Category:    "A05:2021 Security Misconfiguration",
						CVSS:        check.cvss,
						CWE:         check.cwe,
						URL:         checkURL,
						Evidence:    fmt.Sprintf("HTTP 200 at %s with content matching '%s'", check.path, sig),
						Impact:      check.impact,
						Remediation: check.fix,
						References:  []string{"https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"},
					})
					break
				}
			}
		}
	}
}
