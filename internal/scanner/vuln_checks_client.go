package scanner

import (
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// 9. Cookie Security
// ---------------------------------------------------------------------------

func (vs *VulnScanner) scanCookies() {
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

	cookies := resp.Cookies()
	for _, cookie := range cookies {
		// Check Secure flag
		atomic.AddInt64(&vs.Results.TotalChecks, 1)
		if !cookie.Secure {
			vs.addFinding(Vulnerability{
				ID:          vs.nextVulnID("CK"),
				Title:       fmt.Sprintf("Cookie '%s' Missing Secure Flag", cookie.Name),
				Severity:    "low",
				Category:    "A05:2021 Security Misconfiguration",
				CVSS:        3.7,
				CWE:         "CWE-614",
				URL:         target,
				Parameter:   cookie.Name,
				Evidence:    fmt.Sprintf("Cookie '%s' set without Secure flag", cookie.Name),
				Impact:      "Cookie transmitted over unencrypted HTTP connections, susceptible to interception",
				Remediation: "Set the Secure flag on all cookies: Set-Cookie: ...; Secure",
				References:  []string{"https://cwe.mitre.org/data/definitions/614.html", "https://owasp.org/www-community/controls/SecureCookieAttribute"},
			})
		}

		// Check HttpOnly flag
		atomic.AddInt64(&vs.Results.TotalChecks, 1)
		if !cookie.HttpOnly {
			vs.addFinding(Vulnerability{
				ID:          vs.nextVulnID("CK"),
				Title:       fmt.Sprintf("Cookie '%s' Missing HttpOnly Flag", cookie.Name),
				Severity:    "medium",
				Category:    "A05:2021 Security Misconfiguration",
				CVSS:        4.7,
				CWE:         "CWE-1004",
				URL:         target,
				Parameter:   cookie.Name,
				Evidence:    fmt.Sprintf("Cookie '%s' set without HttpOnly flag", cookie.Name),
				Impact:      "JavaScript can access the cookie, enabling session theft via XSS",
				Remediation: "Set the HttpOnly flag on all cookies: Set-Cookie: ...; HttpOnly",
				References:  []string{"https://cwe.mitre.org/data/definitions/1004.html", "https://owasp.org/www-community/controls/HttpOnly"},
			})
		}

		// Check SameSite
		atomic.AddInt64(&vs.Results.TotalChecks, 1)
		if cookie.SameSite == http.SameSiteNoneMode {
			vs.addFinding(Vulnerability{
				ID:          vs.nextVulnID("CK"),
				Title:       fmt.Sprintf("Cookie '%s' SameSite=None", cookie.Name),
				Severity:    "low",
				Category:    "A05:2021 Security Misconfiguration",
				CVSS:        3.1,
				CWE:         "CWE-1275",
				URL:         target,
				Parameter:   cookie.Name,
				Evidence:    fmt.Sprintf("Cookie '%s' has SameSite=None, vulnerable to CSRF in older browsers", cookie.Name),
				Impact:      "Cookie sent with cross-origin requests, enabling CSRF attacks",
				Remediation: "Set SameSite=Lax or SameSite=Strict on sensitive cookies",
				References:  []string{"https://cwe.mitre.org/data/definitions/1275.html", "https://owasp.org/www-community/SameSite"},
			})
		}

		// Session cookie without expiry
		atomic.AddInt64(&vs.Results.TotalChecks, 1)
		nameLower := strings.ToLower(cookie.Name)
		isSessionCookie := strings.Contains(nameLower, "session") || strings.Contains(nameLower, "sid") ||
			strings.Contains(nameLower, "token") || strings.Contains(nameLower, "auth")
		if isSessionCookie && cookie.Expires.IsZero() && cookie.MaxAge == 0 {
			// Session cookie - no persistent expiry, which is actually good
		} else if isSessionCookie && !cookie.Expires.IsZero() && time.Until(cookie.Expires) > 24*time.Hour {
			vs.addFinding(Vulnerability{
				ID:          vs.nextVulnID("CK"),
				Title:       fmt.Sprintf("Session Cookie '%s' Has Long Expiry", cookie.Name),
				Severity:    "low",
				Category:    "A07:2021 Identification and Authentication Failures",
				CVSS:        3.1,
				CWE:         "CWE-613",
				URL:         target,
				Parameter:   cookie.Name,
				Evidence:    fmt.Sprintf("Session cookie '%s' expires at %s (> 24h)", cookie.Name, cookie.Expires.Format(time.RFC3339)),
				Impact:      "Long-lived session tokens increase the window of opportunity for session hijacking",
				Remediation: "Set short session expiry times and implement session rotation",
				References:  []string{"https://cwe.mitre.org/data/definitions/613.html"},
			})
		}
	}
}

// ---------------------------------------------------------------------------
// 10. CORS Misconfiguration
// ---------------------------------------------------------------------------

func (vs *VulnScanner) scanCORS() {
	if vs.Results == nil {
		return
	}
	target := normalizeURL(vs.Target)
	atomic.AddInt64(&vs.Results.TotalChecks, 1)

	// Test with various Origin headers
	origins := []string{
		"https://evil.com",
		"http://evil.com",
		"https://evil.com.attacker.com",
		"https://attacker.com%0aevil.com",
		"null",
	}

	foundWildcard := false
	foundReflection := false
	foundNull := false
	foundCreds := false

	for _, origin := range origins {
		req, err := http.NewRequest("GET", target, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Origin", origin)
		req.Header.Set("User-Agent", "Sift-vulnscanner/1.0")

		resp, err := vs.Client.Do(req)
		if err != nil {
			continue
		}
		_ = resp.Body.Close()

		acao := resp.Header.Get("Access-Control-Allow-Origin")
		acac := resp.Header.Get("Access-Control-Allow-Credentials")

		if acao == "" {
			continue
		}

		if acac == "true" && !foundCreds {
			foundCreds = true
			vs.addFinding(Vulnerability{
				ID:          vs.nextVulnID("CORS"),
				Title:       "CORS Credentials Allowed with Permissive Origin",
				Severity:    "medium",
				Category:    "A05:2021 Security Misconfiguration",
				CVSS:        5.3,
				CWE:         "CWE-942",
				URL:         target,
				Evidence:    fmt.Sprintf("Access-Control-Allow-Credentials: true with Access-Control-Allow-Origin: %s", acao),
				Impact:      "Browsers will send cookies/credentials with cross-origin requests to this origin",
				Remediation: "Never combine Access-Control-Allow-Credentials: true with wildcard or reflected origins",
				References:  []string{"https://cwe.mitre.org/data/definitions/942.html"},
			})
		}

		switch {
		case acao == "*" && !foundWildcard:
			foundWildcard = true
			vs.addFinding(Vulnerability{
				ID:          vs.nextVulnID("CORS"),
				Title:       "CORS Wildcard Origin Allowed",
				Severity:    "medium",
				Category:    "A05:2021 Security Misconfiguration",
				CVSS:        5.3,
				CWE:         "CWE-942",
				URL:         target,
				Evidence:    "Access-Control-Allow-Origin: * — accepts requests from any origin",
				Impact:      "Any website can make cross-origin requests to this API",
				Remediation: "Restrict CORS to specific trusted origins",
				References:  []string{"https://owasp.org/Top10/A05_2021-Security_Misconfiguration/", "https://cwe.mitre.org/data/definitions/942.html"},
			})

		case acao == origin && origin != "null" && !foundReflection:
			foundReflection = true
			vs.addFinding(Vulnerability{
				ID:          vs.nextVulnID("CORS"),
				Title:       "CORS Origin Reflection Vulnerability",
				Severity:    "high",
				Category:    "A05:2021 Security Misconfiguration",
				CVSS:        7.5,
				CWE:         "CWE-942",
				URL:         target,
				Evidence:    fmt.Sprintf("Request with Origin '%s' returned Access-Control-Allow-Origin: %s", origin, acao),
				Impact:      "Attacker-controlled origin is reflected in CORS headers, enabling credential theft",
				Remediation: "Validate Origin against a whitelist before reflecting it in CORS headers",
				References:  []string{"https://owasp.org/Top10/A05_2021-Security_Misconfiguration/", "https://cwe.mitre.org/data/definitions/942.html"},
			})

		case acao == "null" && origin == "null" && !foundNull:
			foundNull = true
			vs.addFinding(Vulnerability{
				ID:          vs.nextVulnID("CORS"),
				Title:       "CORS Allows 'null' Origin",
				Severity:    "medium",
				Category:    "A05:2021 Security Misconfiguration",
				CVSS:        5.3,
				CWE:         "CWE-942",
				URL:         target,
				Evidence:    "Access-Control-Allow-Origin: null — allows sandboxed iframe requests",
				Impact:      "Attacker can use sandboxed iframes to make authenticated cross-origin requests",
				Remediation: "Remove 'null' from the CORS origin whitelist",
				References:  []string{"https://cwe.mitre.org/data/definitions/942.html"},
			})
		}
	}
}
