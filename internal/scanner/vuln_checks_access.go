package scanner

import (
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync/atomic"
)

// ---------------------------------------------------------------------------
// 7. Default Credentials
// ---------------------------------------------------------------------------

func (vs *VulnScanner) scanDefaultCredentials() {
	if vs.Results == nil {
		return
	}
	target := normalizeURL(vs.Target)

	type credPair struct {
		username string
		password string
	}

	creds := []credPair{
		{"admin", "admin"},
		{"admin", "password"},
		{"admin", "1234"},
		{"admin", "admin123"},
		{"admin", ""},
		{"root", "root"},
		{"root", "toor"},
		{"root", "password"},
		{"root", ""},
		{"administrator", "administrator"},
		{"test", "test"},
		{"guest", "guest"},
		{"user", "user"},
		{"demo", "demo"},
	}

	loginEndpoints := []string{"/login", "/admin/login", "/wp-login.php", "/wp-admin/", "/administrator/", "/auth/login", "/signin", "/api/login", "/user/login"}

	for _, endpoint := range loginEndpoints {
		for _, cred := range creds {
			atomic.AddInt64(&vs.Results.TotalChecks, 1)

			u, err := url.Parse(target)
			if err != nil {
				continue
			}
			u.Path = endpoint

			formData := url.Values{
				"username": {cred.username},
				"password": {cred.password},
				"user":     {cred.username},
				"pass":     {cred.password},
				"email":    {cred.username},
			}

			resp, err := vs.postForm(u.String(), formData, nil)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			_ = resp.Body.Close()
			bodyStr := string(body)

			// Check for successful login indicators
			isLoginSuccess := false
			if resp.StatusCode == 200 || resp.StatusCode == 302 {
				successIndicators := []string{"dashboard", "welcome", "profile", "logout", "account", "settings"}
				failureIndicators := []string{"invalid", "incorrect", "wrong", "failed", "error", "denied", "unauthorized", "forbidden"}

				hasSuccess := false
				for _, ind := range successIndicators {
					if strings.Contains(strings.ToLower(bodyStr), ind) {
						hasSuccess = true
						break
					}
				}

				hasFailure := false
				for _, ind := range failureIndicators {
					if strings.Contains(strings.ToLower(bodyStr), ind) {
						hasFailure = true
						break
					}
				}

				if hasSuccess && !hasFailure {
					isLoginSuccess = true
				}
			}

			if isLoginSuccess && cred.password != "" {
				vs.addFinding(Vulnerability{
					ID:          vs.nextVulnID("AUTH"),
					Title:       "Default Credentials Accepted",
					Severity:    "critical",
					Category:    "A07:2021 Identification and Authentication Failures",
					CVSS:        9.8,
					CWE:         "CWE-798",
					URL:         u.String(),
					Parameter:   fmt.Sprintf("username=%s&password=%s", cred.username, cred.password),
					Evidence:    fmt.Sprintf("Login with %s/%s returned HTTP %d with success indicators", cred.username, cred.password, resp.StatusCode),
					Impact:      "Full unauthorized access to the application as an authenticated user",
					Remediation: "Change default credentials immediately, enforce strong password policies",
					References:  []string{"https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/", "https://cwe.mitre.org/data/definitions/798.html"},
					PoC:         fmt.Sprintf("POST %s with username=%s&password=%s", endpoint, cred.username, cred.password),
				})
				return
			}
		}
	}
}

// ---------------------------------------------------------------------------
// 8. API Security
// ---------------------------------------------------------------------------

func (vs *VulnScanner) scanAPISecurity() {
	if vs.Results == nil {
		return
	}
	target := normalizeURL(vs.Target)

	// Check common API endpoints
	apiPaths := []string{
		"/api/", "/api/v1/", "/api/v2/", "/api/users",
		"/api/admin/", "/graphql", "/api/config", "/api/debug",
	}

	for _, path := range apiPaths {
		atomic.AddInt64(&vs.Results.TotalChecks, 1)

		u, err := url.Parse(target)
		if err != nil {
			continue
		}
		u.Path = path

		resp, err := vs.get(u.String())
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()

		// Check for excessive data exposure
		vs.checkSensitiveExposure(u.String(), body)

		// Check for mass assignment — send extra params and see if accepted
		if resp.StatusCode == 200 || resp.StatusCode == 405 {
			extraParams := url.Values{
				"admin":       {"true"},
				"role":        {"admin"},
				"is_admin":    {"1"},
				"privileged":  {"true"},
				"permissions": {"all"},
			}
			baselineResp, err := vs.postForm(u.String(), url.Values{}, nil)
			if err != nil {
				continue
			}
			baselineBody, _ := io.ReadAll(io.LimitReader(baselineResp.Body, 1<<20))
			_ = baselineResp.Body.Close()

			massResp, err := vs.postForm(u.String(), extraParams, nil)
			if err == nil {
				massBody, _ := io.ReadAll(io.LimitReader(massResp.Body, 1<<20))
				_ = massResp.Body.Close()
				if massResp.StatusCode == 200 && len(massBody) > 0 &&
					(massResp.StatusCode != baselineResp.StatusCode || !strings.EqualFold(string(massBody), string(baselineBody))) {
					vs.addFinding(Vulnerability{
						ID:          vs.nextVulnID("API"),
						Title:       "Possible Mass Assignment Vulnerability",
						Severity:    "medium",
						Category:    "A04:2021 Insecure Design",
						CVSS:        5.3,
						CWE:         "CWE-915",
						URL:         u.String(),
						Evidence:    fmt.Sprintf("POST with extra privileged parameters accepted (HTTP %d), response differs from baseline", massResp.StatusCode),
						Impact:      "Attacker may escalate privileges by setting admin=true or role=admin in requests",
						Remediation: "Use allow-lists for bindable parameters, implement DTOs, validate all input",
						References:  []string{"https://owasp.org/Top10/A04_2021-Insecure_Design/", "https://cwe.mitre.org/data/definitions/915.html"},
					})
				}
			}
		}
	}

	// BOLA/IDOR check — try changing IDs in common patterns
	idEndpoints := []string{
		"/api/users/1", "/api/users/2",
		"/api/v1/users/1", "/api/v1/users/2",
		"/api/orders/1", "/api/orders/2",
		"/api/profile/1", "/api/profile/2",
	}

	for i := 0; i < len(idEndpoints)-1; i += 2 {
		atomic.AddInt64(&vs.Results.TotalChecks, 1)

		u1, err1 := url.Parse(target + idEndpoints[i])
		u2, err2 := url.Parse(target + idEndpoints[i+1])
		if err1 != nil || err2 != nil {
			continue
		}

		resp1, err1 := vs.get(u1.String())
		if err1 != nil {
			continue
		}
		body1, _ := io.ReadAll(io.LimitReader(resp1.Body, 1<<20))
		_ = resp1.Body.Close()

		resp2, err2 := vs.get(u2.String())
		if err2 != nil {
			continue
		}
		body2, _ := io.ReadAll(io.LimitReader(resp2.Body, 1<<20))
		_ = resp2.Body.Close()

		if resp1.StatusCode == 200 && resp2.StatusCode == 200 && len(body1) > 0 && len(body2) > 0 {
			vs.checkSensitiveExposure(u1.String(), body1)
			vs.checkSensitiveExposure(u2.String(), body2)

			if !strings.EqualFold(string(body1), string(body2)) {
				vs.addFinding(Vulnerability{
					ID:          vs.nextVulnID("API"),
					Title:       "Potential BOLA/IDOR Vulnerability",
					Severity:    "high",
					Category:    "A01:2021 Broken Access Control",
					CVSS:        7.5,
					CWE:         "CWE-639",
					URL:         fmt.Sprintf("%s vs %s", u1.String(), u2.String()),
					Evidence:    fmt.Sprintf("Sequential IDs return different data (resp1: %d bytes, resp2: %d bytes)", len(body1), len(body2)),
					Impact:      "Attacker can access other users' data by incrementing IDs",
					Remediation: "Implement object-level authorization checks, use UUIDs instead of sequential IDs",
					References:  []string{"https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/", "https://cwe.mitre.org/data/definitions/639.html"},
				})
			}
		}
	}

	// Missing rate limiting
	atomic.AddInt64(&vs.Results.TotalChecks, 1)
	u, _ := url.Parse(target)
	u.Path = "/api/"
	rateLimitSuccess := 0
	for i := 0; i < 20; i++ {
		resp, err := vs.get(u.String())
		if err != nil {
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 429 {
			rateLimitSuccess++
		}
	}
	if rateLimitSuccess == 20 {
		vs.addFinding(Vulnerability{
			ID:          vs.nextVulnID("API"),
			Title:       "Missing Rate Limiting",
			Severity:    "medium",
			Category:    "A05:2021 Security Misconfiguration",
			CVSS:        5.3,
			CWE:         "CWE-770",
			URL:         u.String(),
			Evidence:    "20 rapid requests returned no 429 (Too Many Requests) responses",
			Impact:      "Application vulnerable to brute force, credential stuffing, and denial of service",
			Remediation: "Implement rate limiting with exponential backoff, use WAF or API gateway rate limits",
			References:  []string{"https://owasp.org/Top10/A05_2021-Security_Misconfiguration/", "https://cwe.mitre.org/data/definitions/770.html"},
		})
	}
}

// checkSensitiveExposure flags API responses that leak sensitive fields
func (vs *VulnScanner) checkSensitiveExposure(targetURL string, body []byte) {
	bodyStr := string(body)

	// Only structured data (JSON) counts — avoid false positives on HTML login pages
	if !strings.Contains(bodyStr, "{") && !strings.Contains(bodyStr, "[") {
		return
	}

	sensitivePatterns := []string{
		"password", "token", "secret", "api_key", "apikey",
		"credit_card", "ssn", "social_security",
	}
	for _, pattern := range sensitivePatterns {
		if strings.Contains(strings.ToLower(bodyStr), pattern) {
			vs.addFinding(Vulnerability{
				ID:          vs.nextVulnID("API"),
				Title:       "Excessive Data Exposure in API Response",
				Severity:    "high",
				Category:    "A02:2021 Cryptographic Failures",
				CVSS:        7.5,
				CWE:         "CWE-200",
				URL:         targetURL,
				Evidence:    fmt.Sprintf("API response (%d bytes) contains sensitive pattern '%s'", len(body), pattern),
				Impact:      "Sensitive data returned to unauthorized users via API responses",
				Remediation: "Implement response filtering, use DTOs, apply field-level authorization",
				References:  []string{"https://owasp.org/API-Security/editions/2023/en/0xa2-broken-object-level-authorization/", "https://cwe.mitre.org/data/definitions/200.html"},
			})
			return
		}
	}
}
