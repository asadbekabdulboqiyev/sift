package scanner

import (
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// 1. SQL Injection Detection
// ---------------------------------------------------------------------------

func (vs *VulnScanner) scanSQLInjection() {
	if vs.Results == nil {
		return
	}
	target := normalizeURL(vs.Target)
	params := []string{"id", "user", "search", "q", "page", "cat", "item", "sort", "order", "filter", "type", "name", "email"}
	payloads := []struct {
		payload   string
		signature string
	}{
		// Only error-based signatures belong in the default deep scan. A
		// destructive statement (DROP TABLE) can damage an authorized production
		// database, and time-based payloads (SLEEP/WAITFOR) are a deliberate DoS.
		// Those belong to the separate, explicitly opted-in intrusive module.
		{"' OR 1=1--", "sql"},
		{`" OR ""="`, "sql"},
		{"1' UNION SELECT NULL--", "sql"},
		{"1' AND '1'='1", "sql"},
	}

	sqlErrorPatterns := []string{
		"sql syntax", "mysql", "sqlite", "postgresql", "oracle",
		"unclosed quotation mark", "quoted string not properly terminated",
		"Microsoft OLE DB", "ODBC SQL Server", "ORA-01756",
		"syntax error", "SQLSTATE", "mysql_fetch", "pg_query",
		"valid MySQL result", "MySqlClient", "pg_exec",
		"Warning: mysql", "Fatal error: Uncaught PDOException",
		"SQL syntax.*MySQL", "valid PostgreSQL result",
		"Npgsql\\.", "PG::SyntaxError", "org.postgresql",
		"SQLite/JDBCDriver", "SQLite\\.Exception",
		"System\\.Data\\.SQLite\\.SQLiteException",
		"Unclosed quotation mark after the character string",
		"Microsoft SQL Native Client error",
	}

	for _, param := range params {
		for _, p := range payloads {
			atomic.AddInt64(&vs.Results.TotalChecks, 1)

			u, err := url.Parse(target)
			if err != nil {
				continue
			}
			q := u.Query()
			q.Set(param, p.payload)
			u.RawQuery = q.Encode()

			start := time.Now()
			resp, err := vs.get(u.String())
			elapsed := time.Since(start)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			_ = resp.Body.Close()
			bodyStr := string(body)

			found := false

			if p.signature == "time" {
				if elapsed > 4*time.Second {
					found = true
				}
			} else {
				for _, pattern := range sqlErrorPatterns {
					if matched, _ := regexp.MatchString("(?i)"+pattern, bodyStr); matched {
						found = true
						break
					}
				}
			}

			if found {
				vs.addFinding(Vulnerability{
					ID:          vs.nextVulnID("SQL"),
					Title:       "SQL Injection Detected",
					Severity:    "critical",
					Category:    "A03:2021 Injection",
					CVSS:        9.8,
					CWE:         "CWE-89",
					URL:         u.String(),
					Parameter:   param,
					Evidence:    fmt.Sprintf("Payload '%s' triggered SQL error response (status %d)", p.payload, resp.StatusCode),
					Impact:      "Attacker can execute arbitrary SQL queries, read/modify/delete data, potentially achieve RCE",
					Remediation: "Use parameterized queries/prepared statements. Implement input validation and WAF rules.",
					References:  []string{"https://owasp.org/Top10/A03_2021-Injection/", "https://cwe.mitre.org/data/definitions/89.html"},
					PoC:         fmt.Sprintf("GET %s?%s=%s", u.Path, param, url.QueryEscape(p.payload)),
				})
				break
			}
		}
	}
}

// ---------------------------------------------------------------------------
// 2. XSS Detection
// ---------------------------------------------------------------------------

func (vs *VulnScanner) scanXSS() {
	if vs.Results == nil {
		return
	}
	target := normalizeURL(vs.Target)
	params := []string{"q", "search", "name", "comment", "input", "text", "query", "title", "description", "redirect", "url"}
	payloads := []string{
		`<script>alert(1)</script>`,
		`<img src=x onerror=alert(1)>`,
		`"><svg onload=alert(1)>`,
		`<body onload=alert(1)>`,
		`javascript:alert(1)`,
		`<iframe src="javascript:alert(1)">`,
		`<input onfocus=alert(1) autofocus>`,
		`<details open ontoggle=alert(1)>`,
		`"><img src=x onerror=alert(String.fromCharCode(88,83,83))>`,
		`'-alert(1)-'`,
	}

	for _, param := range params {
		for _, payload := range payloads {
			atomic.AddInt64(&vs.Results.TotalChecks, 1)

			u, err := url.Parse(target)
			if err != nil {
				continue
			}
			q := u.Query()
			q.Set(param, payload)
			u.RawQuery = q.Encode()

			resp, err := vs.get(u.String())
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			_ = resp.Body.Close()
			bodyStr := string(body)

			if strings.Contains(bodyStr, payload) {
				vs.addFinding(Vulnerability{
					ID:          vs.nextVulnID("XSS"),
					Title:       "Cross-Site Scripting (XSS) Detected",
					Severity:    "high",
					Category:    "A03:2021 Injection",
					CVSS:        6.1,
					CWE:         "CWE-79",
					URL:         u.String(),
					Parameter:   param,
					Evidence:    fmt.Sprintf("Reflected payload '%s' found in response body", payload),
					Impact:      "Attacker can execute arbitrary JavaScript in victim's browser, steal session tokens, redirect users, deface websites",
					Remediation: "Implement context-aware output encoding, Content-Security-Policy header, and input validation",
					References:  []string{"https://owasp.org/Top10/A03_2021-Injection/", "https://cwe.mitre.org/data/definitions/79.html"},
					PoC:         fmt.Sprintf("GET %s?%s=%s", u.Path, param, url.QueryEscape(payload)),
				})
				break
			}
		}
	}
}

// ---------------------------------------------------------------------------
// 3. Directory Traversal
// ---------------------------------------------------------------------------

func (vs *VulnScanner) scanDirectoryTraversal() {
	if vs.Results == nil {
		return
	}
	target := normalizeURL(vs.Target)
	endpoints := []string{"/", "/view", "/file", "/include", "/page", "/download", "/static", "/images"}
	payloads := []struct {
		payload   string
		signature string
	}{
		{"../../../etc/passwd", "root:"},
		{"....//....//....//etc/passwd", "root:"},
		{"..%2F..%2F..%2Fetc%2Fpasswd", "root:"},
		{"..%252f..%252f..%252fetc/passwd", "root:"},
		{"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd", "root:"},
		{"../../../etc/shadow", "root:"},
		{"../../../proc/self/environ", "PATH="},
		{"..\\..\\..\\etc\\passwd", "root:"},
		{"../../../win.ini", "[extensions]"},
		{"..\\..\\..\\windows\\win.ini", "[extensions]"},
	}

	for _, endpoint := range endpoints {
		for _, p := range payloads {
			atomic.AddInt64(&vs.Results.TotalChecks, 1)

			u, err := url.Parse(target)
			if err != nil {
				continue
			}
			q := u.Query()
			q.Set("file", p.payload)
			q.Set("path", p.payload)
			u.RawQuery = q.Encode()
			u.Path = endpoint

			resp, err := vs.get(u.String())
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			_ = resp.Body.Close()
			bodyStr := string(body)

			if strings.Contains(bodyStr, p.signature) {
				vs.addFinding(Vulnerability{
					ID:          vs.nextVulnID("DIR"),
					Title:       "Directory Traversal / Path Traversal Detected",
					Severity:    "critical",
					Category:    "A01:2021 Broken Access Control",
					CVSS:        9.1,
					CWE:         "CWE-22",
					URL:         u.String(),
					Evidence:    fmt.Sprintf("Payload '%s' returned system file content (matched '%s')", p.payload, p.signature),
					Impact:      "Attacker can read arbitrary files on the server including /etc/passwd, application source code, credentials, and private keys",
					Remediation: "Validate and sanitize file paths, use chroot/jails, prevent path separators in user input",
					References:  []string{"https://owasp.org/Top10/A01_2021-Broken_Access_Control/", "https://cwe.mitre.org/data/definitions/22.html"},
					PoC:         fmt.Sprintf("GET %s?file=%s", u.Path, url.QueryEscape(p.payload)),
				})
				break
			}
		}
	}
}

// ---------------------------------------------------------------------------
// 4. Open Redirect
// ---------------------------------------------------------------------------

func (vs *VulnScanner) scanOpenRedirect() {
	if vs.Results == nil {
		return
	}
	target := normalizeURL(vs.Target)
	redirectParams := []string{"url", "redirect", "next", "return", "continue", "dest", "destination", "redir", "redirect_url", "return_to", "checkout_url", "return_url", "go", "out"}
	payloads := []string{
		"//evil.com",
		"//evil.com/path",
		"/redirect?url=//evil.com",
		"https://evil.com",
		"//evil.com%2F.evil.com",
		`//evil.com%0aevil.com`,
	}

	for _, param := range redirectParams {
		for _, payload := range payloads {
			atomic.AddInt64(&vs.Results.TotalChecks, 1)

			u, err := url.Parse(target)
			if err != nil {
				continue
			}
			q := u.Query()
			q.Set(param, payload)
			u.RawQuery = q.Encode()

			resp, err := vs.get(u.String())
			if err != nil {
				continue
			}
			_ = resp.Body.Close()

			location := resp.Header.Get("Location")
			if location == "" {
				continue
			}

			parsedLoc, err := url.Parse(location)
			if err != nil {
				continue
			}

			isRedirect := false
			if strings.Contains(parsedLoc.Host, "evil.com") {
				isRedirect = true
			}
			if strings.Contains(location, "evil.com") && resp.StatusCode >= 300 && resp.StatusCode < 400 {
				isRedirect = true
			}

			if isRedirect {
				vs.addFinding(Vulnerability{
					ID:          vs.nextVulnID("REDIR"),
					Title:       "Open Redirect Vulnerability",
					Severity:    "medium",
					Category:    "A01:2021 Broken Access Control",
					CVSS:        6.1,
					CWE:         "CWE-601",
					URL:         u.String(),
					Parameter:   param,
					Evidence:    fmt.Sprintf("Parameter '%s' caused redirect to '%s' (status %d)", param, location, resp.StatusCode),
					Impact:      "Attacker can craft phishing URLs that appear legitimate, bypass open redirect filters for OAuth token theft",
					Remediation: "Validate redirect URLs against a whitelist of allowed domains, use relative URLs",
					References:  []string{"https://owasp.org/Top10/A01_2021-Broken_Access_Control/", "https://cwe.mitre.org/data/definitions/601.html"},
					PoC:         fmt.Sprintf("GET %s?%s=%s", u.Path, param, url.QueryEscape(payload)),
				})
				break
			}
		}
	}
}
