package dashboard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSplitSecurityCSPOnEveryResponseClass pins the defense-in-depth headers
// after server.go was split into focused files. securityHeaders runs in
// ServeHTTP before any route dispatch, so every response class - including the
// operations endpoints and the unknown-API 404 - must carry the same CSP.
func TestSplitSecurityCSPOnEveryResponseClass(t *testing.T) {
	for _, path := range []string{
		"/",
		"/style.css",
		"/app.js",
		"/api/snapshot",
		"/api/not-a-real-endpoint",
		"/healthz",
	} {
		t.Run(path, func(t *testing.T) {
			s := NewServer()
			rec := httptest.NewRecorder()
			s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))

			csp := rec.Header().Get("Content-Security-Policy")
			if csp == "" {
				t.Fatal("response is missing Content-Security-Policy")
			}
			for _, directive := range []string{
				"default-src 'self'",
				"script-src 'self'",
				"object-src 'none'",
				"base-uri 'none'",
				"frame-ancestors 'self'",
			} {
				if !strings.Contains(csp, directive) {
					t.Errorf("CSP missing %q: %q", directive, csp)
				}
			}
			// Inline styles are scoped to the signed certificate preview only;
			// an inline-script exception anywhere would defeat the CSP entirely.
			for _, d := range strings.Split(csp, ";") {
				d = strings.TrimSpace(d)
				if strings.HasPrefix(d, "script-src") || strings.HasPrefix(d, "default-src") {
					if strings.Contains(d, "unsafe-inline") {
						t.Errorf("directive allows inline script: %q", d)
					}
				}
			}
			if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
				t.Errorf("X-Frame-Options = %q, want DENY", got)
			}
			if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
			}
		})
	}
}

// TestSplitSecurityHostGatePrecedesOpsDispatch verifies the ordering in
// ServeHTTP that the split preserves: Host validation happens before the
// operations-endpoint switch, so a DNS-rebinding request cannot reach /healthz
// even though operations endpoints are exempt from auth.
func TestSplitSecurityHostGatePrecedesOpsDispatch(t *testing.T) {
	s := NewServer()
	for _, path := range []string{"/healthz", "/readyz", "/metrics", "/api/version"} {
		t.Run(path, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, path, nil)
			r.Host = "attacker.example:8888"
			r = withLocalAddr(r, "127.0.0.1:8888")

			rec := httptest.NewRecorder()
			s.ServeHTTP(rec, r)
			if rec.Code != http.StatusMisdirectedRequest {
				t.Errorf("status = %d, want 421 (rebinding request must not reach handler)", rec.Code)
			}
			if strings.Contains(rec.Body.String(), "status") {
				t.Errorf("handler body leaked past the host gate: %q", rec.Body.String())
			}
		})
	}
}

// TestSafeCSPHost admits only syntactically valid host[:port] values that can
// be placed verbatim in a CSP source expression. Anything that could inject a
// directive, attribute or extra source is rejected.
func TestSafeCSPHost(t *testing.T) {
	for _, host := range []string{
		"localhost:8080",
		"127.0.0.1:8080",
		"[::1]:8080",
		"app.example.com",
	} {
		if got := safeCSPHost(host); got != host {
			t.Errorf("safeCSPHost(%q) = %q, want unchanged", host, got)
		}
	}
	for _, host := range []string{
		"",
		"app.example.com; script-src *",
		"app.example.com' onload='alert(1)",
		"app.example.com/evil",
		"app.example.com,https://evil.example",
		"bad_host:8080",
		"app.example.com:notaport",
		strings.Repeat("a", 256),
	} {
		if got := safeCSPHost(host); got != "" {
			t.Errorf("safeCSPHost(%q) = %q, want empty", host, got)
		}
	}
}

// TestCSPCannotBeInjectedViaHost proves a malicious Host header cannot add a
// directive to Content-Security-Policy: the explicit ws/wss sources are dropped
// when the host fails validation.
func TestCSPCannotBeInjectedViaHost(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://dashboard.local/", nil)
	req.Host = "x; script-src *; connect-src *"
	w := httptest.NewRecorder()
	securityHeaders(w, req)
	csp := w.Header().Get("Content-Security-Policy")
	if strings.Contains(csp, "script-src *") || strings.Contains(csp, "ws://") {
		t.Fatalf("CSP injectable via Host: %s", csp)
	}
	if !strings.Contains(csp, "connect-src 'self'") || !strings.Contains(csp, "script-src 'self'") {
		t.Errorf("safe CSP directives missing: %s", csp)
	}

	valid := httptest.NewRequest(http.MethodGet, "http://dashboard.local/", nil)
	valid.Host = "localhost:8080"
	vw := httptest.NewRecorder()
	securityHeaders(vw, valid)
	if vcsp := vw.Header().Get("Content-Security-Policy"); !strings.Contains(vcsp, "ws://localhost:8080 wss://localhost:8080") {
		t.Errorf("valid host did not get WebSocket sources: %s", vcsp)
	}
}
