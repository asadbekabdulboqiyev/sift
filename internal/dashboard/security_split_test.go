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
