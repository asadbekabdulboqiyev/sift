package dashboard

import (
	"net/http"
	"testing"
)

func TestPermForPath(t *testing.T) {
	cases := []struct {
		path, method, want string
	}{
		// Admin surface: the path wins over the method. GET is not a read-only
		// escape hatch for the control plane — it must still carry admin:access.
		{"/api/admin/status", http.MethodGet, "admin:access"},
		{"/api/admin/unlock", http.MethodPost, "admin:access"},
		{"/api/admin/lock", http.MethodPost, "admin:access"},
		{"/api/admin/lock/unlock", http.MethodPost, "admin:access"},
		{"/api/admin/x", http.MethodGet, "admin:access"},
		{"/api/admin/x", http.MethodDelete, "admin:access"},
		{"/api/admin/x", http.MethodPut, "admin:access"},
		// Audit surface: every method maps to audit:read, including POST.
		{"/api/audit", http.MethodGet, "audit:read"},
		{"/api/audit", http.MethodPost, "audit:read"},
		{"/api/audit", http.MethodPut, "audit:read"},
		{"/api/audit", http.MethodDelete, "audit:read"},
		{"/api/audit-360", http.MethodPost, "audit:read"},
		{"/api/audit-360/status", http.MethodGet, "audit:read"},
		{"/api/audit-360/stream", http.MethodGet, "audit:read"},
		// Run endpoints map to tests:run for every method.
		{"/api/run", http.MethodGet, "tests:run"},
		{"/api/run", http.MethodPost, "tests:run"},
		{"/api/run/start", http.MethodPost, "tests:run"},
		// Ordinary reads stay tests:view; other mutations need tests:run.
		{"/api/history", http.MethodGet, "tests:view"},
		{"/api/certificate/download/abc", http.MethodGet, "tests:view"},
		{"/api/anything", http.MethodGet, "tests:view"},
		{"/api/anything", http.MethodHead, "tests:view"},
		{"/api/anything", http.MethodPost, "tests:run"},
		{"/api/anything", http.MethodPatch, "tests:run"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.path+" "+tc.method, func(t *testing.T) {
			if got := permForPath(tc.path, tc.method); got != tc.want {
				t.Errorf("permForPath(%q,%q) = %q, want %q", tc.path, tc.method, got, tc.want)
			}
		})
	}
}

// TestRBACMiddlewareGuardsReadOnlyMethods pins the broken-access-control fix
// at the middleware layer: removing the isSafeMethod exemption means a GET is
// authorized like any other request.
func TestRBACMiddlewareGuardsReadOnlyMethods(t *testing.T) {
	// Bearer credentials authenticate as "bearer:<hash-prefix>", so role
	// assignments must be keyed by that subject exactly as in production.
	viewerToken, runnerToken := "viewer-tok", "runner-tok"
	viewerSubject := "bearer:" + shortID(HashKey(viewerToken))
	runnerSubject := "bearer:" + shortID(HashKey(runnerToken))
	a := NewAuth(AuthConfig{
		BearerTokens: []string{viewerToken, runnerToken},
		RBACEnabled:  true,
		RBACRoles: map[string][]string{
			viewerSubject: {"viewer"},
			runnerSubject: {"runner"},
			"viewer":      {"tests:view"},
			"runner":      {"tests:run", "tests:view"},
		},
	})
	defer a.Close()

	withRole := func(role string) func(*http.Request) {
		token := viewerToken
		if role == "runner" {
			token = runnerToken
		}
		return authBearer("Bearer " + token)
	}

	cases := []struct {
		name, path, method, role string
		want                     int
	}{
		{"viewer can read history", "/api/history", http.MethodGet, "viewer", http.StatusOK},
		{"viewer cannot read admin status via GET", "/api/admin/status", http.MethodGet, "viewer", http.StatusForbidden},
		{"viewer cannot POST admin unlock", "/api/admin/unlock", http.MethodPost, "viewer", http.StatusForbidden},
		{"runner still cannot read admin status", "/api/admin/status", http.MethodGet, "runner", http.StatusForbidden},
		{"viewer cannot POST audit-360", "/api/audit-360", http.MethodPost, "viewer", http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := authRequest(t, a, tc.method, tc.path, withRole(tc.role))
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
		})
	}
}
