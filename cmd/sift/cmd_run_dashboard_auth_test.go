package main

import (
	"reflect"
	"testing"

	"github.com/asadbekabdulboqiyev/sift/internal/dashboard"
)

// parseRunAuthFlags exercises the real `sift run` FlagSet without invoking
// scenario loading or os.Args, so the mapping test stays deterministic.
func parseRunAuthFlags(t *testing.T, args ...string) *runOptions {
	t.Helper()
	o := &runOptions{headers: headerFlags{}}
	fs := newRunFlagSet(o)
	if err := fs.Parse(args); err != nil {
		t.Fatalf("parse run flags %q: %v", args, err)
	}
	return o
}

func TestRunDashboardAuthFlagsRegistered(t *testing.T) {
	o := &runOptions{headers: headerFlags{}}
	fs := newRunFlagSet(o)
	for _, name := range []string{
		"dashboard-auth-oidc",
		"dashboard-auth-rbac",
		"dashboard-auth-oidc-role-map",
		"dashboard-auth-rbac-enabled",
	} {
		if fs.Lookup(name) == nil {
			t.Errorf("run flag --%s is not registered", name)
		}
	}
}

func TestDashboardAuthOptionsMapsOIDCAndRBAC(t *testing.T) {
	o := parseRunAuthFlags(t,
		"--dashboard-auth-token", "token-a",
		"--dashboard-auth-api-key", "deadbeef",
		"--dashboard-auth-origin", "https://app.example.com",
		"--dashboard-auth-rate-limit", "7",
		"--dashboard-auth-rate-burst", "11",
		"--dashboard-auth-trust-proxy",
		"--dashboard-insecure",
		"--dashboard-auth-oidc", "https://issuer.example.com:client-123",
		"--dashboard-auth-rbac", "alice:operator,viewer",
		"--dashboard-auth-rbac-enabled",
	)

	got := dashboardAuthOptions(o)
	if got.OIDCIssuer != "https://issuer.example.com" {
		t.Errorf("OIDCIssuer = %q, want %q", got.OIDCIssuer, "https://issuer.example.com")
	}
	if got.OIDCClientID != "client-123" {
		t.Errorf("OIDCClientID = %q, want %q", got.OIDCClientID, "client-123")
	}
	if got.OIDCRoleClaim != "role" {
		t.Errorf("OIDCRoleClaim = %q, want %q (parity with sift-dashboard)", got.OIDCRoleClaim, "role")
	}
	if !got.RBACEnabled {
		t.Error("RBACEnabled = false, want true")
	}
	if want := []string{"alice:operator,viewer"}; !reflect.DeepEqual(got.RBACRole, want) {
		t.Errorf("RBACRole = %v, want %v", got.RBACRole, want)
	}

	// Existing fields must still be carried through unchanged.
	if want := []string{"token-a"}; !reflect.DeepEqual(got.Tokens, want) {
		t.Errorf("Tokens = %v, want %v", got.Tokens, want)
	}
	if want := []string{"deadbeef"}; !reflect.DeepEqual(got.APIKeyHashes, want) {
		t.Errorf("APIKeyHashes = %v, want %v", got.APIKeyHashes, want)
	}
	if want := []string{"https://app.example.com"}; !reflect.DeepEqual(got.AllowedOrigins, want) {
		t.Errorf("AllowedOrigins = %v, want %v", got.AllowedOrigins, want)
	}
	if got.RateLimitRPS != 7 || got.RateLimitBurst != 11 || !got.TrustProxy || !got.AllowAnonymous {
		t.Errorf("legacy auth fields changed: %+v", got)
	}
}

func TestDashboardAuthOptionsOIDCAndRBACDefaults(t *testing.T) {
	o := parseRunAuthFlags(t)
	got := dashboardAuthOptions(o)
	want := dashboard.AuthOptions{}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("default mapping = %+v, want zero AuthOptions %+v", got, want)
	}
}

func TestDashboardAuthOptionsOIDCEntryParsing(t *testing.T) {
	tests := []struct {
		name      string
		entries   []string
		issuer    string
		clientID  string
		roleClaim string
	}{
		{
			name:      "plain issuer:client",
			entries:   []string{"issuer.example.com:client-a"},
			issuer:    "issuer.example.com",
			clientID:  "client-a",
			roleClaim: "role",
		},
		{
			name:      "url issuer splits on last colon",
			entries:   []string{"https://issuer.example.com:8443:client-b"},
			issuer:    "https://issuer.example.com:8443",
			clientID:  "client-b",
			roleClaim: "role",
		},
		{
			name:      "malformed entries skipped",
			entries:   []string{"no-colon", ":missing-issuer", "missing-client:"},
			issuer:    "",
			clientID:  "",
			roleClaim: "",
		},
		{
			name:      "last valid pair wins",
			entries:   []string{"issuer-a:client-a", "malformed", "issuer-b:client-b"},
			issuer:    "issuer-b",
			clientID:  "client-b",
			roleClaim: "role",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			args := make([]string, 0, len(tc.entries)*2)
			for _, entry := range tc.entries {
				args = append(args, "--dashboard-auth-oidc", entry)
			}
			got := dashboardAuthOptions(parseRunAuthFlags(t, args...))
			if got.OIDCIssuer != tc.issuer || got.OIDCClientID != tc.clientID || got.OIDCRoleClaim != tc.roleClaim {
				t.Errorf("mapping = (%q, %q, %q), want (%q, %q, %q)",
					got.OIDCIssuer, got.OIDCClientID, got.OIDCRoleClaim,
					tc.issuer, tc.clientID, tc.roleClaim)
			}
		})
	}
}

// TestDashboardAuthOptionsOIDCRoleMapWiring proves the --dashboard-auth-oidc-role-map
// flag actually reaches AuthOptions. Without this the fail-closed OIDC role map
// stays empty and every claim-derived role is silently ignored at runtime.
func TestDashboardAuthOptionsOIDCRoleMapWiring(t *testing.T) {
	o := parseRunAuthFlags(t,
		"--dashboard-auth-oidc", "https://issuer.example.com:client-123",
		"--dashboard-auth-oidc-role-map", "analyst=viewer",
		"--dashboard-auth-oidc-role-map", "ops=operator",
	)
	got := dashboardAuthOptions(o)
	want := map[string]string{"analyst": "viewer", "ops": "operator"}
	if !reflect.DeepEqual(got.OIDCRoleMap, want) {
		t.Fatalf("OIDCRoleMap = %v, want %v", got.OIDCRoleMap, want)
	}
}

func TestDashboardAuthOptionsRBACDefaultsDisabled(t *testing.T) {
	o := parseRunAuthFlags(t, "--dashboard-auth-rbac", "alice:operator")
	got := dashboardAuthOptions(o)
	if got.RBACEnabled {
		t.Error("RBACEnabled = true, want false when --dashboard-auth-rbac-enabled is absent")
	}
	if want := []string{"alice:operator"}; !reflect.DeepEqual(got.RBACRole, want) {
		t.Errorf("RBACRole = %v, want %v", got.RBACRole, want)
	}
}
