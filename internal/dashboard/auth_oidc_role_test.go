package dashboard

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/asadbekabdulboqiyev/sift/internal/rbac"
)

// TestOIDCClaimCannotGrantAdmin is the regression test for the privilege
// escalation: an ID token claim value must never become a local role name on
// its own, and the operator's RBACRoles assignment must remain authoritative.
func TestOIDCClaimCannotGrantAdmin(t *testing.T) {
	const subject = "alice@example.com"

	t.Run("unmapped admin claim is rejected and viewer restriction survives", func(t *testing.T) {
		a := NewAuth(AuthConfig{
			RBACEnabled: true,
			RBACRoles: map[string][]string{
				subject:  {"viewer"},
				"viewer": {"tests:view"},
			},
		})
		defer a.Close()

		roles := a.rolesFromClaims(map[string]any{"role": "admin"})
		if len(roles) != 0 {
			t.Fatalf("roles = %q, want none: an unmapped claim must grant nothing", roles)
		}
		if a.rbacAllowed(subject, roles, rbac.PermAdmin) {
			t.Fatal("unmapped admin claim granted admin:access (privilege escalation)")
		}
		if !a.rbacAllowed(subject, roles, rbac.PermView) {
			t.Fatal("operator-assigned viewer role was lost")
		}
	})

	t.Run("unmapped benign claim is also ignored (fail closed)", func(t *testing.T) {
		a := NewAuth(AuthConfig{})
		defer a.Close()

		for _, claim := range []string{"viewer", "engineer", "admin", " ADMIN "} {
			if roles := a.rolesFromClaims(map[string]any{"role": claim}); len(roles) != 0 {
				t.Errorf("claim %q produced roles %q with no OIDCRoleMap", claim, roles)
			}
		}
	})

	t.Run("operator mapping to viewer works", func(t *testing.T) {
		a := NewAuth(AuthConfig{
			OIDCRoleMap: map[string]string{"analyst": "viewer"},
			RBACEnabled: true,
			RBACRoles: map[string][]string{
				"viewer": {"tests:view"},
			},
		})
		defer a.Close()

		roles := a.rolesFromClaims(map[string]any{"role": "analyst"})
		if want := []string{"viewer"}; !reflect.DeepEqual(roles, want) {
			t.Fatalf("roles = %q, want %q", roles, want)
		}
		if !a.rbacAllowed(subject, roles, rbac.PermView) {
			t.Fatal("mapped viewer role did not grant tests:view")
		}
		if a.rbacAllowed(subject, roles, rbac.PermAdmin) {
			t.Fatal("mapped viewer role granted admin:access")
		}
	})

	t.Run("claim value admin is only an identifier, never a role name", func(t *testing.T) {
		// Even when the operator maps the literal claim value "admin", the
		// target local role is what counts; the value itself is not a role.
		a := NewAuth(AuthConfig{
			OIDCRoleMap: map[string]string{"admin": "viewer"},
			RBACEnabled: true,
			RBACRoles: map[string][]string{
				"viewer": {"tests:view"},
			},
		})
		defer a.Close()

		roles := a.rolesFromClaims(map[string]any{"role": "admin"})
		if want := []string{"viewer"}; !reflect.DeepEqual(roles, want) {
			t.Fatalf("roles = %q, want %q", roles, want)
		}
		if a.rbacAllowed(subject, roles, rbac.PermAdmin) {
			t.Fatal("claim value admin was used directly as a role name")
		}
	})

	t.Run("array claim with custom claim name maps only allowlisted values", func(t *testing.T) {
		a := NewAuth(AuthConfig{
			OIDCRoleClaim: "roles",
			OIDCRoleMap:   map[string]string{"eng": "engineer", "root": "viewer"},
		})
		defer a.Close()

		claims := map[string]any{"roles": []any{"eng", "admin", "root", "ghost"}}
		roles := a.rolesFromClaims(claims)
		if want := []string{"engineer", "viewer"}; !reflect.DeepEqual(roles, want) {
			t.Fatalf("roles = %q, want %q", roles, want)
		}
	})
}

// TestOIDCRoleMapNeverTargetsAdmin verifies both enforcement points: config
// normalization drops admin mappings, and the conversion function refuses an
// admin target even if a raw map reaches it.
func TestOIDCRoleMapNeverTargetsAdmin(t *testing.T) {
	a := NewAuth(AuthConfig{
		OIDCRoleMap: map[string]string{
			"analyst": "viewer",
			"root":    "admin",
			"boss":    "ADMIN",
		},
	})
	defer a.Close()

	if _, ok := a.cfg.OIDCRoleMap["root"]; ok {
		t.Error("mapping to admin survived normalization")
	}
	if _, ok := a.cfg.OIDCRoleMap["boss"]; ok {
		t.Error("mapping to ADMIN survived case-insensitive normalization")
	}
	if roles := a.rolesFromClaims(map[string]any{"role": "root"}); len(roles) != 0 {
		t.Fatalf("admin-target mapping produced roles %q", roles)
	}

	// Defense in depth: the conversion itself rejects admin targets.
	raw := map[string]string{"root": "admin", "analyst": "viewer"}
	got := mapOIDCRoleClaimRoles([]string{"root", "analyst"}, raw)
	if want := []string{"viewer"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("mapOIDCRoleClaimRoles = %q, want %q", got, want)
	}
}

// TestCompactOIDCRoleMap checks trimming, blank removal and admin rejection.
func TestCompactOIDCRoleMap(t *testing.T) {
	got := compactOIDCRoleMap(map[string]string{
		" analyst ": " viewer ",
		"empty":     "   ",
		"   ":       "viewer",
		"elevated":  "Admin",
	})
	want := map[string]string{"analyst": "viewer"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("compactOIDCRoleMap = %q, want %q", got, want)
	}
	if compactOIDCRoleMap(map[string]string{"x": "admin"}) != nil {
		t.Fatal("an all-admin map should normalize to nil")
	}
}

// TestOIDCRoleMapJSONConfig pins the JSON config key for operators. Both the
// middleware config and the higher-level options use snake_case, matching the
// rest of the project's serialized configuration.
func TestOIDCRoleMapJSONConfig(t *testing.T) {
	const payload = `{"oidc_role_map":{"analyst":"viewer"}}`

	var cfg AuthConfig
	if err := json.Unmarshal([]byte(payload), &cfg); err != nil {
		t.Fatalf("unmarshal AuthConfig: %v", err)
	}
	if cfg.OIDCRoleMap["analyst"] != "viewer" {
		t.Fatalf("AuthConfig.OIDCRoleMap = %q", cfg.OIDCRoleMap)
	}

	var opt AuthOptions
	if err := json.Unmarshal([]byte(payload), &opt); err != nil {
		t.Fatalf("unmarshal AuthOptions: %v", err)
	}
	if opt.OIDCRoleMap["analyst"] != "viewer" {
		t.Fatalf("AuthOptions.OIDCRoleMap = %q", opt.OIDCRoleMap)
	}

	// ApplyAuth forwards the normalized allowlist: the admin mapping is
	// dropped during normalization and must not reach the middleware.
	srv := NewServer()
	a := srv.ApplyAuth(AuthOptions{
		Tokens:      []string{"tok"},
		OIDCRoleMap: map[string]string{"analyst": "viewer", "root": "admin"},
	})
	if a == nil {
		t.Fatal("ApplyAuth returned nil")
	}
	defer a.Close()
	if got := a.cfg.OIDCRoleMap; !reflect.DeepEqual(got, map[string]string{"analyst": "viewer"}) {
		t.Fatalf("forwarded OIDCRoleMap = %q", got)
	}
}
