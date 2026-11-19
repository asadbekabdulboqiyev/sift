package dashboard

import (
	"strings"
)

// AuthOptions configures the dashboard control-plane gate from CLI flags or
// environment configuration.
type AuthOptions struct {
	// Tokens are accepted verbatim as `Authorization: Bearer <token>`.
	Tokens []string
	// APIKeyHashes are lowercase hex SHA-256 digests of accepted API keys.
	APIKeyHashes []string
	// AllowedOrigins is the CSRF allowlist for state-changing methods.
	AllowedOrigins []string
	// RateLimitRPS refills each client IP's token bucket; 0 disables.
	RateLimitRPS float64
	// RateLimitBurst is the limiter capacity; defaults to 1.
	RateLimitBurst int
	// TrustProxy makes the limiter honor X-Forwarded-For / X-Real-IP.
	TrustProxy bool
	// AllowAnonymous explicitly acknowledges that the control API is reachable
	// without credentials when bound to a non-loopback address. It is an
	// opt-in escape hatch (CLI: -insecure / --dashboard-insecure) for demos
	// whose host port is published on loopback only; it never enables anything
	// by accident and is ignored when credentials are enrolled.
	AllowAnonymous bool

	// OIDCIssuer is the OpenID Connect issuer URL. When non-empty, bearer
	// tokens are verified as OIDC ID tokens against this provider.
	OIDCIssuer string

	// OIDCClientID is the OAuth client ID registered with the OIDC provider.
	OIDCClientID string

	// OIDCRoleClaim is the ID token claim name used to extract the user role.
	OIDCRoleClaim string

	// RBACEnabled turns on role-based access control for state-changing
	// endpoints.
	RBACEnabled bool

	// RBACRole is a role assignment in the form "subject:role1,role2".
	// Repeatable for multiple subjects.
	RBACRole []string
}

// HasCredentials reports whether at least one credential is enrolled. Only
// bearer tokens and API keys authenticate callers; an origin allowlist alone
// still rejects every caller (secure by default).
func (o AuthOptions) HasCredentials() bool {
	return len(o.Tokens) > 0 || len(o.APIKeyHashes) > 0 || o.OIDCIssuer != ""
}

// ApplyAuth builds the authentication middleware from opt, installs it on the
// server and returns the backing *Auth so the caller can Close it (releasing
// the rate-limit janitor). The operations endpoints stay open for probes and
// scrapes. When no credential is enrolled it installs nothing and returns nil —
// callers must decide whether an open dashboard is acceptable for their bind
// address (loopback, or an explicit -insecure acknowledgement).
func (s *Server) ApplyAuth(opt AuthOptions) *Auth {
	if !opt.HasCredentials() {
		return nil
	}
	// Parse RBACRole flags ("subject:role1,role2") into a map.
	rbacRoles := make(map[string][]string)
	for _, entry := range opt.RBACRole {
		parts := strings.SplitN(entry, ":", 2)
		if len(parts) != 2 {
			continue
		}
		sub := strings.TrimSpace(parts[0])
		roles := strings.Split(parts[1], ",")
		for i, r := range roles {
			roles[i] = strings.TrimSpace(r)
		}
		rbacRoles[sub] = roles
	}
	a := NewAuth(AuthConfig{
		BearerTokens:   opt.Tokens,
		APIKeyHashes:   opt.APIKeyHashes,
		AllowedOrigins: opt.AllowedOrigins,
		RateLimitRPS:   opt.RateLimitRPS,
		RateLimitBurst: opt.RateLimitBurst,
		TrustProxy:     opt.TrustProxy,
		OIDCIssuer:     opt.OIDCIssuer,
		OIDCClientID:   opt.OIDCClientID,
		OIDCRoleClaim:  opt.OIDCRoleClaim,
		RBACEnabled:    opt.RBACEnabled,
		RBACRoles:      rbacRoles,
	})
	s.auth = a
	s.SetAuthMiddleware(a.Middleware)
	return a
}
