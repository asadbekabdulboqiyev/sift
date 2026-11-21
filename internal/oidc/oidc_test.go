package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// --- In-test provider --------------------------------------------------------

// fakeProvider is an httptest OIDC provider that serves discovery, JWKS and a
// configurable token endpoint. The RSA and EC keys are generated per test so
// real signatures are verified end to end.
type fakeProvider struct {
	server *httptest.Server
	rsaKey *rsa.PrivateKey
	ecKey  *ecdsa.PrivateKey
	rsaKid string
	ecKid  string

	// lastForm captures the last token-endpoint form for assertions.
	lastForm url.Values
}

type fakeProviderConfig struct {
	// issuerOverride, when set, is returned as the discovery issuer (used to
	// exercise issuer-mismatch detection).
	issuerOverride string
	// discoveryStatus, when non-zero, makes the discovery endpoint fail.
	discoveryStatus int
	// tokenFn builds the token-endpoint response. A nil function returns 500.
	tokenFn func(p *fakeProvider, form url.Values) (int, string)
}

func newFakeProvider(t *testing.T, cfg fakeProviderConfig) *fakeProvider {
	t.Helper()

	p := &fakeProvider{
		rsaKey: genRSAKey(t),
		ecKey:  genECKey(t),
		rsaKid: "rsa-key-1",
		ecKid:  "ec-key-1",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		if cfg.discoveryStatus != 0 {
			w.WriteHeader(cfg.discoveryStatus)
			return
		}
		issuer := p.server.URL
		if cfg.issuerOverride != "" {
			issuer = cfg.issuerOverride
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 issuer,
			"authorization_endpoint": p.server.URL + "/authorize",
			"token_endpoint":         p.server.URL + "/token",
			"jwks_uri":               p.server.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(p.jwksJSON(t)))
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		p.lastForm = r.PostForm
		if cfg.tokenFn == nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		status, body := cfg.tokenFn(p, r.PostForm)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})

	p.server = httptest.NewServer(mux)
	t.Cleanup(p.server.Close)
	return p
}

// config returns a Config pointed at this provider.
func (p *fakeProvider) config() Config {
	return Config{
		Issuer:        p.server.URL,
		ClientID:      "client-1",
		ClientSecret:  "shhh",
		RedirectURI:   "https://app.example/callback",
		AllowInsecure: true,
		ClockSkew:     5 * time.Second,
	}
}

// newClient discovers and returns a Client, failing the test on error.
func (p *fakeProvider) newClient(t *testing.T) *Client {
	t.Helper()
	c, err := New(t.Context(), p.config())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func (p *fakeProvider) jwksJSON(t *testing.T) string {
	t.Helper()
	doc := map[string]any{
		"keys": []any{
			rsaJWK(p.rsaKid, &p.rsaKey.PublicKey),
			ecJWK(t, p.ecKid, &p.ecKey.PublicKey),
		},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return string(raw)
}

// --- Key generation and signing ---------------------------------------------

func genRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return key
}

func genECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	return key
}

func b64URL(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }

func rsaJWK(kid string, pub *rsa.PublicKey) map[string]any {
	return map[string]any{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": kid,
		"n":   b64URL(pub.N.Bytes()),
		"e":   b64URL(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func ecJWK(t *testing.T, kid string, pub *ecdsa.PublicKey) map[string]any {
	t.Helper()
	point, err := pub.Bytes()
	if err != nil {
		t.Fatalf("encode EC public key: %v", err)
	}
	return map[string]any{
		"kty": "EC",
		"use": "sig",
		"alg": "ES256",
		"kid": kid,
		"crv": "P-256",
		"x":   b64URL(point[1:33]),
		"y":   b64URL(point[33:65]),
	}
}

func signJWT(t *testing.T, header, claims map[string]any, sign func(string) []byte) string {
	t.Helper()
	hb, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	input := b64URL(hb) + "." + b64URL(cb)
	return input + "." + b64URL(sign(input))
}

func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	return signJWT(t,
		map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid},
		claims,
		func(input string) []byte {
			digest := sha256.Sum256([]byte(input))
			sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
			if err != nil {
				t.Fatalf("sign RS256: %v", err)
			}
			return sig
		})
}

func signES256(t *testing.T, key *ecdsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	return signJWT(t,
		map[string]any{"alg": "ES256", "typ": "JWT", "kid": kid},
		claims,
		func(input string) []byte {
			digest := sha256.Sum256([]byte(input))
			r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
			if err != nil {
				t.Fatalf("sign ES256: %v", err)
			}
			sig := make([]byte, 64)
			r.FillBytes(sig[:32])
			s.FillBytes(sig[32:])
			return sig
		})
}

// baseClaims builds a valid claim set for the given issuer/client.
func baseClaims(issuer, clientID string) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss":   issuer,
		"aud":   clientID,
		"sub":   "user-123",
		"email": "user@example.com",
		"iat":   now.Add(-time.Minute).Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	}
}

func tokenBody(idToken string, expiresIn int64) string {
	raw, _ := json.Marshal(map[string]any{
		"access_token":  "access-token-xyz",
		"token_type":    "Bearer",
		"expires_in":    expiresIn,
		"refresh_token": "refresh-xyz",
		"id_token":      idToken,
	})
	return string(raw)
}

// --- Config / New ------------------------------------------------------------

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.ClockSkew != 30*time.Second {
		t.Errorf("ClockSkew = %v, want 30s", cfg.ClockSkew)
	}
	want := map[string]bool{"openid": true, "profile": true, "email": true}
	if len(cfg.Scopes) != len(want) {
		t.Fatalf("Scopes = %v, want %v", cfg.Scopes, want)
	}
	for _, s := range cfg.Scopes {
		if !want[s] {
			t.Errorf("unexpected scope %q", s)
		}
	}
}

func TestNewInvalidConfig(t *testing.T) {
	tests := map[string]Config{
		"empty":                {},
		"missing client_id":    {Issuer: "https://issuer.example"},
		"missing issuer":       {ClientID: "client-1"},
		"malformed issuer":     {Issuer: "not a url", ClientID: "client-1"},
		"plain http (no flag)": {Issuer: "http://issuer.example", ClientID: "client-1"},
		"issuer without host":  {Issuer: "https://", ClientID: "client-1"},
	}
	for name, cfg := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := New(t.Context(), cfg); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("New error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestNewDiscoveryFailure(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{discoveryStatus: http.StatusNotFound})
	if _, err := New(t.Context(), p.config()); err == nil {
		t.Fatal("New with a 404 discovery endpoint must fail")
	}
}

func TestNewIssuerMismatch(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{issuerOverride: "https://other-issuer.example"})
	_, err := New(t.Context(), p.config())
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("New error = %v, want ErrInvalidConfig for an issuer mismatch", err)
	}
}

func TestNewMissingEndpoints(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"issuer":"` + "http://placeholder" + `","authorization_endpoint":"x"}`))
	}))
	defer srv.Close()

	_, err := New(t.Context(), Config{Issuer: srv.URL, ClientID: "c", AllowInsecure: true})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("New error = %v, want ErrInvalidConfig for missing token_endpoint", err)
	}
}

func TestClientSatisfiesProvider(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{})
	// Compile-time assertion that *Client implements Provider, plus a runtime
	// check that the concrete type survives the interface round-trip (SA4023:
	// a non-nil concrete value in an interface is never == nil).
	var provider Provider = p.newClient(t)
	if _, ok := provider.(*Client); !ok {
		t.Fatalf("newClient returned %T, want *Client", provider)
	}
}

// --- AuthURL -----------------------------------------------------------------

func TestAuthURLIncludesPKCEAndCoreParams(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{})
	c := p.newClient(t)

	raw := c.AuthURL("state-123", "challenge-abc")
	if raw == "" {
		t.Fatal("AuthURL returned empty string")
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("AuthURL is not a URL: %v", err)
	}
	if u.Path != "/authorize" {
		t.Errorf("AuthURL path = %q, want /authorize", u.Path)
	}
	q := u.Query()
	for key, want := range map[string]string{
		"response_type":         "code",
		"client_id":             "client-1",
		"redirect_uri":          "https://app.example/callback",
		"state":                 "state-123",
		"code_challenge":        "challenge-abc",
		"code_challenge_method": "S256",
		"scope":                 "openid profile email",
	} {
		if got := q.Get(key); got != want {
			t.Errorf("AuthURL %s = %q, want %q", key, got, want)
		}
	}
}

func TestAuthURLOmitsPKCEWhenNoChallenge(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{})
	c := p.newClient(t)

	u, err := url.Parse(c.AuthURL("st", ""))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if u.Query().Has("code_challenge") || u.Query().Has("code_challenge_method") {
		t.Error("AuthURL must omit PKCE params when no challenge is supplied")
	}
	if u.Query().Get("state") != "st" {
		t.Errorf("state = %q, want st", u.Query().Get("state"))
	}
}

// --- PKCE --------------------------------------------------------------------

func TestGeneratePKCE(t *testing.T) {
	verifier, challenge, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE: %v", err)
	}
	// 32 bytes -> 43 base64url chars, within RFC 7636's 43..128 range.
	if len(verifier) != 43 {
		t.Errorf("verifier length = %d, want 43", len(verifier))
	}
	for _, c := range verifier {
		if !strings.ContainsRune("-_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", c) {
			t.Fatalf("verifier contains non-unreserved character %q", c)
		}
	}

	digest := sha256.Sum256([]byte(verifier))
	wantChallenge := base64.RawURLEncoding.EncodeToString(digest[:])
	if challenge != wantChallenge {
		t.Errorf("challenge = %q, want S256(verifier) = %q", challenge, wantChallenge)
	}

	// Two generations must not collide.
	otherVerifier, _, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE: %v", err)
	}
	if verifier == otherVerifier {
		t.Error("GeneratePKCE returned the same verifier twice")
	}
}

// --- Exchange: success paths -------------------------------------------------

func TestExchangeRS256Success(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{
		tokenFn: func(p *fakeProvider, form url.Values) (int, string) {
			claims := baseClaims(p.server.URL, "client-1")
			claims["nonce"] = "nonce-123"
			return http.StatusOK, tokenBody(signRS256(t, p.rsaKey, p.rsaKid, claims), 3600)
		},
	})
	c := p.newClient(t)

	tok, err := c.Exchange(t.Context(), "auth-code", "verifier-xyz", "nonce-123")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if tok.Subject != "user-123" {
		t.Errorf("Subject = %q, want user-123", tok.Subject)
	}
	if tok.Email != "user@example.com" {
		t.Errorf("Email = %q, want user@example.com", tok.Email)
	}
	if tok.AccessToken != "access-token-xyz" {
		t.Errorf("AccessToken = %q", tok.AccessToken)
	}
	if tok.RefreshToken != "refresh-xyz" {
		t.Errorf("RefreshToken = %q", tok.RefreshToken)
	}
	if time.Until(tok.ExpiresAt) < 55*time.Minute {
		t.Errorf("ExpiresAt = %v, want ~1h from now", tok.ExpiresAt)
	}

	// The token request must be a well-formed authorization_code + PKCE form.
	form := p.lastForm
	for key, want := range map[string]string{
		"grant_type":    "authorization_code",
		"code":          "auth-code",
		"code_verifier": "verifier-xyz",
		"client_id":     "client-1",
		"client_secret": "shhh",
		"redirect_uri":  "https://app.example/callback",
	} {
		if got := form.Get(key); got != want {
			t.Errorf("token form %s = %q, want %q", key, got, want)
		}
	}
}

func TestExchangeES256Success(t *testing.T) {
	newFakeProviderForEC := func() *fakeProvider {
		p := newFakeProvider(t, fakeProviderConfig{
			tokenFn: func(p *fakeProvider, form url.Values) (int, string) {
				claims := baseClaims(p.server.URL, "client-1")
				return http.StatusOK, tokenBody(signES256(t, p.ecKey, p.ecKid, claims), 600)
			},
		})
		return p
	}
	p := newFakeProviderForEC()
	c := p.newClient(t)

	tok, err := c.Exchange(t.Context(), "code", "", "")
	if err != nil {
		t.Fatalf("Exchange (ES256): %v", err)
	}
	if tok.Subject != "user-123" {
		t.Errorf("Subject = %q, want user-123", tok.Subject)
	}
	if tok.IDToken == "" {
		t.Error("IDToken must be preserved on the Token")
	}
}

// TestExchangeAudienceArray covers the multi-audience claim form.
func TestExchangeAudienceArray(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{
		tokenFn: func(p *fakeProvider, form url.Values) (int, string) {
			claims := baseClaims(p.server.URL, "client-1")
			claims["aud"] = []string{"client-1", "another-client"}
			return http.StatusOK, tokenBody(signRS256(t, p.rsaKey, p.rsaKid, claims), 300)
		},
	})
	c := p.newClient(t)

	if _, err := c.Exchange(t.Context(), "code", "", ""); err != nil {
		t.Fatalf("Exchange with array aud: %v", err)
	}
}

// --- Exchange: failure paths -------------------------------------------------

func TestExchangeNoIDToken(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{
		tokenFn: func(p *fakeProvider, form url.Values) (int, string) {
			return http.StatusOK, `{"access_token":"at","token_type":"Bearer"}`
		},
	})
	c := p.newClient(t)

	_, err := c.Exchange(t.Context(), "code", "", "")
	if !errors.Is(err, ErrNoToken) {
		t.Fatalf("Exchange error = %v, want ErrNoToken", err)
	}
}

func TestExchangeTokenEndpointError(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{
		tokenFn: func(p *fakeProvider, form url.Values) (int, string) {
			return http.StatusInternalServerError, `{"error":"server_error"}`
		},
	})
	c := p.newClient(t)

	if _, err := c.Exchange(t.Context(), "code", "", ""); err == nil {
		t.Fatal("Exchange must fail when the token endpoint errors")
	}
}

// TestExchangeErrorBodyIsRedacted is the CWE-532 fix: a provider that echoes a
// secret in its error body must not leak it through the returned error (which
// callers routinely log). Only the HTTP status and the sanitized OAuth error
// code are surfaced.
func TestExchangeErrorBodyIsRedacted(t *testing.T) {
	const secret = "super-secret-authorization-code-abc123"
	p := newFakeProvider(t, fakeProviderConfig{
		tokenFn: func(p *fakeProvider, form url.Values) (int, string) {
			return http.StatusBadRequest, `{"error":"invalid_grant","error_description":"code ` + secret + ` was rejected"}`
		},
	})
	c := p.newClient(t)

	_, err := c.Exchange(t.Context(), "code", "", "")
	if err == nil {
		t.Fatal("Exchange must fail when the token endpoint errors")
	}
	msg := err.Error()
	if !strings.Contains(msg, "400") || !strings.Contains(msg, "error=invalid_grant") {
		t.Fatalf("error = %q, want the status and the OAuth error code", msg)
	}
	if strings.Contains(msg, secret) || strings.Contains(msg, "error_description") {
		t.Fatalf("error = %q leaked the provider's raw body", msg)
	}
}

// TestTokenEndpointErrorSanitization covers bodies that carry no usable code:
// they must degrade to the status alone, never to raw provider text.
func TestTokenEndpointErrorSanitization(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string // substring that must be absent, if any
	}{
		{"html body", `<html><body>token=abc123</body></html>`, "token=abc123"},
		{"code with punctuation", `{"error":"invalid_grant\nX-Evil: 1"}`, "X-Evil"},
		{"very long code", `{"error":"` + strings.Repeat("a", 65) + `"}`, strings.Repeat("a", 65)},
		{"plain text", "server exploded with stack trace", "stack trace"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tokenEndpointError(http.StatusInternalServerError, []byte(tc.body))
			if strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q leaked %q", err, tc.want)
			}
			if !strings.Contains(err.Error(), "500") {
				t.Fatalf("error = %q, want the status code", err)
			}
		})
	}

	// A well-formed code is preserved so operators can still diagnose the
	// OAuth failure.
	if got := tokenEndpointError(http.StatusBadRequest, []byte(`{"error":"invalid_client"}`)).Error(); !strings.Contains(got, "error=invalid_client") {
		t.Fatalf("error = %q, want the sanitized code", got)
	}
}

func TestExchangeEmptyCode(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{})
	c := p.newClient(t)

	if _, err := c.Exchange(t.Context(), "  ", "", ""); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("Exchange error = %v, want ErrInvalidConfig", err)
	}
}

func TestExchangeExpiredToken(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{
		tokenFn: func(p *fakeProvider, form url.Values) (int, string) {
			claims := baseClaims(p.server.URL, "client-1")
			claims["exp"] = time.Now().Add(-time.Hour).Unix()
			return http.StatusOK, tokenBody(signRS256(t, p.rsaKey, p.rsaKid, claims), 3600)
		},
	})
	c := p.newClient(t)

	if _, err := c.Exchange(t.Context(), "code", "", ""); err == nil {
		t.Fatal("Exchange must reject an expired id_token")
	}
}

// TestExchangeExpiryWithinSkew: an exp just inside ClockSkew is still valid.
func TestExchangeExpiryWithinSkew(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{
		tokenFn: func(p *fakeProvider, form url.Values) (int, string) {
			claims := baseClaims(p.server.URL, "client-1")
			claims["exp"] = time.Now().Add(-2 * time.Second).Unix()
			return http.StatusOK, tokenBody(signRS256(t, p.rsaKey, p.rsaKid, claims), 3600)
		},
	})
	c := p.newClient(t)

	if _, err := c.Exchange(t.Context(), "code", "", ""); err != nil {
		t.Fatalf("Exchange within ClockSkew should succeed: %v", err)
	}
}

func TestExchangeNotYetValid(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{
		tokenFn: func(p *fakeProvider, form url.Values) (int, string) {
			claims := baseClaims(p.server.URL, "client-1")
			claims["nbf"] = time.Now().Add(time.Hour).Unix()
			return http.StatusOK, tokenBody(signRS256(t, p.rsaKey, p.rsaKid, claims), 3600)
		},
	})
	c := p.newClient(t)

	if _, err := c.Exchange(t.Context(), "code", "", ""); err == nil {
		t.Fatal("Exchange must reject a not-yet-valid id_token")
	}
}

func TestExchangeNonceMismatch(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{
		tokenFn: func(p *fakeProvider, form url.Values) (int, string) {
			claims := baseClaims(p.server.URL, "client-1")
			claims["nonce"] = "expected-nonce"
			return http.StatusOK, tokenBody(signRS256(t, p.rsaKey, p.rsaKid, claims), 3600)
		},
	})
	c := p.newClient(t)

	if _, err := c.Exchange(t.Context(), "code", "", "different-nonce"); err == nil {
		t.Fatal("Exchange must reject a nonce mismatch")
	}
}

// TestExchangeNonceMissing: a nonce was requested but the token omits it.
func TestExchangeNonceMissing(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{
		tokenFn: func(p *fakeProvider, form url.Values) (int, string) {
			claims := baseClaims(p.server.URL, "client-1")
			return http.StatusOK, tokenBody(signRS256(t, p.rsaKey, p.rsaKid, claims), 3600)
		},
	})
	c := p.newClient(t)

	if _, err := c.Exchange(t.Context(), "code", "", "expected-nonce"); err == nil {
		t.Fatal("Exchange must reject a token without the requested nonce")
	}
}

func TestExchangeWrongIssuer(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{
		tokenFn: func(p *fakeProvider, form url.Values) (int, string) {
			claims := baseClaims(p.server.URL, "client-1")
			claims["iss"] = "https://attacker.example"
			return http.StatusOK, tokenBody(signRS256(t, p.rsaKey, p.rsaKid, claims), 3600)
		},
	})
	c := p.newClient(t)

	if _, err := c.Exchange(t.Context(), "code", "", ""); err == nil {
		t.Fatal("Exchange must reject an id_token with the wrong issuer")
	}
}

func TestExchangeWrongAudience(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{
		tokenFn: func(p *fakeProvider, form url.Values) (int, string) {
			claims := baseClaims(p.server.URL, "some-other-client")
			return http.StatusOK, tokenBody(signRS256(t, p.rsaKey, p.rsaKid, claims), 3600)
		},
	})
	c := p.newClient(t)

	if _, err := c.Exchange(t.Context(), "code", "", ""); err == nil {
		t.Fatal("Exchange must reject an id_token for another client")
	}
}

func TestExchangeMissingExp(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{
		tokenFn: func(p *fakeProvider, form url.Values) (int, string) {
			claims := baseClaims(p.server.URL, "client-1")
			delete(claims, "exp")
			return http.StatusOK, tokenBody(signRS256(t, p.rsaKey, p.rsaKid, claims), 3600)
		},
	})
	c := p.newClient(t)

	if _, err := c.Exchange(t.Context(), "code", "", ""); err == nil {
		t.Fatal("Exchange must reject an id_token without exp")
	}
}

// TestExchangeBadSignature: the token claims are valid but signed by a key the
// provider does not publish.
func TestExchangeBadSignature(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{
		tokenFn: func(p *fakeProvider, form url.Values) (int, string) {
			attacker := genRSAKey(t)
			claims := baseClaims(p.server.URL, "client-1")
			return http.StatusOK, tokenBody(signRS256(t, attacker, p.rsaKid, claims), 3600)
		},
	})
	c := p.newClient(t)

	if _, err := c.Exchange(t.Context(), "code", "", ""); err == nil {
		t.Fatal("Exchange must reject a token with an invalid signature")
	}
}

func TestExchangeUnsupportedAlg(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{
		tokenFn: func(p *fakeProvider, form url.Values) (int, string) {
			claims := baseClaims(p.server.URL, "client-1")
			// alg=none with an empty signature segment.
			unsigned := signJWT(t, map[string]any{"alg": "none", "typ": "JWT"}, claims, func(string) []byte { return nil })
			return http.StatusOK, tokenBody(unsigned, 3600)
		},
	})
	c := p.newClient(t)

	if _, err := c.Exchange(t.Context(), "code", "", ""); err == nil {
		t.Fatal("Exchange must reject alg=none")
	}
}

// TestExchangeUnknownKid: the id_token's kid is not in the published JWKS.
func TestExchangeUnknownKid(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{
		tokenFn: func(p *fakeProvider, form url.Values) (int, string) {
			claims := baseClaims(p.server.URL, "client-1")
			return http.StatusOK, tokenBody(signRS256(t, p.rsaKey, "ghost-kid", claims), 3600)
		},
	})
	c := p.newClient(t)

	if _, err := c.Exchange(t.Context(), "code", "", ""); err == nil {
		t.Fatal("Exchange must reject a kid that is not published in the JWKS")
	}
}

// TestExchangeMalformedJWT: a non-JWT id_token must be rejected.
func TestExchangeMalformedJWT(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{
		tokenFn: func(p *fakeProvider, form url.Values) (int, string) {
			return http.StatusOK, tokenBody("not-a-jwt", 3600)
		},
	})
	c := p.newClient(t)

	if _, err := c.Exchange(t.Context(), "code", "", ""); err == nil {
		t.Fatal("Exchange must reject a malformed id_token")
	}
}

// --- Helpers ------------------------------------------------------------------

func TestRequireHTTPS(t *testing.T) {
	if err := requireHTTPS("https://issuer.example/token"); err != nil {
		t.Errorf("requireHTTPS(https) = %v, want nil", err)
	}
	for _, raw := range []string{"http://issuer.example/token", "ftp://issuer.example", "::bad::"} {
		if err := requireHTTPS(raw); err == nil {
			t.Errorf("requireHTTPS(%q) = nil, want error", raw)
		}
	}
}

func TestAudienceContains(t *testing.T) {
	if !audienceContains("client-1", "client-1") {
		t.Error("string aud should match")
	}
	if audienceContains("client-2", "client-1") {
		t.Error("string aud mismatch should not match")
	}
	if !audienceContains([]any{"a", "client-1"}, "client-1") {
		t.Error("[]any aud should match")
	}
	if audienceContains([]any{"a", "b"}, "client-1") {
		t.Error("[]any aud mismatch should not match")
	}
	if audienceContains(nil, "client-1") {
		t.Error("nil aud should not match")
	}
}

func TestDecodeBigIntRejectsEmpty(t *testing.T) {
	if _, err := decodeBigInt(""); err == nil {
		t.Error("decodeBigInt(\"\") must fail")
	}
	if _, err := decodeBigInt("!!!not-base64!!!"); err == nil {
		t.Error("decodeBigInt of invalid base64 must fail")
	}
}

func TestContextCancellationOnDiscovery(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := New(ctx, p.config()); err == nil {
		t.Fatal("New must fail when the context is already cancelled")
	}
}

// --- VerifyIDToken: the middleware entry point --------------------------------
//
// Exchange tests above reach verification through the code-flow path. These
// tests call VerifyIDToken (and its nonce-bearing sibling) directly, because
// internal/authz.go uses VerifyIDToken with an empty nonce on every request.
// Every token here is signed by the provider's real key unless the case is
// explicitly about the signature, so a failure isolates the claim at fault.

func TestVerifyIDTokenRS256Success(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{})
	c := p.newClient(t)

	// Arrange: a valid token from the configured issuer for the configured client.
	claims := baseClaims(p.server.URL, "client-1")
	raw := signRS256(t, p.rsaKey, p.rsaKid, claims)

	// Act
	got, err := c.VerifyIDToken(raw)

	// Assert
	if err != nil {
		t.Fatalf("VerifyIDToken(RS256): %v", err)
	}
	if got == nil {
		t.Fatal("VerifyIDToken returned nil claims for a valid token")
	}
	for key, want := range map[string]any{
		"iss": p.server.URL,
		"aud": "client-1",
		"sub": "user-123",
	} {
		if got[key] != want {
			t.Errorf("claim %s = %v, want %v", key, got[key], want)
		}
	}
	if _, ok := got["exp"]; !ok {
		t.Error("exp claim was dropped from the returned claims")
	}
}

func TestVerifyIDTokenES256Success(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{})
	c := p.newClient(t)

	// Arrange
	raw := signES256(t, p.ecKey, p.ecKid, baseClaims(p.server.URL, "client-1"))

	// Act
	got, err := c.VerifyIDToken(raw)

	// Assert
	if err != nil {
		t.Fatalf("VerifyIDToken(ES256): %v", err)
	}
	if got["sub"] != "user-123" {
		t.Errorf("sub = %v, want user-123", got["sub"])
	}
}

func TestVerifyIDTokenRejectsInvalidClaims(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{})
	c := p.newClient(t)

	cases := []struct {
		name    string
		mutate  func(map[string]any)
		wantErr string
	}{
		{
			name:    "expired",
			mutate:  func(cl map[string]any) { cl["exp"] = time.Now().Add(-time.Hour).Unix() },
			wantErr: "expired",
		},
		{
			name:    "missing exp",
			mutate:  func(cl map[string]any) { delete(cl, "exp") },
			wantErr: "missing the exp claim",
		},
		{
			name:    "wrong issuer",
			mutate:  func(cl map[string]any) { cl["iss"] = "https://attacker.example" },
			wantErr: "issuer",
		},
		{
			name:    "missing issuer",
			mutate:  func(cl map[string]any) { delete(cl, "iss") },
			wantErr: "missing the iss claim",
		},
		{
			name:    "wrong audience",
			mutate:  func(cl map[string]any) { cl["aud"] = "another-client" },
			wantErr: "audience",
		},
		{
			name:    "audience array without this client",
			mutate:  func(cl map[string]any) { cl["aud"] = []string{"someone-else"} },
			wantErr: "audience",
		},
		{
			name:    "not yet valid",
			mutate:  func(cl map[string]any) { cl["nbf"] = time.Now().Add(time.Hour).Unix() },
			wantErr: "not yet valid",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange: valid signature, one bad claim.
			claims := baseClaims(p.server.URL, "client-1")
			tc.mutate(claims)
			raw := signRS256(t, p.rsaKey, p.rsaKid, claims)

			// Act
			got, err := c.VerifyIDToken(raw)

			// Assert
			if err == nil {
				t.Fatalf("VerifyIDToken accepted a token with %s: %+v", tc.name, got)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to mention %q", err, tc.wantErr)
			}
			if got != nil {
				t.Errorf("claims = %+v, want nil when verification fails", got)
			}
		})
	}
}

func TestVerifyIDTokenRejectsForgedSignature(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{})
	c := p.newClient(t)

	// Arrange: the claims are perfect, but the signer is not the provider's key.
	attacker := genRSAKey(t)
	raw := signRS256(t, attacker, p.rsaKid, baseClaims(p.server.URL, "client-1"))

	// Act
	got, err := c.VerifyIDToken(raw)

	// Assert
	if err == nil {
		t.Fatalf("VerifyIDToken accepted a forged signature: %+v", got)
	}
	if !strings.Contains(err.Error(), "signature") {
		t.Errorf("error = %q, want a signature failure", err)
	}
	if got != nil {
		t.Errorf("claims = %+v, want nil when the signature fails", got)
	}
}

func TestVerifyIDTokenRejectsTamperedClaims(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{})
	c := p.newClient(t)

	// Arrange: sign a valid token, then edit only the claims segment while
	// keeping the original signature. The digest must no longer match.
	raw := signRS256(t, p.rsaKey, p.rsaKid, baseClaims(p.server.URL, "client-1"))
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("signed token has %d segments, want 3", len(parts))
	}
	tampered := baseClaims(p.server.URL, "client-1")
	tampered["sub"] = "attacker"
	encoded, err := json.Marshal(tampered)
	if err != nil {
		t.Fatalf("marshal tampered claims: %v", err)
	}
	parts[1] = b64URL(encoded)

	// Act
	got, err := c.VerifyIDToken(strings.Join(parts, "."))

	// Assert
	if err == nil {
		t.Fatalf("VerifyIDToken accepted edited claims under the old signature: %+v", got)
	}
	if got != nil {
		t.Errorf("claims = %+v, want nil for a tampered token", got)
	}
}

// TestVerifyIDTokenNonce exercises the nonce branch, which VerifyIDToken itself
// intentionally leaves off (authz.go calls it as a middleware check). The
// code-flow helper verifyIDToken is the entry point that enforces a nonce.
func TestVerifyIDTokenNonce(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{})
	c := p.newClient(t)

	withNonce := baseClaims(p.server.URL, "client-1")
	withNonce["nonce"] = "nonce-123"
	signed := signRS256(t, p.rsaKey, p.rsaKid, withNonce)

	t.Run("matching nonce is accepted", func(t *testing.T) {
		got, err := c.verifyIDToken(t.Context(), signed, "nonce-123")
		if err != nil {
			t.Fatalf("verifyIDToken with matching nonce: %v", err)
		}
		if got["nonce"] != "nonce-123" {
			t.Errorf("nonce = %v, want nonce-123", got["nonce"])
		}
	})

	t.Run("mismatched nonce is rejected", func(t *testing.T) {
		got, err := c.verifyIDToken(t.Context(), signed, "different-nonce")
		if err == nil {
			t.Fatalf("verifyIDToken accepted a nonce mismatch: %+v", got)
		}
		if !strings.Contains(err.Error(), "nonce mismatch") {
			t.Errorf("error = %q, want a nonce mismatch", err)
		}
	})

	t.Run("missing nonce is rejected when one is required", func(t *testing.T) {
		noNonce := signRS256(t, p.rsaKey, p.rsaKid, baseClaims(p.server.URL, "client-1"))
		got, err := c.verifyIDToken(t.Context(), noNonce, "nonce-123")
		if err == nil {
			t.Fatalf("verifyIDToken accepted a token without the requested nonce: %+v", got)
		}
		if !strings.Contains(err.Error(), "nonce mismatch") {
			t.Errorf("error = %q, want a nonce mismatch", err)
		}
	})

	t.Run("VerifyIDToken skips the nonce check", func(t *testing.T) {
		// Contract for the authz middleware: no authorization-code flow, so a
		// token carrying a nonce must still verify when no nonce is requested.
		got, err := c.VerifyIDToken(signed)
		if err != nil {
			t.Fatalf("VerifyIDToken with an empty nonce: %v", err)
		}
		if got["sub"] != "user-123" {
			t.Errorf("sub = %v, want user-123", got["sub"])
		}
	})
}

func TestVerifyIDTokenRejectsInvalidJWT(t *testing.T) {
	p := newFakeProvider(t, fakeProviderConfig{})
	c := p.newClient(t)
	claims := baseClaims(p.server.URL, "client-1")

	cases := []struct {
		name    string
		raw     string
		wantErr string
	}{
		{
			name:    "not a JWT",
			raw:     "not-a-jwt",
			wantErr: "not a well-formed JWT",
		},
		{
			name:    "alg none",
			raw:     signJWT(t, map[string]any{"alg": "none", "typ": "JWT"}, claims, func(string) []byte { return nil }),
			wantErr: "unsupported",
		},
		{
			name:    "unknown kid",
			raw:     signRS256(t, p.rsaKey, "ghost-kid", claims),
			wantErr: "no verification key",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := c.VerifyIDToken(tc.raw)
			if err == nil {
				t.Fatalf("VerifyIDToken accepted %s: %+v", tc.name, got)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

// --- JWKS metadata filter (audit §5.3) ---------------------------------------

// TestJWKUsableForSigning covers the metadata filter that keeps ill-declared
// keys out of the verification cache. It is defense in depth on top of the
// algorithm pinning in verifyIDToken, which remains the primary control.
func TestJWKUsableForSigning(t *testing.T) {
	cases := []struct {
		name string
		key  jwkKey
		want bool
	}{
		{"empty use accepted", jwkKey{Kty: "RSA", Use: "", Alg: "RS256"}, true},
		{"sig use accepted", jwkKey{Kty: "EC", Use: "sig", Alg: "ES256", Crv: "P-256"}, true},
		{"enc use rejected", jwkKey{Kty: "RSA", Use: "enc", Alg: "RS256"}, false},
		{"unknown use rejected", jwkKey{Kty: "RSA", Use: "other"}, false},
		{"RS256 with RSA accepted", jwkKey{Kty: "RSA", Alg: "RS256"}, true},
		{"RS256 with EC rejected", jwkKey{Kty: "EC", Alg: "RS256", Crv: "P-256"}, false},
		{"ES256 with EC P-256 accepted", jwkKey{Kty: "EC", Alg: "ES256", Crv: "P-256"}, true},
		{"ES256 with EC P-384 rejected", jwkKey{Kty: "EC", Alg: "ES256", Crv: "P-384"}, false},
		{"ES256 with RSA rejected", jwkKey{Kty: "RSA", Alg: "ES256"}, false},
		{"unknown alg rejected", jwkKey{Kty: "RSA", Alg: "RS512"}, false},
		{"empty alg with RSA accepted", jwkKey{Kty: "RSA", Alg: ""}, true},
		{"empty alg with EC accepted", jwkKey{Kty: "EC", Alg: "", Crv: "P-256"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.key.usableForSigning(); got != tc.want {
				t.Fatalf("usableForSigning() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestLoadKeysFiltersJWKSMetadata exercises the filter through loadKeys with a
// real JWKS response, including the all-rejected error path.
func TestLoadKeysFiltersJWKSMetadata(t *testing.T) {
	rsaPub := &genRSAKey(t).PublicKey
	ecPub := &genECKey(t).PublicKey

	with := func(src map[string]any, field, value string) map[string]any {
		out := make(map[string]any, len(src)+1)
		for k, v := range src {
			out[k] = v
		}
		out[field] = value
		return out
	}
	without := func(src map[string]any, field string) map[string]any {
		out := make(map[string]any, len(src))
		for k, v := range src {
			if k != field {
				out[k] = v
			}
		}
		return out
	}

	goodRSA := rsaJWK("rsa-good", rsaPub)                              // use=sig, alg=RS256
	goodECNoUse := without(ecJWK(t, "ec-good", ecPub), "use")          // use absent, alg=ES256
	goodRSANoAlg := without(rsaJWK("rsa-noalg", rsaPub), "alg")        // use=sig, alg absent
	encRSA := with(rsaJWK("rsa-enc", rsaPub), "use", "enc")            // encryption-only
	mismatchEC := with(ecJWK(t, "ec-mismatch", ecPub), "alg", "RS256") // alg contradicts kty
	unknownAlg := with(rsaJWK("rsa-unknown", rsaPub), "alg", "RS512")

	serve := func(t *testing.T, docs ...map[string]any) *Client {
		t.Helper()
		raw, err := json.Marshal(map[string]any{"keys": docs})
		if err != nil {
			t.Fatalf("marshal jwks: %v", err)
		}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(raw)
		}))
		t.Cleanup(srv.Close)
		return &Client{jwksURI: srv.URL, http: srv.Client()}
	}

	t.Run("all keys rejected by metadata keep the original error", func(t *testing.T) {
		c := serve(t, encRSA, mismatchEC, unknownAlg)
		_, err := c.loadKeys(t.Context())
		if err == nil || !strings.Contains(err.Error(), "jwks contained no usable keys") {
			t.Fatalf("loadKeys error = %v, want jwks contained no usable keys", err)
		}
	})

	t.Run("usable keys are kept and unusable keys are skipped", func(t *testing.T) {
		c := serve(t, encRSA, mismatchEC, unknownAlg, goodRSA, goodECNoUse, goodRSANoAlg)
		keys, err := c.loadKeys(t.Context())
		if err != nil {
			t.Fatalf("loadKeys: %v", err)
		}
		for _, kid := range []string{"rsa-good", "ec-good", "rsa-noalg"} {
			if _, ok := keys[kid]; !ok {
				t.Errorf("usable key %q was dropped", kid)
			}
		}
		for _, kid := range []string{"rsa-enc", "ec-mismatch", "rsa-unknown"} {
			if _, ok := keys[kid]; ok {
				t.Errorf("unusable key %q was loaded", kid)
			}
		}
		if len(keys) != 3 {
			t.Errorf("len(keys) = %d, want 3", len(keys))
		}
	})
}
