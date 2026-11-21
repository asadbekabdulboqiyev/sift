package verigate

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func secureFlag(v bool) *bool { return &v }

// solveForCookie drives a real solve through handleSolve so the Set-Cookie
// header reflects the production path. tlsState simulates either a direct TLS
// connection or a plain-HTTP connection behind a TLS-terminating proxy.
func solveForCookie(t *testing.T, g *VeriGate, tlsState *tls.ConnectionState) *http.Cookie {
	t.Helper()
	const ip = "192.0.2.10"
	prefix, difficulty, err := g.makeChallenge(ip)
	if err != nil {
		t.Fatalf("makeChallenge: %v", err)
	}
	nonce := solveProof(prefix, difficulty)
	if nonce == "" {
		t.Fatal("could not solve proof of work")
	}
	body, err := json.Marshal(solveRequest{Prefix: prefix, Nonce: nonce})
	if err != nil {
		t.Fatalf("marshal solve request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, solvePath, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = ip + ":1234"
	req.TLS = tlsState
	rec := httptest.NewRecorder()
	g.handleSolve(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("solve status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies, want 1", len(cookies))
	}
	return cookies[0]
}

// TestPassCookieSecureOption verifies that the Secure attribute comes only
// from the operator setting and that the default is secure.
func TestPassCookieSecureOption(t *testing.T) {
	cases := []struct {
		name   string
		val    *bool
		tls    bool
		secure bool
	}{
		{"default is secure on plain HTTP", nil, false, true},
		{"explicit true", secureFlag(true), false, true},
		{"explicit false for local HTTP", secureFlag(false), false, false},
		{"request TLS state is ignored", secureFlag(false), true, false},
		{"default is secure even with request TLS state", nil, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g, err := New(Options{SecureCookies: tc.val})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			var tlsState *tls.ConnectionState
			if tc.tls {
				tlsState = &tls.ConnectionState{}
			}
			cookie := solveForCookie(t, g, tlsState)
			if cookie.Secure != tc.secure {
				t.Fatalf("cookie Secure = %v, want %v", cookie.Secure, tc.secure)
			}
			if !cookie.HttpOnly {
				t.Fatal("pass cookie lost HttpOnly")
			}
			if cookie.SameSite != http.SameSiteLaxMode {
				t.Fatalf("pass cookie SameSite = %v, want Lax", cookie.SameSite)
			}
		})
	}
}

// TestMakePassCookieNilOptionFailsSecure covers the defensive default in the
// cookie builder itself, in case a VeriGate is constructed without New.
func TestMakePassCookieNilOptionFailsSecure(t *testing.T) {
	g := &VeriGate{opts: Options{ChallengeTTL: time.Minute}}
	if cookie := g.makePassCookie("192.0.2.10"); !cookie.Secure {
		t.Fatal("nil SecureCookies must produce a Secure cookie")
	}
}
