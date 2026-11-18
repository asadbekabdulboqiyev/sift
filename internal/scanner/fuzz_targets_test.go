package scanner

// fuzz_targets_test.go — coverage-guided fuzzing for the parsers that read
// attacker-controlled bytes.
//
// A security scanner's whole input is hostile by construction. These three
// parsers handle the most attacker-shaped input the passive scanner sees: a
// bearer token handed to us, a Set-Cookie header, and a Content-Security-Policy
// header. Each is a hand-written parser, so each is where a panic would come
// from — and a panic in a scanner is a denial of service against the operator,
// delivered by the target.

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// FuzzAnalyzeJWT feeds arbitrary tokens to the JWT analyser.
func FuzzAnalyzeJWT(f *testing.F) {
	seeds := []string{
		"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIn0.",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln",
		"a.b.c",
		"..",
		"",
		"header.payload",
		"!!!.???.###",
		"eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjF9.c2ln",
		".eyJzdWIiOiIxIn0.",
		"eyJhbGciOiJIUzI1NiJ9..c2ln",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, token string) {
		if len(token) > 1<<16 {
			t.Skip()
		}
		res := AnalyzeJWT(token)
		if res == nil {
			t.Fatalf("AnalyzeJWT returned nil for %q", token)
		}
		if res.Token != token {
			t.Fatalf("result carries a different token than the one analysed")
		}

		// An earlier version of this target required every decoded header key to
		// be non-empty. That is not an invariant: a JWT header is a JSON object
		// handed to us by whoever minted the token, and {"":""} is a legal one.
		// The corpus found exactly that ("eyJ0000iOiJ00000IiwiIjoiIn0..", whose
		// header decodes to {"t\xd3M":"t\xd3M4","":""}), so the job went red on
		// input the analyser handles correctly. The rule that does matter is
		// that the analyser reports the header it was given: no key invented,
		// none dropped, and a header that did not decode leaves Valid false.
		want, decoded := decodeFuzzJWTHeader(token)
		if !decoded {
			if res.Header != nil {
				t.Fatalf("header did not decode but result carries %v", res.Header)
			}
			if res.Valid {
				t.Fatalf("header did not decode but result claims Valid")
			}
			return
		}
		if want == nil { // the segment is the JSON literal "null"
			if res.Header != nil {
				t.Fatalf("header is JSON null but result carries %v", res.Header)
			}
			return
		}
		if res.Header == nil {
			t.Fatalf("header decoded to %v but result carries none", want)
		}
		if !res.Valid {
			t.Fatalf("header decoded but result claims Valid is false")
		}
		for k := range res.Header {
			if _, ok := want[k]; !ok {
				t.Fatalf("analyser invented header key %q", k)
			}
		}
		for k := range want {
			if _, ok := res.Header[k]; !ok {
				t.Fatalf("analyser dropped header key %q", k)
			}
		}
	})
}

// FuzzPassiveParseSetCookie feeds arbitrary Set-Cookie values to the parser.
func FuzzPassiveParseSetCookie(f *testing.F) {
	seeds := []string{
		"session=abc; Path=/; HttpOnly; Secure; SameSite=Lax",
		"a=b",
		"",
		";",
		"=;",
		"a=b; Domain=; Path=; Max-Age=notanumber",
		"__Host-x=y; Secure; Path=/",
		"k=v; Expires=Wed, 21 Oct 2015 07:28:00 GMT",
		"token=averylongvalue" + strings.Repeat("A", 4096) + "; Secure",
		"a=b; a=c; a=d",
		"\x00=\x01; Path=\x02",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 1<<16 {
			t.Skip()
		}
		c := passiveParseSetCookie(raw)
		if c.attrs == nil {
			t.Fatalf("attrs map is nil")
		}
		// A name must never keep the raw separator: a parsed cookie whose
		// name still contains ';' or '=' would be string-spliced downstream.
		if strings.ContainsAny(c.name, ";=") {
			t.Fatalf("parsed name %q still contains a separator", c.name)
		}
	})
}

// FuzzPassiveParseCSP feeds arbitrary policy headers to the parser.
func FuzzPassiveParseCSP(f *testing.F) {
	seeds := []string{
		"default-src 'self'; script-src 'self' 'unsafe-inline'",
		"",
		";;;;;",
		"default-src",
		"script-src *",
		"script-src 'nonce-abc123'",
		"default-src 'self'",
		"connect-src 'self' ws://x",
		"script-src 'sha256-" + strings.Repeat("A", 44) + "'",
		"script-src 'unsafe-eval' 'unsafe-inline' *",
		strings.Repeat("a;", 2000),
		"default-src \x00\x01\x02",
	}
	for _, s := range seeds {
		f.Add(s, "https://example.com/")
	}

	f.Fuzz(func(t *testing.T, raw, source string) {
		if len(raw) > 1<<16 || len(source) > 1<<12 {
			t.Skip()
		}
		pol := passiveParseCSP(raw, source)
		if pol.directives == nil {
			t.Fatalf("directives map is nil")
		}
		for name, vals := range pol.directives {
			if name == "" {
				t.Fatalf("empty directive name in %q", raw)
			}
			if strings.ContainsAny(name, " \t;") {
				t.Fatalf("directive name %q contains a separator", name)
			}
			for _, v := range vals {
				if v == "" {
					t.Fatalf("directive %q has an empty source", name)
				}
			}
		}
	})
}

// decodeFuzzJWTHeader is the reference decoder the target compares against: the
// header segment, base64url without padding, parsed as a JSON object. It reports
// decoded=false when either step fails, which is when AnalyzeJWT must not claim
// it has a header.
func decodeFuzzJWTHeader(token string) (map[string]any, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, false
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, false
	}
	return m, true
}
