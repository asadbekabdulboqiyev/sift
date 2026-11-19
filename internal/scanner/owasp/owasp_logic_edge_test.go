package owasp

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/asadbekabdulboqiyev/sift/internal/scanner/core"
)

type denyAllRequester struct{}

func (denyAllRequester) Check(_ context.Context, _ string, _ string, _ bool) error {
	return core.ErrOutOfScope
}

func (denyAllRequester) Do(_ *http.Request) (*http.Response, error) {
	return nil, core.ErrOutOfScope
}

// A target that never answers (immediate connection failure / timeout path:
// every probe returns no response) must not be reported as protected or
// vulnerable. Zero responses means zero evidence.
func TestCheckAllNoResponseProducesNoFalseFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	target := srv.URL
	srv.Close() // force immediate connection failures

	checker := NewOWASPChecker(target)
	// Keep dial/probe failures fast in case a check bypasses the HTTP client.
	checker.Client.Timeout = 50 * 1e6 // 50ms

	report := checker.CheckAll()
	for id, cat := range report.Categories {
		if cat.Status != "NOT TESTED" {
			t.Errorf("category %s status = %q, want NOT TESTED when no probe reached the server", id, cat.Status)
		}
		if len(cat.Findings) != 0 {
			t.Errorf("category %s reported findings with no reachable evidence: %v", id, cat.Findings)
		}
	}
	if report.Score != 0 || report.Grade != "" {
		t.Errorf("score/grade = %d/%q, want 0/empty when nothing was tested", report.Score, report.Grade)
	}
}

// WAF/rate-limit responses (403/429) on rapid requests are not evidence that
// rate limiting is absent; the check must only claim "no rate limiting" when
// every probe actually reached the application and succeeded.
func TestA04DoesNotClaimNoRateLimitWhenBlocked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	checker := NewOWASPChecker(srv.URL)
	cat := checker.checkA04()
	for _, f := range cat.Findings {
		if f == "No rate limiting detected: 50/50 rapid requests succeeded" {
			t.Fatal("reported missing rate limiting despite 429 responses")
		}
		if f == "[MEDIUM] No rate limiting detected: 50/50 rapid requests succeeded" {
			t.Fatal("reported missing rate limiting despite 429 responses")
		}
	}
}

// Brute-force protection is not "missing" when the login endpoint never
// produced a response (connection failure / gate refusal / timeout). Absence
// of evidence is not evidence of absence.
func TestA07NoBruteForceFindingWithoutResponses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	target := srv.URL
	srv.Close()

	checker := NewOWASPChecker(target)
	checker.Client.Timeout = 50 * 1e6 // 50ms
	cat := checker.checkA07()
	for _, f := range cat.Findings {
		if f == "[HIGH] No brute force protection: 20 failed login attempts with no lockout/rate limit" {
			t.Fatal("reported missing brute-force protection with no login responses")
		}
	}
}

// Loopback classification decides whether the "open service port" probe runs at
// all: on a loopback target a local MySQL/Redis/Mongo listener is the host's
// business, not the target application's exposure.
func TestIsLoopbackHost(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"127.0.0.1", true},
		{"127.0.0.2", true},
		{"::1", true},
		{"localhost", true},
		{"LOCALHOST", true},
		{"app.localhost", true},
		{" 127.0.0.1 ", true},
		{"", false},
		{"example.com", false},
		{"10.0.0.5", false},
		{"192.168.1.10", false},
		{"localhost.example.com", false},
	}
	for _, tc := range cases {
		if got := isLoopbackHost(tc.host); got != tc.want {
			t.Errorf("isLoopbackHost(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

// A loopback target must not be charged with an exposed database port: the
// listener below belongs to the test host, and the report would otherwise
// misattribute it to the scanned application.
func TestA05SkipsServicePortProbeOnLoopbackTarget(t *testing.T) {
	// The probe dials fixed ports, so the listener has to sit on one of them.
	// MongoDB is the least likely to be running on a developer machine; when it
	// is, the assertion would test the host rather than the code.
	ln, err := net.Listen("tcp", "127.0.0.1:27017")
	if err != nil {
		t.Skipf("port 27017 unavailable on this host: %v", err)
	}
	defer ln.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><body>hello</body></html>"))
	}))
	defer srv.Close()

	checker := NewOWASPChecker(srv.URL)
	cat := checker.checkA05()
	for _, f := range cat.Findings {
		if strings.Contains(f, "Database/service port reachable") {
			t.Fatalf("loopback target charged with an exposed service port: %s", f)
		}
	}
}

// 404/405 on /api/login means the endpoint is not there, which is not evidence
// about brute-force protection; a real endpoint (401 here) must still be judged.
func TestA07BruteForceOnlyJudgedWhenEndpointExists(t *testing.T) {
	missing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer missing.Close()
	for _, f := range NewOWASPChecker(missing.URL).checkA07().Findings {
		if strings.Contains(f, "brute force protection") {
			t.Fatalf("claimed missing brute-force protection for a 404 login endpoint: %s", f)
		}
	}

	// Positive control: reached endpoint, no lockout, so the finding must fire.
	present := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/login" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("<html><body>hello</body></html>"))
	}))
	defer present.Close()
	found := false
	for _, f := range NewOWASPChecker(present.URL).checkA07().Findings {
		if strings.Contains(f, "No brute force protection signal observed") {
			found = true
		}
	}
	if !found {
		t.Fatal("missing brute-force finding for a live login endpoint with no lockout")
	}
}
