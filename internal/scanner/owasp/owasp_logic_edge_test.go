package owasp

import (
	"context"
	"net/http"
	"net/http/httptest"
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

// A scan whose every probe is refused (gate denial, dry run, or scope miss)
// produces no evidence. The report must say so honestly: NOT TESTED, never a
// manufactured PASS, with no score/grade claimed and no findings invented.
func TestCheckAllMarksUntestedWhenGateRefusesEverything(t *testing.T) {
	checker := NewOWASPChecker("https://example.com")
	checker.Requester = denyAllRequester{}

	report := checker.CheckAll()
	if report == nil {
		t.Fatal("report is nil")
	}
	if report.Score != 0 {
		t.Fatalf("score = %d, want 0 when nothing was tested", report.Score)
	}
	if report.Grade != "" {
		t.Fatalf("grade = %q, want empty when nothing was tested", report.Grade)
	}
	for id, cat := range report.Categories {
		if cat.Status != "NOT TESTED" {
			t.Errorf("category %s status = %q, want NOT TESTED", id, cat.Status)
		}
		if len(cat.Findings) != 0 {
			t.Errorf("category %s has findings without evidence: %v", id, cat.Findings)
		}
	}
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
