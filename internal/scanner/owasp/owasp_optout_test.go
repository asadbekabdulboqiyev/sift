package owasp

// Regression coverage for result-bound OWASP lab warnings. The warning must
// come from the checker/report that actually opted out, not from a global flag.

import (
	"strings"
	"testing"
)

func TestRenderWarnsOnlyForTheOptedOutChecker(t *testing.T) {
	if !TLSVerifyEnabled() {
		t.Fatal("TLSVerifyEnabled() = false at start, want the secure default true")
	}

	newReport := func(insecure bool) *OWASPReport {
		return &OWASPReport{
			Categories: map[string]*OWASPCategory{
				"A01": {Name: "Broken Access Control", Status: "NOT TESTED"},
			},
			InsecureTLS: insecure,
		}
	}

	lab := NewOWASPCheckerWithOptions("https://example.invalid", Options{TLSVerify: false})
	lab.Results = newReport(lab.InsecureTLS)
	if !strings.Contains(lab.Render(), TLSVerifyWarning) {
		t.Fatal("opted-out checker Render() is missing the lab-mode warning")
	}

	safe := NewOWASPChecker("https://example.invalid")
	safe.Results = newReport(safe.InsecureTLS)
	if strings.Contains(safe.Render(), TLSVerifyWarning) {
		t.Fatal("default checker Render() shows the lab-mode warning")
	}

	// Creating an opted-out checker must not change the package default, so a
	// later report built from the default stays clean.
	if !TLSVerifyEnabled() {
		t.Fatal("per-checker opt-out leaked into the package default")
	}
}
