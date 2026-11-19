//go:build integration

package owasp

import (
	"testing"
)

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
