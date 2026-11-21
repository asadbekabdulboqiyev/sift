package audit360

import (
	"strings"
	"testing"
)

func TestRecommendedActionNotesPrioritized(t *testing.T) {
	r := &Audit360Report{
		Findings: []Finding{
			{Title: "Low issue", Severity: "low", Remediation: "low fix"},
			{Title: "Critical issue", Severity: "critical", Remediation: "critical fix"},
			{Title: "High issue", Severity: "high", Remediation: "high fix"},
		},
	}
	notes := RecommendedActionNotes(r)
	if len(notes) == 0 {
		t.Fatal("expected recommendation notes")
	}
	joined := strings.Join(notes, "\n")
	if !strings.Contains(joined, "1 critical, 1 high") {
		t.Fatalf("missing severity summary: %q", joined)
	}
	if !strings.Contains(joined, "Immediate action 1 [critical]: Critical issue — critical fix") {
		t.Fatalf("missing prioritized critical action: %q", joined)
	}
	if !strings.Contains(joined, "Immediate action 2 [high]: High issue — high fix") {
		t.Fatalf("missing prioritized high action: %q", joined)
	}
}

func TestRecommendedActionNotesCapacityAndCoverage(t *testing.T) {
	r := &Audit360Report{
		LoadTestSkipped:     true,
		LoadTestAvailable:   false,
		SecurityScanPartial: true,
	}
	joined := strings.Join(RecommendedActionNotes(r), "\n")
	if !strings.Contains(joined, "no issues were reported") {
		t.Fatalf("expected clean-scan plan note: %q", joined)
	}
	if !strings.Contains(joined, "not measured in this run") {
		t.Fatalf("expected capacity-evidence note: %q", joined)
	}
	if !strings.Contains(joined, "coverage was partial") {
		t.Fatalf("expected coverage note: %q", joined)
	}

	r2 := &Audit360Report{CapacityBlocked: true}
	if !strings.Contains(strings.Join(RecommendedActionNotes(r2), "\n"), "target refused load") {
		t.Fatal("expected blocked-capacity note")
	}
}
