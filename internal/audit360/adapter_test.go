package audit360

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/asadbekabdulboqiyev/sift/internal/finding"
)

func TestAudit360FindingCanonicalCarriesLegacyFields(t *testing.T) {
	legacy := Finding{
		Title:         "Missing header",
		Severity:      "medium",
		ImpactSummary: "users are exposed",
		Remediation:   "add the header",
		Evidence:      "X-Test missing in response",
		Source:        "security_scan",
	}
	want := finding.Finding{
		Title:       "Missing header",
		Severity:    "medium",
		Impact:      "users are exposed",
		Remediation: "add the header",
		Evidence:    "X-Test missing in response",
		Source:      "security_scan",
	}
	if got := legacy.Canonical(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Canonical() = %+v, want %+v", got, want)
	}
	if got := ToCanonical(legacy); !reflect.DeepEqual(got, want) {
		t.Fatalf("ToCanonical() = %+v, want %+v", got, want)
	}
}

func TestAudit360FindingCanonicalRoundTrip(t *testing.T) {
	legacy := Finding{
		Title:         "Slow endpoint",
		Severity:      "high",
		ImpactSummary: "timeouts under load",
		Remediation:   "add caching",
		Evidence:      "p95 above 2s",
		Source:        "load_test",
	}
	if got := FromCanonical(legacy.Canonical()); !reflect.DeepEqual(got, legacy) {
		t.Fatalf("round trip = %+v, want %+v", got, legacy)
	}
}

func TestAudit360FindingFromCanonicalDropsNonAuditFields(t *testing.T) {
	canonical := finding.Finding{
		ID:          "A-1",
		Severity:    "low",
		Title:       "Banner disclosure",
		Description: "Version is visible",
		Impact:      "fingerprinting",
		Source:      "security_scan",
		Location:    "https://example.test/",
		Remediation: "remove banner",
		Evidence:    "Server: nginx/1.0",
		Confidence:  finding.ConfidenceHeuristic,
		CWE:         "CWE-200",
		Digests:     []string{"abcdef"},
	}
	want := Finding{
		Title:         "Banner disclosure",
		Severity:      "low",
		ImpactSummary: "fingerprinting",
		Remediation:   "remove banner",
		Evidence:      "Server: nginx/1.0",
		Source:        "security_scan",
	}
	if got := FromCanonical(canonical); !reflect.DeepEqual(got, want) {
		t.Fatalf("FromCanonical() = %+v, want %+v", got, want)
	}
}

func TestAudit360FindingJSONShapeUnchanged(t *testing.T) {
	raw, err := json.Marshal(Finding{
		Title:         "t",
		Severity:      "medium",
		ImpactSummary: "i",
		Remediation:   "r",
		Evidence:      "e",
		Source:        "security_scan",
	})
	if err != nil {
		t.Fatalf("marshal finding: %v", err)
	}
	want := `{"title":"t","severity":"medium","impact_summary":"i","remediation":"r","evidence":"e","source":"security_scan"}`
	if string(raw) != want {
		t.Fatalf("finding JSON = %s, want %s", raw, want)
	}

	raw, err = json.Marshal(Finding{Title: "t", Severity: "low"})
	if err != nil {
		t.Fatalf("marshal minimal finding: %v", err)
	}
	want = `{"title":"t","severity":"low","impact_summary":"","remediation":""}`
	if string(raw) != want {
		t.Fatalf("minimal finding JSON = %s, want %s", raw, want)
	}
}
