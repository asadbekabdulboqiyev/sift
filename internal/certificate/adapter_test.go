package certificate

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/asadbekabdulboqiyev/sift/internal/finding"
)

func TestCertificateFindingCanonicalCarriesLegacyFields(t *testing.T) {
	legacy := Finding{ID: "CERT-1", Severity: "high", Title: "Missing HSTS", Evidence: "no HSTS header"}
	want := finding.Finding{ID: "CERT-1", Severity: "high", Title: "Missing HSTS", Evidence: "no HSTS header"}
	if got := legacy.Canonical(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Canonical() = %+v, want %+v", got, want)
	}
	if got := ToCanonical(legacy); !reflect.DeepEqual(got, want) {
		t.Fatalf("ToCanonical() = %+v, want %+v", got, want)
	}
}

func TestCertificateFindingCanonicalRoundTrip(t *testing.T) {
	legacy := Finding{ID: "F-2", Severity: "low", Title: "Verbose banner", Evidence: "version disclosed"}
	if got := FromCanonical(legacy.Canonical()); got != legacy {
		t.Fatalf("round trip = %+v, want %+v", got, legacy)
	}
}

func TestCertificateFindingFromCanonicalDropsNonCertificateFields(t *testing.T) {
	canonical := finding.Finding{
		ID:          "F-3",
		Severity:    "medium",
		Title:       "Missing CSP",
		Description: "No content security policy",
		Impact:      "XSS is easier to exploit",
		Source:      "security_scan",
		Location:    "https://example.test/",
		Remediation: "Add a policy",
		Evidence:    "no CSP header",
		Confidence:  finding.ConfidenceVerified,
		CWE:         "CWE-79",
		Digests:     []string{"abcdef"},
	}
	want := Finding{ID: "F-3", Severity: "medium", Title: "Missing CSP", Evidence: "no CSP header"}
	if got := FromCanonical(canonical); got != want {
		t.Fatalf("FromCanonical() = %+v, want %+v", got, want)
	}
}

func TestCertificateFindingJSONShapeUnchanged(t *testing.T) {
	raw, err := json.Marshal(Finding{ID: "F-1", Severity: "medium", Title: "Missing CSP", Evidence: "no CSP"})
	if err != nil {
		t.Fatalf("marshal finding: %v", err)
	}
	want := `{"id":"F-1","severity":"medium","title":"Missing CSP","evidence":"no CSP"}`
	if string(raw) != want {
		t.Fatalf("finding JSON = %s, want %s", raw, want)
	}

	raw, err = json.Marshal(Finding{ID: "F-2", Severity: "low", Title: "No evidence"})
	if err != nil {
		t.Fatalf("marshal finding without evidence: %v", err)
	}
	want = `{"id":"F-2","severity":"low","title":"No evidence"}`
	if string(raw) != want {
		t.Fatalf("finding JSON without evidence = %s, want %s", raw, want)
	}
}

func TestCanonicalAssessmentJSONHasNoNewFindingKeys(t *testing.T) {
	a := Assessment{Findings: []Finding{{ID: "F-1", Severity: "low", Title: "t", Evidence: "e"}}}
	raw, err := canonical(a)
	if err != nil {
		t.Fatalf("canonical assessment: %v", err)
	}
	for _, key := range []string{
		`"confidence"`, `"description"`, `"impact"`, `"source"`,
		`"location"`, `"remediation"`, `"cwe"`, `"digests"`,
	} {
		if bytes.Contains(raw, []byte(key)) {
			t.Errorf("signed canonical JSON gained key %s: %s", key, raw)
		}
	}
}
