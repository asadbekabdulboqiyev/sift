package finding

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func TestParseConfidenceNormalizesEnumAndLegacyText(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want Confidence
	}{
		{"canonical verified", "verified", ConfidenceVerified},
		{"canonical verified trimmed", " VERIFIED ", ConfidenceVerified},
		{"legacy confirmed", "confirmed", ConfidenceVerified},
		{"legacy high", "high", ConfidenceVerified},
		{"canonical heuristic", "heuristic", ConfidenceHeuristic},
		{"legacy heuristic trimmed", " Heuristic ", ConfidenceHeuristic},
		{"canonical unchecked", "unchecked", ConfidenceUnchecked},
		{"legacy informational", "informational", ConfidenceUnchecked},
		{"legacy unknown", "unknown", ConfidenceUnchecked},
		{"empty", "", ConfidenceUnchecked},
		{"unrecognized value", "guess", ConfidenceUnchecked},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ParseConfidence(tc.in); got != tc.want {
				t.Fatalf("ParseConfidence(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestConfidenceStringReturnsCanonicalValue(t *testing.T) {
	cases := map[Confidence]string{
		ConfidenceVerified:  "verified",
		ConfidenceHeuristic: "heuristic",
		ConfidenceUnchecked: "unchecked",
	}
	for c, want := range cases {
		if got := c.String(); got != want {
			t.Errorf("Confidence(%q).String() = %q, want %q", c, got, want)
		}
	}
}

func TestConfidenceJSONNormalizesLegacyText(t *testing.T) {
	var decoded Finding
	if err := json.Unmarshal([]byte(`{"title":"t","confidence":"confirmed"}`), &decoded); err != nil {
		t.Fatalf("unmarshal legacy confidence: %v", err)
	}
	if decoded.Confidence != ConfidenceVerified {
		t.Fatalf("decoded confidence = %q, want %q", decoded.Confidence, ConfidenceVerified)
	}

	encoded, err := json.Marshal(Finding{Title: "t", Confidence: Confidence("high")})
	if err != nil {
		t.Fatalf("marshal legacy confidence: %v", err)
	}
	if want := `{"title":"t","confidence":"verified"}`; string(encoded) != want {
		t.Fatalf("marshaled JSON = %s, want %s", encoded, want)
	}

	empty, err := json.Marshal(Finding{})
	if err != nil {
		t.Fatalf("marshal empty finding: %v", err)
	}
	if string(empty) != `{}` {
		t.Fatalf("empty finding JSON = %s, want {}", empty)
	}
}

func TestFindingJSONRoundTripKeepsAllCanonicalFields(t *testing.T) {
	original := Finding{
		ID:          "F-1",
		Severity:    "high",
		Title:       "Missing HSTS",
		Description: "Transport protection is absent",
		Impact:      "Traffic can be downgraded",
		Source:      "security_scan",
		Location:    "https://example.test/",
		Remediation: "Set Strict-Transport-Security",
		Evidence:    "no HSTS header",
		Confidence:  ConfidenceVerified,
		CWE:         "CWE-319",
		Digests:     []string{"abcdef0123456789"},
	}

	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal canonical finding: %v", err)
	}
	for _, key := range []string{
		`"id"`, `"severity"`, `"title"`, `"description"`, `"impact"`, `"source"`,
		`"location"`, `"remediation"`, `"evidence"`, `"confidence"`, `"cwe"`, `"digests"`,
	} {
		if !bytes.Contains(raw, []byte(key)) {
			t.Errorf("marshaled JSON %s is missing key %s", raw, key)
		}
	}

	var decoded Finding
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal canonical finding: %v", err)
	}
	if !reflect.DeepEqual(decoded, original) {
		t.Fatalf("round trip changed finding:\n got %+v\nwant %+v", decoded, original)
	}
}
