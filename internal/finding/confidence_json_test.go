package finding

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestConfidenceUnmarshalJSONAcceptsCanonicalAndLegacyValues checks that every
// historical spelling is normalised on the way in, including the JSON null
// case which must land on the conservative Unchecked value.
func TestConfidenceUnmarshalJSONAcceptsCanonicalAndLegacyValues(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want Confidence
	}{
		{name: "canonical verified", raw: `"verified"`, want: ConfidenceVerified},
		{name: "canonical heuristic", raw: `"heuristic"`, want: ConfidenceHeuristic},
		{name: "canonical unchecked", raw: `"unchecked"`, want: ConfidenceUnchecked},
		{name: "legacy confirmed", raw: `"confirmed"`, want: ConfidenceVerified},
		{name: "legacy high", raw: `"high"`, want: ConfidenceVerified},
		{name: "legacy informational", raw: `"informational"`, want: ConfidenceUnchecked},
		{name: "case and whitespace are normalised", raw: `" HIGH "`, want: ConfidenceVerified},
		{name: "json null degrades to unchecked", raw: `null`, want: ConfidenceUnchecked},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange: start from a non-zero value so the decode has to overwrite it.
			got := ConfidenceVerified

			// Act
			err := json.Unmarshal([]byte(tc.raw), &got)

			// Assert
			if err != nil {
				t.Fatalf("unmarshal %s: %v", tc.raw, err)
			}
			if got != tc.want {
				t.Fatalf("unmarshal %s = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

// TestConfidenceUnmarshalJSONRejectsNonStrings covers the error branch that
// prevents numbers, objects and arrays from being promoted to a confidence.
func TestConfidenceUnmarshalJSONRejectsNonStrings(t *testing.T) {
	cases := []string{`7`, `true`, `{}`, `[]`}

	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			// Arrange
			c := Confidence("")

			// Act
			err := json.Unmarshal([]byte(raw), &c)

			// Assert
			if err == nil {
				t.Fatalf("unmarshal %s succeeded, want type error", raw)
			}
			if !strings.Contains(err.Error(), "finding: confidence must be a string") {
				t.Fatalf("unmarshal %s error = %v, want wrapped type error", raw, err)
			}
			if c != "" {
				t.Fatalf("failed unmarshal changed confidence to %q", c)
			}
		})
	}
}

// TestConfidenceMarshalJSONAlwaysEmitsCanonicalSpelling guards the signed
// document boundary: a legacy value written directly into the enum must never
// leak into published JSON.
func TestConfidenceMarshalJSONAlwaysEmitsCanonicalSpelling(t *testing.T) {
	cases := []struct {
		name string
		in   Confidence
		want string
	}{
		{name: "verified stays verified", in: ConfidenceVerified, want: `"verified"`},
		{name: "heuristic stays heuristic", in: ConfidenceHeuristic, want: `"heuristic"`},
		{name: "unchecked stays unchecked", in: ConfidenceUnchecked, want: `"unchecked"`},
		{name: "legacy confirmed becomes verified", in: Confidence("confirmed"), want: `"verified"`},
		{name: "legacy high becomes verified", in: Confidence("high"), want: `"verified"`},
		{name: "unknown text becomes unchecked", in: Confidence("guess"), want: `"unchecked"`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			got, err := json.Marshal(tc.in)

			// Assert
			if err != nil {
				t.Fatalf("marshal %q: %v", tc.in, err)
			}
			if string(got) != tc.want {
				t.Fatalf("marshal %q = %s, want %s", tc.in, got, tc.want)
			}
		})
	}
}
