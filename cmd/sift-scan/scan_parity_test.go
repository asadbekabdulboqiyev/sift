package main

import (
	"reflect"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/scanner"
	"github.com/asadbekabdulboqiyev/sift/internal/shared"
)

// regressionResult is identical to the one used by the scanner's parity test.
// The old sift-scan copy produced only TLS-003 (for the deprecated version),
// uppercase SEC-* IDs, and no WAF finding for this exact input.
func regressionResult() *scanner.ScanResult {
	return &scanner.ScanResult{
		TLS: &scanner.TLSInfo{
			Version: "TLS 1.0",
			Certificate: &scanner.CertInfo{
				IsExpired:    true,
				IsSelfSigned: true,
				NotAfter:     time.Date(2023, 5, 6, 0, 0, 0, 0, time.UTC),
			},
			Vulnerabilities: []string{"Insecure cipher: TLS_RSA_WITH_RC4_128_SHA"},
		},
		Security: &scanner.SecurityInfo{MissingHeaders: []string{"X-Frame-Options"}, Score: 80},
		HTTP:     &scanner.HTTPInfo{CORS: &scanner.CORSInfo{AllowOrigin: "*", IsPermissive: true}},
		WAF:      &scanner.WAFInfo{Detected: false},
	}
}

func TestSiftScanUsesSharedFindingRules(t *testing.T) {
	r := regressionResult()

	// The CLI entry point and the shared canonical rule must be the same
	// function in effect. If a local copy is reintroduced, this fails.
	if got, want := calculateVulns(r), shared.CalculateVulns(r); !reflect.DeepEqual(got, want) {
		t.Fatalf("sift-scan findings drifted from shared rules:\n got %+v\nwant %+v", got, want)
	}
	if got, want := calculateRiskScore(r), shared.CalculateRiskScore(r); got != want {
		t.Errorf("sift-scan score = %d, shared = %d", got, want)
	}

	ids := make([]string, 0, 7)
	for _, v := range calculateVulns(r) {
		ids = append(ids, v.ID)
	}
	want := []string{"TLS-001", "TLS-002", "TLS-003", "TLS-004", "SEC-xframeoptions", "CORS-001", "WAF-001"}
	if !reflect.DeepEqual(ids, want) {
		t.Errorf("canonical finding IDs = %v, want %v", ids, want)
	}
}

func TestSiftScanStatusHelpersUseSharedRules(t *testing.T) {
	if got, want := statusRank("FAIL"), shared.OWASPStatusRank("FAIL"); got != want {
		t.Errorf("statusRank(FAIL) = %d, want %d", got, want)
	}
	if got, want := worseStatus("WARNING", "FAIL"), shared.OWASPWorstStatus("WARNING", "FAIL"); got != want {
		t.Errorf("worseStatus = %q, want %q", got, want)
	}
}
