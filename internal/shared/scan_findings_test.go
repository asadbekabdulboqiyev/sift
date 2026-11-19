package shared

import (
	"reflect"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/scanner/core"
)

// richResult exercises every branch of the canonical finding rules at once:
// expired + self-signed cert, a weak cipher, a deprecated version, a missing
// header (mixed case), a permissive CORS policy and no WAF.
func richResult() *core.ScanResult {
	return &core.ScanResult{
		TLS: &core.TLSInfo{
			Version: "TLS 1.0",
			Certificate: &core.CertInfo{
				IsExpired:    true,
				IsSelfSigned: true,
				NotAfter:     time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC),
			},
			Vulnerabilities: []string{"Insecure cipher: TLS_RSA_WITH_RC4_128_SHA"},
		},
		Security: &core.SecurityInfo{MissingHeaders: []string{"X-Frame-Options"}},
		HTTP:     &core.HTTPInfo{CORS: &core.CORSInfo{AllowOrigin: "*", IsPermissive: true}},
		WAF:      &core.WAFInfo{Detected: false},
	}
}

func TestCalculateVulnsCanonicalIDs(t *testing.T) {
	vulns := CalculateVulns(richResult())

	got := make([]string, 0, len(vulns))
	for _, v := range vulns {
		got = append(got, v.ID)
	}
	want := []string{
		"TLS-001", "TLS-002", "TLS-003", "TLS-004",
		"SEC-xframeoptions", "CORS-001", "WAF-001",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("finding IDs = %v, want %v", got, want)
	}

	// The weak-cipher finding (TLS-003) and the deprecated-version finding
	// (TLS-004) must coexist: the old sift-scan copy emitted only one of them.
	if vulns[2].Title != "Insecure cipher: TLS_RSA_WITH_RC4_128_SHA" {
		t.Errorf("TLS-003 title = %q", vulns[2].Title)
	}
	if vulns[3].Title != "Deprecated TLS Version" {
		t.Errorf("TLS-004 title = %q", vulns[3].Title)
	}
}

func TestCalculateRiskScoreClampsAndDeducts(t *testing.T) {
	tests := []struct {
		name string
		r    *core.ScanResult
		want int
	}{
		{"clean", &core.ScanResult{}, 100},
		{"nil", nil, 100},
		{"insecure TLS", &core.ScanResult{TLS: &core.TLSInfo{}}, 80},
		{"clamped at zero", richResult(), 0},
		{"capped at 100", &core.ScanResult{Security: &core.SecurityInfo{Score: 200}}, 100},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := CalculateRiskScore(tc.r); got != tc.want {
				t.Errorf("CalculateRiskScore() = %d, want %d", got, tc.want)
			}
		})
	}
}
