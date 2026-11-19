package scanner

import (
	"reflect"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/shared"
)

// parityResult exercises both entry points with the same rich input. A scan of
// one target must yield the same findings and score no matter which binary
// produced it.
func parityResult() *ScanResult {
	return &ScanResult{
		TLS: &TLSInfo{
			Version: "TLS 1.0",
			Certificate: &CertInfo{
				IsExpired:    true,
				IsSelfSigned: true,
				NotAfter:     time.Date(2023, 5, 6, 0, 0, 0, 0, time.UTC),
			},
			Vulnerabilities: []string{"Insecure cipher: TLS_RSA_WITH_RC4_128_SHA"},
		},
		Security: &SecurityInfo{MissingHeaders: []string{"X-Frame-Options"}, Score: 80},
		HTTP:     &HTTPInfo{CORS: &CORSInfo{AllowOrigin: "*", IsPermissive: true}},
		WAF:      &WAFInfo{Detected: false},
	}
}

func TestScannerUsesSharedFindingRules(t *testing.T) {
	r := parityResult()
	if got, want := calculateVulns(r), shared.CalculateVulns(r); !reflect.DeepEqual(got, want) {
		t.Fatalf("scanner findings drifted from shared rules:\n got %+v\nwant %+v", got, want)
	}
	if got, want := calculateRiskScore(r), shared.CalculateRiskScore(r); got != want {
		t.Errorf("scanner score = %d, shared = %d", got, want)
	}

	// Explicit canonical IDs: a future local re-implementation must not be able
	// to silently drop TLS-003/004 or change SEC-* casing again.
	ids := make([]string, 0, 7)
	for _, v := range calculateVulns(r) {
		ids = append(ids, v.ID)
	}
	want := []string{"TLS-001", "TLS-002", "TLS-003", "TLS-004", "SEC-xframeoptions", "CORS-001", "WAF-001"}
	if !reflect.DeepEqual(ids, want) {
		t.Errorf("canonical finding IDs = %v, want %v", ids, want)
	}
}
