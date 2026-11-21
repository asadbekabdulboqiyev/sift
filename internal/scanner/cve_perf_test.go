package scanner

// cve_perf_test.go — benchmarks and equivalence checks for the CVE matcher.
// The benchmarks exercise the production checkCVE path so the numbers before
// and after the compiled-pattern change are directly comparable.

import (
	"strings"
	"testing"
)

func cveBenchTech(body string) map[string]string {
	return map[string]string{
		"server":         "Apache/2.4.49 (Unix)",
		"powered_by":     "PHP/8.0.13",
		"body":           body,
		"apache_version": "2.4.49",
		"php":            "true",
		"spring":         "true",
		"wordpress":      "true",
		"wordpress_path": "true",
	}
}

// BenchmarkCheckCVEAllSignatures isolates the per-call pattern compilation
// cost: every signature has to be tested against a short fingerprint.
func BenchmarkCheckCVEAllSignatures(b *testing.B) {
	det := NewCVEDetector("http://example.com")
	tech := cveBenchTech("<html><body>hello</body></html>")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, sig := range cveDatabase {
			_ = det.checkCVE(sig, tech)
		}
	}
}

// BenchmarkCheckCVELargeBody is the end-to-end hot path: a roughly 1 MB
// response body scanned through every signature.
func BenchmarkCheckCVELargeBody(b *testing.B) {
	det := NewCVEDetector("http://example.com")
	body := "<html><body>" + strings.Repeat("plain text content ", 1<<16) + "</body></html>"
	tech := cveBenchTech(body)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, sig := range cveDatabase {
			_ = det.checkCVE(sig, tech)
		}
	}
}

func TestCompileCVEPatternCachesValidAndInvalid(t *testing.T) {
	valid := `(?i)` + t.Name()
	first := compileCVEPattern(valid)
	second := compileCVEPattern(valid)
	if first == nil || first != second {
		t.Fatal("valid pattern should compile once and be reused")
	}

	invalid := `(` + t.Name()
	if got := compileCVEPattern(invalid); got != nil {
		t.Fatalf("invalid pattern should be skipped, got %v", got)
	}
	if got := compileCVEPattern(invalid); got != nil {
		t.Fatalf("cached invalid pattern should be skipped, got %v", got)
	}
	cvePatternCacheMu.RLock()
	_, cachedInvalid := cvePatternInvalid[invalid]
	cvePatternCacheMu.RUnlock()
	if !cachedInvalid {
		t.Fatal("invalid pattern should be cached as invalid")
	}
}

func TestCheckCVEInvalidPatternIsSkipped(t *testing.T) {
	det := NewCVEDetector("http://example.com")
	sig := cveSignature{
		CVEID: "TEST-INVALID-PATTERN",
		Patterns: []cvePattern{
			{Type: "body", Match: `(`},
			{Type: "body", Match: `(?i)needle`},
		},
	}
	tech := map[string]string{"body": "haystack NEEDLE"}

	match := det.checkCVE(sig, tech)
	if match == nil {
		t.Fatal("valid pattern should still match after an invalid pattern")
	}
	if want := `body:(?i)needle`; match.Evidence != want {
		t.Fatalf("evidence = %q, want %q", match.Evidence, want)
	}
}
