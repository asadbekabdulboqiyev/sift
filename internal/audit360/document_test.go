package audit360

import (
	"bytes"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const testSignerKey = "3b1f8a1e6d4c2b0a9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a3928"

// sealedReport is a fully populated report used by the rendering tests. It
// mimics the shape produced by Seal: signature, certificate ID and the signer
// public key carried in Notes.
func sealedReport() *Audit360Report {
	return &Audit360Report{
		ResilienceScore:    72,
		RiskLevel:          "Medium",
		BreakingPointUsers: 250,
		MaxSafeRPS:         41.5,
		MaxObservedRPS:     63.25,
		MaxObservedUsers:   240,
		Findings: []Finding{
			{
				Title:         "Verbose error page",
				Severity:      "high",
				ImpactSummary: "Stack traces leak internal paths",
				Remediation:   "Disable debug output in production",
				Evidence:      "HTTP 500 body contained /srv/app/main.go",
				Source:        "security_scan",
			},
		},
		VPMPSignature:     strings.Repeat("ab", 64),
		CertificateID:     "sift360-0123456789abcdef",
		Timestamp:         "2026-01-02T03:04:05Z",
		TargetURL:         "https://example.test/app",
		DurationMS:        180000,
		Notes:             []string{"run mode: standard", "VPMP signer public key (hex): " + testSignerKey},
		LoadTestAvailable: true,
		Scores: &ScoreBreakdown{
			Overall: 72, Security: 66, Resilience: 80, Capacity: 71, EvidenceQuality: 90,
		},
		ScoringVersion:    "scoring/v3",
		TestConfiguration: &TestConfiguration{Mode: "standard", MaxDurationSec: 180, RequestedTarget: "https://example.test/app", SecurityScanEnabled: true, ActiveLoadEnabled: true, LoadMaxUsers: 500},
		RawEvidenceHash:   strings.Repeat("cd", 32),
		RawEvidenceFormat: "sift.evidence/v1+json",
	}
}

// TestRenderHTMLNilReport covers the empty-state path: callers may render a
// document before a report exists and must get a placeholder, not a panic.
func TestRenderHTMLNilReport(t *testing.T) {
	// Arrange
	var report *Audit360Report

	// Act
	out := RenderHTML(report)

	// Assert
	if !strings.Contains(out, "No audit360 report.") {
		t.Fatalf("RenderHTML(nil) = %q, want it to contain %q", out, "No audit360 report.")
	}
}

// TestRenderHTMLSealedReportContainsSealAndScores verifies the document
// surfaces the fields an auditor relies on: certificate id, seal status,
// signer key, signature, scores, findings, config and evidence hashes.
func TestRenderHTMLSealedReportContainsSealAndScores(t *testing.T) {
	// Arrange
	report := sealedReport()

	// Act
	out := RenderHTML(report)

	// Assert
	if !strings.HasPrefix(out, "<!doctype html>") {
		t.Errorf("RenderHTML output does not start with a doctype")
	}
	if !strings.HasSuffix(out, "</html>") {
		t.Errorf("RenderHTML output does not end with </html>")
	}
	wantContains := []string{
		report.CertificateID,
		report.TargetURL,
		report.Timestamp,
		"Present (VPMP Ed25519 seal)",
		testSignerKey,
		report.VPMPSignature,
		report.ScoringVersion,
		report.RawEvidenceHash,
		report.RawEvidenceFormat,
		"Verbose error page",
		"Disable debug output in production",
		"No breaking point in window",
		"Peak observed throughput: 63.25 req/s",
		"41.50 req/s",
		"63.25 req/s",
		"180000 ms",
		"standard",
	}
	for _, want := range wantContains {
		if !strings.Contains(out, want) {
			t.Errorf("RenderHTML output missing %q", want)
		}
	}
}

// TestRenderHTMLUnsignedReportShowsUnavailable makes sure an unsigned report is
// not rendered as if it were sealed: no signature means the seal must read
// "Unavailable" and empty envelope fields must not render as blank cells.
func TestRenderHTMLUnsignedReportShowsUnavailable(t *testing.T) {
	// Arrange
	report := &Audit360Report{RiskLevel: "Low", ResilienceScore: 95}

	// Act
	out := RenderHTML(report)

	// Assert
	if strings.Contains(out, "Present (VPMP Ed25519 seal)") {
		t.Errorf("unsigned report rendered as sealed")
	}
	if !strings.Contains(out, "Unavailable") {
		t.Errorf("unsigned report does not report an Unavailable seal")
	}
	if !strings.Contains(out, "unavailable") {
		t.Errorf("unsigned report does not render the certificate id placeholder")
	}
	if !strings.Contains(out, "No significant findings reported") {
		t.Errorf("report without findings does not render the empty-findings message")
	}
	if !strings.Contains(out, "No additional notes.") {
		t.Errorf("report without notes does not render the empty-notes message")
	}
}

// TestRenderHTMLEscapesUntrustedFields guards against stored XSS: report fields
// can originate from scanned targets, so they must be HTML-escaped.
func TestRenderHTMLEscapesUntrustedFields(t *testing.T) {
	// Arrange
	payload := `"><script>alert(1)</script>`
	report := &Audit360Report{
		RiskLevel:     "High",
		TargetURL:     "https://example.test/" + payload,
		Timestamp:     payload,
		Findings:      []Finding{{Title: payload, Severity: "critical", ImpactSummary: payload, Remediation: payload, Evidence: payload}},
		Notes:         []string{payload},
		Scores:        &ScoreBreakdown{Overall: 10, Security: 10, Resilience: 10, Capacity: 10, EvidenceQuality: 10},
		CertificateID: payload,
	}

	// Act
	out := RenderHTML(report)

	// Assert
	if strings.Contains(out, "<script>alert(1)</script>") {
		t.Fatalf("RenderHTML emitted an unescaped script tag")
	}
	if !strings.Contains(out, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Errorf("RenderHTML does not escape <script> in report fields")
	}
	// html.EscapeString renders `"` as &#34;; the payload starts with `">` so a
	// correctly escaped document contains `&#34;&gt;`.
	if !strings.Contains(out, "&#34;&gt;") {
		t.Errorf("RenderHTML does not escape double quotes in report fields")
	}
}

// TestRenderPDFProducesValidPDF checks the byte-level envelope of the generated
// PDF: header, cross-reference trailer and EOF marker must be present so the
// artifact opens in a viewer.
func TestRenderPDFProducesValidPDF(t *testing.T) {
	// Arrange
	report := sealedReport()

	// Act
	out, err := RenderPDF(report)

	// Assert
	if err != nil {
		t.Fatalf("RenderPDF returned error: %v", err)
	}
	if !bytes.HasPrefix(out, []byte("%PDF-1.4\n")) {
		t.Errorf("RenderPDF output does not start with %%PDF-1.4 header: %q", out[:min(len(out), 16)])
	}
	if !bytes.Contains(out, []byte("\nxref\n0 ")) {
		t.Errorf("RenderPDF output has no xref table")
	}
	if !bytes.HasSuffix(out, []byte("%%EOF\n")) {
		t.Errorf("RenderPDF output does not end with %%%%EOF")
	}
	for _, want := range []string{
		"SIFT 360",
		"SIGNED AUDIT",
		report.CertificateID,
		report.TargetURL,
		"72 / 100",
		"180000 ms",
		"Helvetica",
	} {
		if !bytes.Contains(out, []byte(want)) {
			t.Errorf("RenderPDF output missing %q", want)
		}
	}
}

// TestRenderPDFNilReport covers the empty-state path for PDF rendering.
func TestRenderPDFNilReport(t *testing.T) {
	// Arrange
	var report *Audit360Report

	// Act
	out, err := RenderPDF(report)

	// Assert
	if err != nil {
		t.Fatalf("RenderPDF(nil) returned error: %v", err)
	}
	if !bytes.HasPrefix(out, []byte("%PDF-1.4\n")) {
		t.Errorf("RenderPDF(nil) output is not a PDF")
	}
	if !bytes.Contains(out, []byte("No report data.")) {
		t.Errorf("RenderPDF(nil) does not render the placeholder text")
	}
}

// TestRenderPDFEscapesContentStreamSyntax verifies characters that are special
// inside a PDF string literal are escaped, otherwise the document structure
// breaks on hostile report text.
func TestRenderPDFEscapesContentStreamSyntax(t *testing.T) {
	// Arrange
	report := &Audit360Report{
		RiskLevel:       "Low",
		ResilienceScore: 100,
		TargetURL:       `https://example.test/a(b)c\d`,
	}

	// Act
	out, err := RenderPDF(report)

	// Assert
	if err != nil {
		t.Fatalf("RenderPDF returned error: %v", err)
	}
	if !bytes.Contains(out, []byte(`https://example.test/a\(b\)c\\d) Tj`)) {
		t.Errorf("RenderPDF does not escape parentheses/backslashes in string literals")
	}
}

// TestExtractSignerPublicKey covers the Notes parsing used by both renderers to
// display the signer key embedded by Seal.
func TestExtractSignerPublicKey(t *testing.T) {
	// Arrange
	tests := []struct {
		name  string
		notes []string
		want  string
	}{
		{name: "absent", notes: nil, want: ""},
		{name: "unrelated notes", notes: []string{"mode: standard", "workers: 2"}, want: ""},
		{name: "present", notes: []string{"mode: standard", "VPMP signer public key (hex): " + testSignerKey}, want: testSignerKey},
		{name: "extra whitespace", notes: []string{"  VPMP signer public key (hex):   deadbeef  "}, want: "deadbeef"},
		{name: "prefix only", notes: []string{"VPMP signer public key (hex): "}, want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			got := extractSignerPublicKey(tc.notes)

			// Assert
			if got != tc.want {
				t.Errorf("extractSignerPublicKey(%q) = %q, want %q", tc.notes, got, tc.want)
			}
		})
	}
}

// TestClampDocScore keeps out-of-range scores from producing broken progress
// bars or impossible document claims.
func TestClampDocScore(t *testing.T) {
	// Arrange
	tests := []struct{ in, want int }{
		{in: -50, want: 0},
		{in: -1, want: 0},
		{in: 0, want: 0},
		{in: 55, want: 55},
		{in: 100, want: 100},
		{in: 101, want: 100},
		{in: 9999, want: 100},
	}

	for _, tc := range tests {
		// Act
		got := clampDocScore(tc.in)

		// Assert
		if got != tc.want {
			t.Errorf("clampDocScore(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// TestChunkString covers the helper used for long single-line PDF content.
func TestChunkString(t *testing.T) {
	// Arrange
	tests := []struct {
		name string
		in   string
		n    int
		want []string
	}{
		{name: "zero width returns input", in: "abcdef", n: 0, want: []string{"abcdef"}},
		{name: "negative width returns input", in: "abcdef", n: -3, want: []string{"abcdef"}},
		{name: "shorter than width", in: "abc", n: 10, want: []string{"abc"}},
		{name: "exact width", in: "abcd", n: 4, want: []string{"abcd"}},
		{name: "even split", in: "abcdef", n: 2, want: []string{"ab", "cd", "ef"}},
		{name: "remainder", in: "abcde", n: 2, want: []string{"ab", "cd", "e"}},
		{name: "empty string", in: "", n: 2, want: []string{""}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			got := chunkString(tc.in, tc.n)

			// Assert
			if len(got) != len(tc.want) {
				t.Fatalf("chunkString(%q, %d) = %q, want %q", tc.in, tc.n, got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("chunkString(%q, %d) = %q, want %q", tc.in, tc.n, got, tc.want)
				}
			}
			if joined := strings.Join(got, ""); joined != tc.in {
				t.Errorf("chunks do not reassemble input: %q != %q", joined, tc.in)
			}
		})
	}
}

// TestSanitizePDFText drops control characters that would corrupt the content
// stream while preserving newlines and replacing tabs with spaces.
func TestSanitizePDFText(t *testing.T) {
	// Arrange
	in := "line1\x00\x07\tline2\nline3"

	// Act
	got := sanitizePDFText(in)

	// Assert
	want := "line1 line2\nline3"
	if got != want {
		t.Errorf("sanitizePDFText(%q) = %q, want %q", in, got, want)
	}
}

// TestPDFEscapeStr covers the PDF string-literal escaping rules.
func TestPDFEscapeStr(t *testing.T) {
	// Arrange
	tests := []struct{ name, in, want string }{
		{name: "plain", in: "hello", want: "hello"},
		{name: "parentheses and backslash", in: `a(b)c\d`, want: `a\(b\)c\\d`},
		{name: "control chars replaced", in: "a\x00b\x07c", want: "a?b?c"},
		{name: "whitespace collapsed", in: "a\nb\rc\td", want: "a b c d"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			got := pdfEscapeStr(tc.in)

			// Assert
			if got != tc.want {
				t.Errorf("pdfEscapeStr(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestRenderPDFPaginatesLongReports exercises the multi-page branch: long
// reports must produce a pages tree with a matching count and one content
// stream per page, otherwise viewers show a truncated document.
func TestRenderPDFPaginatesLongReports(t *testing.T) {
	// Arrange
	report := sealedReport()
	report.Findings = make([]Finding, 0, 30)
	for i := 0; i < 30; i++ {
		report.Findings = append(report.Findings, Finding{
			Title:         "finding " + strings.Repeat("x", 20),
			Severity:      "medium",
			ImpactSummary: "impact text that is reasonably long to consume a line",
			Remediation:   "remediation text that is reasonably long to consume a line",
			Evidence:      "evidence text that is reasonably long to consume a line",
		})
	}

	// Act
	out, err := RenderPDF(report)

	// Assert
	if err != nil {
		t.Fatalf("RenderPDF returned error: %v", err)
	}
	m := regexp.MustCompile(`/Type /Pages /Kids \[[^\]]*\] /Count (\d+)`).FindSubmatch(out)
	if m == nil {
		t.Fatalf("RenderPDF output has no pages tree")
	}
	pages, err := strconv.Atoi(string(m[1]))
	if err != nil {
		t.Fatalf("page count %q is not an integer: %v", m[1], err)
	}
	if pages < 2 {
		t.Fatalf("page count = %d, want >= 2 for a long report", pages)
	}
	if got := bytes.Count(out, []byte("BT\n/F1 9 Tf")); got != pages {
		t.Errorf("content streams = %d, want %d (one per page)", got, pages)
	}
	if !bytes.HasSuffix(out, []byte("%%EOF\n")) {
		t.Errorf("multi-page PDF does not end with %%%%EOF")
	}
}
