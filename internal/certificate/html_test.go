package certificate

// html_test.go — layout and hash-boundary invariants of the printable document.
//
// Two classes of bug live here, and both are invisible in a unit test that only
// checks the HTML contains a title:
//
//  1. The certificate page must be exactly one A4 sheet. A layout that grows
//     past 297 mm pushes the footer onto a second page, and a printed
//     certificate that opens with a stray blank page is not acceptable.
//  2. Anything known only after signing (certificate id, validity, previous
//     hash, signature) must live inside the seal block. Outside it, the
//     verification recomputes the document hash over values that were not
//     present when it was signed, and every certificate fails with
//     "document hash mismatch".

import (
	"strings"
	"testing"

	"github.com/asadbekabdulboqiyev/sift/internal/attest"
)

func htmlTestCert(t *testing.T) *Certificate {
	t.Helper()
	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	a := NewFromPentest("https://example.com", "full scope", "QA Lead", "0.16.6", 12, "B", "PASS",
		Counts{Medium: 1}, 9, "2026-11-07T08:00:00Z", "2026-11-07T08:01:00Z", "1m0s")
	a.Findings = []Finding{{
		ID: "F-001", Severity: "medium",
		Title:    "Missing Content-Security-Policy header",
		Evidence: "no CSP on / and /login",
	}}
	a.Compliance = []ComplianceResult{{
		Framework: "OWASP Top 10 (2021)", ID: "A05",
		Title: "Security Misconfiguration", Status: "FAIL",
	}}
	c, err := Issue(kp, a, "previous-hash-abc123", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return c
}

// TestHTTPSheetGeometry pins the two layout decisions that were measured in a
// real browser: the certificate sheet is a fixed 297 mm box that clips its own
// overflow, and the annex is a plain block so a forced page break applies.
func TestHTTPSheetGeometry(t *testing.T) {
	doc := HTML(htmlTestCert(t))

	for _, want := range []string{
		// The certificate page is one sheet, and a rounding difference between
		// the 297 mm box and the paper is clipped instead of spilling.
		`.sheet.page1 { height: 297mm; display: flex; flex-direction: column; overflow: hidden; }`,
		// Chrome ignores a forced page break on a flex container, so the annex
		// must be a block.
		`.sheet.annex { min-height: 297mm; display: block; }`,
		// The annex footer cannot use margin-top:auto outside a flex container.
		`.annexfoot { margin-top: 6mm;`,
		// Print pagination: the annex starts on its own page.
		`break-before: page; page-break-before: always;`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("rendered document is missing %q", want)
		}
	}
}

// TestHTMLSealCarriesEveryPostSigningValue proves the hash boundary holds: the
// document minus the seal must be byte-identical to what was signed, so nothing
// that only exists after signing may appear outside it.
func TestHTMLSealCarriesEveryPostSigningValue(t *testing.T) {
	c := htmlTestCert(t)

	outside := stripSeal(c.HTML)
	if outside == c.HTML {
		t.Fatal("stripSeal removed nothing; the seal marker is missing")
	}
	// Each value is checked in the form the document actually renders it: the
	// signature raw, the key and the document hash grouped, the previous hash
	// shortened. Checking the raw field would pass on an empty document.
	for name, value := range map[string]string{
		"signature":       c.Signature,
		"public key":      groupHex(c.PublicKey, 4),
		"certificate id":  c.CertificateID,
		"validity":        c.ValidityPeriod,
		"previous hash":   shortHex(c.PreviousCertificateHash, 16),
		"document sha256": groupHex(c.Assessment.DocumentSHA, 8),
	} {
		if value == "" {
			t.Fatalf("%s is empty in the fixture; the test would pass vacuously", name)
		}
		if strings.Contains(outside, value) {
			t.Errorf("%s appears outside the seal; verification would fail with a document hash mismatch", name)
		}
		if !strings.Contains(c.HTML, value) {
			t.Errorf("%s is not rendered anywhere in the document", name)
		}
	}

	// The values the document was signed with must survive inside the seal.
	if got := documentSHA(c.HTML); got != c.Assessment.DocumentSHA {
		t.Fatalf("document hash drifted after sealing: got %s, signed %s", got, c.Assessment.DocumentSHA)
	}
}

// TestHTMLTwoPageStructure checks the annex is a separate sheet with its own
// masthead, so a reader can tell page 1 is the certificate and page 2 is the
// findings, not one long document.
func TestHTMLTwoPageStructure(t *testing.T) {
	doc := HTML(htmlTestCert(t))
	if n := strings.Count(doc, `class="sheet page1"`); n != 1 {
		t.Fatalf("certificate sheet appears %d times, want 1", n)
	}
	if n := strings.Count(doc, `class="sheet annex"`); n != 1 {
		t.Fatalf("annex sheet appears %d times, want 1", n)
	}
	if !strings.Contains(doc, `class="annexhead"`) {
		t.Error("annex has no masthead")
	}
	// The annex must not repeat the double frame: a frame would be cut in half
	// at a page boundary.
	if strings.Contains(doc, `.sheet.annex::before`) || strings.Contains(doc, `.sheet.annex::after`) {
		t.Error("annex draws a frame that will be cut at a page boundary")
	}
}

// TestSplitVerdict pins the mapping from the report ladder's one-line verdict
// to the certificate's headline, detail and colour.
//
// The previous code derived the CSS class with strings.ToLower, which turned
// "MEDIUM RISK -- Remediation recommended" into a class name containing spaces.
// No rule matched, so every verdict rendered in the body colour and the
// v-pass / v-fail / v-warn rules were dead code.
func TestSplitVerdict(t *testing.T) {
	for _, tc := range []struct {
		in, head, detail, tone string
	}{
		{"MEDIUM RISK -- Remediation recommended", "MEDIUM RISK", "Remediation recommended", "v-warn"},
		{"CRITICAL RISK -- Immediate remediation required", "CRITICAL RISK", "Immediate remediation required", "v-fail"},
		{"HIGH RISK -- Urgent remediation recommended", "HIGH RISK", "Urgent remediation recommended", "v-fail"},
		{"LOW RISK -- Minor issues found", "LOW RISK", "Minor issues found", "v-warn"},
		{"CLEAN -- No significant issues found", "CLEAN", "No significant issues found", "v-pass"},
		{"PASS", "PASS", "", "v-pass"},
		{"FAIL", "FAIL", "", "v-fail"},
		{"REVIEW", "REVIEW", "", "v-warn"},
		{"", "—", "", ""},
		{"SOMETHING ELSE", "SOMETHING ELSE", "", ""},
	} {
		head, detail, tone := splitVerdict(tc.in)
		if head != tc.head || detail != tc.detail || tone != tc.tone {
			t.Errorf("splitVerdict(%q) = (%q, %q, %q), want (%q, %q, %q)",
				tc.in, head, detail, tone, tc.head, tc.detail, tc.tone)
		}
	}
}

// TestHTMLVerdictRendersTone checks the tone class reaches the document and a
// long ladder verdict is split instead of running off the sheet.
func TestHTMLVerdictRendersTone(t *testing.T) {
	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	a := NewFromPentest("https://example.com", "full scope", "QA Lead", "0.16.6", 44, "C",
		"MEDIUM RISK -- Remediation recommended",
		Counts{Medium: 3}, 7, "2026-11-07T08:00:00Z", "2026-11-07T08:01:00Z", "1m0s")
	a.Findings = []Finding{
		{ID: "F-001", Severity: "medium", Title: "Missing CSP header", Evidence: "no CSP on /"},
		{ID: "F-002", Severity: "medium", Title: "Cookie without SameSite", Evidence: "session cookie"},
		{ID: "F-003", Severity: "medium", Title: "Directory listing enabled", Evidence: "/static/"},
	}
	c, err := Issue(kp, a, "", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	doc := c.HTML
	if !strings.Contains(doc, `class="v v-warn">MEDIUM RISK</div>`) {
		t.Error("verdict headline is not rendered with its tone class")
	}
	if !strings.Contains(doc, `<div class="vd">Remediation recommended</div>`) {
		t.Error("verdict detail is not rendered under the headline")
	}
	if strings.Contains(doc, "v-medium risk") {
		t.Error("the raw verdict leaked into a class name again")
	}
}
