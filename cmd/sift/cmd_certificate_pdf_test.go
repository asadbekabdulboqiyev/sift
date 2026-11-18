package main

// cmd_certificate_pdf_test.go — regressions for the printable certificate PDF.
//
// Two failures are pinned here:
//
//  1. renderPDF dereferenced the certificate envelope without a nil check, so
//     printing from an assessment alone panicked.
//  2. The PDF writer emitted a page that pointed at the wrong objects, so every
//     certificate PDF opened as a blank page while still being non-empty bytes.
//
// The blank-page bug is tested structurally in internal/certificate; the tests
// here prove the CLI's renderer actually puts the certificate content into the
// stream and never panics.

import (
	"bytes"
	"strconv"
	"strings"
	"testing"

	"github.com/asadbekabdulboqiyev/sift/internal/attest"
	"github.com/asadbekabdulboqiyev/sift/internal/certificate"
)

func pdfTestAssessment() certificate.Assessment {
	return certificate.NewFromPentest(
		"https://school12.example.uz", "Public web application", "Sift School Audit",
		"0.16.6", 28, "B", "REVIEW",
		certificate.Counts{}, 8,
		"2026-11-18T09:12:04Z", "2026-11-18T09:41:37Z", "29m33s")
}

// TestRenderPDFNilCertificateDoesNotPanic pins the crash: callers pass nil when
// they only have an assessment, and a nil dereference while writing the
// printable copy of a signed document is not an acceptable failure mode.
func TestRenderPDFNilCertificateDoesNotPanic(t *testing.T) {
	a := pdfTestAssessment()
	got := renderPDF(a, nil)
	if len(got) == 0 {
		t.Fatal("renderPDF returned no bytes for a nil certificate")
	}
	if !strings.HasPrefix(string(got), "%PDF-1.4") {
		t.Fatalf("output is not a PDF: %q", string(got[:min(16, len(got))]))
	}
}

// TestRenderPDFCarriesFindingsAndCompliance proves the printed copy is a
// certificate and not a stub: the findings and the compliance mapping have to
// survive into the PDF.
func TestRenderPDFCarriesFindingsAndCompliance(t *testing.T) {
	a := pdfTestAssessment()
	a.Findings = []certificate.Finding{
		{ID: "F-001", Severity: "high", Title: "Missing HSTS header", Evidence: "no header on /login"},
	}
	a.Compliance = []certificate.ComplianceResult{
		{Framework: "OWASP Top 10 (2021)", ID: "A05", Title: "Security Misconfiguration", Status: "FAIL"},
	}
	a.Counts = certificate.Counts{High: 1}

	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	cert, err := certificate.Issue(kp, a, "", "exp-pdf")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	got := string(renderPDF(cert.Assessment, cert))
	for _, want := range []string{
		"(Target: https://school12.example.uz) Tj",
		"Missing HSTS header",
		"Security Misconfiguration",
		`Signature \(Ed25519, over canonical assessment JSON\):`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("PDF is missing %q", want)
		}
	}

	// The 128-character signature must be wrapped, not drawn as one line that
	// runs off the page.
	if strings.Contains(got, "("+cert.Signature+") Tj") {
		t.Error("the signature was emitted as one unwrapped line")
	}
	// And it must still be fully present, split across lines.
	if !strings.Contains(strings.ReplaceAll(got, "\\227", ""), cert.Signature[:64]) {
		t.Errorf("the first half of the signature is missing from the PDF")
	}
}

// TestRenderPDFPaginatesLongFindings proves a long certificate does not draw
// past the bottom of the page: the printed copy has to grow pages instead.
func TestRenderPDFPaginatesLongFindings(t *testing.T) {
	a := pdfTestAssessment()
	for i := 0; i < 120; i++ {
		a.Findings = append(a.Findings, certificate.Finding{
			ID:       "F-" + strconv.Itoa(100+i),
			Severity: "medium",
			Title:    "A finding title that is long enough to wrap onto a second line",
			Evidence: "GET /path?parameter=value returned HTTP 200",
		})
	}
	a.Counts = certificate.Counts{Medium: 120}

	got := string(renderPDF(a, nil))
	pages := strings.Count(got, "/Type /Page /Parent")
	if pages < 3 {
		t.Fatalf("120 findings rendered into %d pages; expected the document to paginate", pages)
	}
	// No content stream may hold more lines than an A4 page fits. 48 is
	// certificate's pdfMaxLines: floor((789-60)/15) on 595.28x841.89 pt.
	const linesPerA4 = 48
	for _, stream := range strings.Split(got, "stream\n") {
		if n := strings.Count(stream, " Tj\n"); n > linesPerA4 {
			t.Fatalf("a page holds %d text lines; the page fits %d", n, linesPerA4)
		}
	}
}

// pdfTestCertificate issues a real certificate so the PDF seal can be checked
// end to end: signature, document hash and page-text digest.
func pdfTestCertificate(t *testing.T) (*certificate.Certificate, certificate.Assessment) {
	t.Helper()
	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	a := pdfTestAssessment()
	a.Findings = []certificate.Finding{{
		ID: "F-001", Severity: "medium",
		Title:    "Missing Content-Security-Policy header",
		Evidence: "no CSP on / and /login",
	}}
	a.Counts = certificate.Counts{Medium: 1}
	c, err := certificate.Issue(kp, a, "", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return c, a
}

// TestRenderedPDFVerifiesOnItsOwn proves the printable copy is a certificate,
// not a picture of one: `sift certificate cert.pdf` can answer without the
// JSON, because the signed certificate and a digest of the page text are
// inside the file.
func TestRenderedPDFVerifiesOnItsOwn(t *testing.T) {
	c, a := pdfTestCertificate(t)
	doc := renderPDF(a, c)

	res, err := certificate.VerifyPDF(doc, nil, false)
	if err != nil {
		t.Fatalf("VerifyPDF: %v", err)
	}
	if !res.RenderedMatch {
		t.Fatalf("page digest %s does not match seal %s", res.RenderedSHA256, res.SealRenderedSHA256)
	}
	if res.Certificate == nil || res.Certificate.Signature != c.Signature {
		t.Fatal("the PDF did not carry the certificate it was rendered from")
	}
	if !strings.Contains(string(doc), "/MediaBox [0 0 595.28 841.89]") {
		t.Error("printed certificate is not A4")
	}
}

// TestRenderedPDFDetectsEditedPage: the embedded JSON stays valid, the page is
// changed, and verification must still fail. This is the difference between
// "the evidence is intact" and "this is the page that was sealed".
func TestRenderedPDFDetectsEditedPage(t *testing.T) {
	c, a := pdfTestCertificate(t)
	doc := renderPDF(a, c)

	needle := []byte("Grade: B")
	if !bytes.Contains(doc, needle) {
		t.Fatal("test setup: the grade line is not in the content stream")
	}
	edited := bytes.Replace(doc, needle, []byte("Grade: A"), 1)

	res, err := certificate.VerifyPDF(edited, nil, false)
	if err == nil {
		t.Fatal("an edited printed certificate verified")
	}
	if res == nil || res.RenderedMatch {
		t.Fatalf("edited page reported as matching: %+v", res)
	}
	if !strings.Contains(err.Error(), "does not match the sealed rendering") {
		t.Errorf("unhelpful error: %v", err)
	}
}
