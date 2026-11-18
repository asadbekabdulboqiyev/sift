package certificate

// pdf_certificate.go — the single definition of what a printed certificate says.
//
// # Why this is not in the CLI
//
// The text of a certificate PDF used to be assembled inside cmd/sift, and the
// verifier only compared the page against a digest the PDF carried in its own
// seal. That is circular: whoever can edit the page can also rewrite the seal,
// so the check proved "the page matches the number next to it", not "the page
// is this certificate".
//
// Concretely, the hole was: take a genuinely signed certificate for grade B,
// draw a page that says grade A, compute its digest, put that digest in the
// seal, and leave the embedded certificate untouched. Every signature check
// passed, the page matched the seal, and the printed copy claimed an A that no
// issuer ever signed.
//
// The fix is to make the text a function of the certificate. The verifier
// re-renders the expected pages from the embedded certificate and requires the
// page digest, and the seal, to equal that — not merely to agree with each
// other. So the renderer has to live in this package, where the verifier can
// call it, and both sides have to be the same code.
//
// # Compatibility
//
// The lines below are byte-for-byte the ones the CLI drew before the move, so a
// PDF printed by v0.17.0 still re-renders to the same digest and still verifies.
// Change a string here and you invalidate every printed copy; the golden test in
// pdf_certificate_test.go is there to make that a deliberate act.

import (
	"fmt"
	"strings"
)

// CertificatePDFLines returns the text a certificate PDF draws, in order.
//
// The result depends only on the certificate (plus the two fields the assessment
// may leave for it to fill in), which is what lets a verifier recompute the
// expected pages from the embedded JSON alone.
func CertificatePDFLines(a Assessment, cert *Certificate) []string {
	var certID, validity, signature, publicKey string
	if cert != nil {
		// A caller that only has the assessment can pass cert.Assessment and
		// still get the signed values printed: they are part of the signature,
		// so dropping them would make the page disagree with the seal.
		if strings.TrimSpace(a.DocumentSHA) == "" {
			a.DocumentSHA = cert.Assessment.DocumentSHA
		}
		if strings.TrimSpace(a.SignedAt) == "" {
			a.SignedAt = cert.Assessment.SignedAt
		}
		certID = cert.CertificateID
		validity = cert.ValidityPeriod
		signature = cert.Signature
		publicKey = cert.PublicKey
	}
	total := a.Counts.Critical + a.Counts.High + a.Counts.Medium + a.Counts.Low + a.Counts.Info

	lines := []string{
		"Sift - Security Assessment Certificate (ss-cert/v1)",
		"",
		"Target: " + pdfTextOrDash(a.Target),
		"Grade: " + pdfTextOrDash(a.Grade) + "   Verdict: " + pdfTextOrDash(a.Verdict) + "   Risk: " + fmt.Sprintf("%d", a.RiskScore) + "/100",
		fmt.Sprintf("Findings: %d (critical %d, high %d, medium %d, low %d, info %d)", total, a.Counts.Critical, a.Counts.High, a.Counts.Medium, a.Counts.Low, a.Counts.Info),
		"Scope: " + pdfTextOrDash(a.Scope),
		"Started: " + pdfTextTime(a.Started) + "   Ended: " + pdfTextTime(a.Ended),
		"Duration: " + pdfTextOrDash(a.Duration),
		"Issuer: " + pdfTextOrDash(a.Issuer) + "   Issued: " + pdfTextTime(a.SignedAt),
		"Tool: " + pdfTextOrDash(strings.TrimSpace(a.Tool+" "+a.ToolVersion)),
		"Scanner families: " + pdfTextList(a.Covered),
		"Certificate ID: " + pdfTextOrDash(certID),
		"Validity: " + pdfTextOrDash(validity),
	}

	// The findings and the compliance mapping belong in the printed copy too: a
	// PDF that only carries the header is not a certificate, it is a stub.
	if len(a.Findings) > 0 {
		lines = append(lines, "", "Findings")
		for _, f := range a.Findings {
			lines = append(lines, fmt.Sprintf("[%s] %s - %s (%s)",
				strings.ToUpper(pdfTextOrDash(f.Severity)), pdfTextOrDash(f.Title),
				pdfTextOrDash(f.Evidence), pdfTextOrDash(f.ID)))
		}
	}
	if len(a.Compliance) > 0 {
		lines = append(lines, "", "Compliance mapping")
		for _, c := range a.Compliance {
			lines = append(lines, fmt.Sprintf("[%s] %s %s - %s",
				strings.ToUpper(pdfTextOrDash(c.Status)), pdfTextOrDash(c.Framework),
				pdfTextOrDash(c.ID), pdfTextOrDash(c.Title)))
		}
	}

	lines = append(lines,
		"",
		"Signature (Ed25519, over canonical assessment JSON):",
		pdfTextOrDash(signature),
		"Signer public key:",
		pdfTextOrDash(publicKey),
		"Document SHA-256: "+pdfTextOrDash(a.DocumentSHA),
		"",
		"This document is tamper-evident, not a warranty: it proves that the",
		"assessment above was sealed by the key named here, and that this page",
		"is the one that was sealed. Verify with: sift certificate cert.pdf",
	)
	return lines
}

// ExpectedPDFRenderedSHA256 is the digest a certificate PDF must carry, derived
// from the certificate alone.
//
// It runs the same writer the printer ran — same wrapping, same page breaks,
// same WinAnsi substitution — so the value is not a second implementation that
// can drift from the first.
func ExpectedPDFRenderedSHA256(c *Certificate) string {
	if c == nil {
		return ""
	}
	p := NewPDF()
	for _, line := range CertificatePDFLines(c.Assessment, c) {
		p.Text(line)
	}
	return pdfRenderedDigest(p.layout())
}

// The three helpers below are deliberately ASCII-only and separate from the
// HTML renderer's displayOrDash, which draws an em dash. A certificate printed
// before this package owned the text used "-", and a PDF must keep re-rendering
// to the digest it was sealed with.

func pdfTextTime(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || s == "0001-01-01T00:00:00Z" {
		return "-"
	}
	return s
}

func pdfTextOrDash(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "-"
	}
	return s
}

func pdfTextList(items []string) string {
	if len(items) == 0 {
		return "-"
	}
	return strings.Join(items, ", ")
}
