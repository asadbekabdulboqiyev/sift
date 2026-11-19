package certificate

// v2_test.go — ss-cert/v2 signs the envelope and binds the rendered seal.
//
// v1 signed the assessment only. The validity period, the previous-certificate
// link, the source reference and the envelope signing time sat outside the
// signature, and Verify never compared the stored page with the page the
// certificate renders. So a holder could:
//
//   - change validity to "36500 days (no expiry)", recompute the derived
//     certificate id, and still get a valid certificate and a valid PDF; and
//   - edit the seal block (issuer, key fingerprint, sealed time, validity)
//     without touching the document hash, because the seal is excluded from it.
//
// These tests pin the v2 rules and the v1 compatibility guarantee.

import (
	"strings"
	"testing"

	"github.com/asadbekabdulboqiyev/sift/internal/attest"
)

// TestIssueProducesV2 pins that the shared issuance path — the one both the CLI
// and the dashboard call — emits v2, so the stronger rules apply to everything
// this build issues.
func TestIssueProducesV2(t *testing.T) {
	c := issueValid(t)
	if c.Version != VersionV2 {
		t.Fatalf("version = %q, want %q", c.Version, VersionV2)
	}
	if err := Verify(c); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// TestVerifyRejectsTamperedValidityPeriod is the H-2 regression: validity is a
// signed field in v2, so changing it fails even when the derived certificate id
// is recomputed (which is what made v1 accept it).
func TestVerifyRejectsTamperedValidityPeriod(t *testing.T) {
	c := issueValid(t)

	tampered := *c
	tampered.ValidityPeriod = "36500 days (no expiry)"
	tampered.CertificateID = CertificateID(&tampered)
	// The attacker re-renders the page from the edited certificate, so only the
	// signature over the envelope can catch this.
	tampered.HTML = HTML(&tampered)

	if err := Verify(&tampered); err == nil {
		t.Fatal("a certificate with a rewritten validity period verified")
	}
}

// TestVerifyRejectsTamperedPreviousHash covers the hash chain: a holder must
// not be able to re-point the previous-certificate link.
func TestVerifyRejectsTamperedPreviousHash(t *testing.T) {
	c := issueValid(t)

	tampered := *c
	tampered.PreviousCertificateHash = strings.Repeat("b", 64)
	tampered.CertificateID = CertificateID(&tampered)
	tampered.HTML = HTML(&tampered)

	if err := Verify(&tampered); err == nil {
		t.Fatal("a certificate with a rewritten previous-certificate hash verified")
	}
}

// TestVerifyRejectsTamperedExperimentReference covers the provenance field.
func TestVerifyRejectsTamperedExperimentReference(t *testing.T) {
	c := issueValid(t)

	tampered := *c
	tampered.ExperimentReference = "some-other-run"
	tampered.CertificateID = CertificateID(&tampered)
	tampered.HTML = HTML(&tampered)

	if err := Verify(&tampered); err == nil {
		t.Fatal("a certificate with a rewritten experiment reference verified")
	}
}

// TestVerifyRejectsEnvelopeSignedAtMismatch covers the v2 rule that the seal's
// signing time and the assessment's signing time are the same fact, not two
// values a holder may set independently.
func TestVerifyRejectsEnvelopeSignedAtMismatch(t *testing.T) {
	c := issueValid(t)

	tampered := *c
	tampered.SignedAt = "2027-01-01T00:00:00Z"
	tampered.CertificateID = CertificateID(&tampered)

	if err := Verify(&tampered); err == nil {
		t.Fatal("a certificate whose seal and assessment name different signing times verified")
	}
}

// TestVerifyRejectsTamperedAssessmentSignedAt moves the signing time everywhere
// (assessment and envelope, page re-rendered, id recomputed) so no consistency
// rule can be what rejects it: the signed document hash and the signature must.
func TestVerifyRejectsTamperedAssessmentSignedAt(t *testing.T) {
	c := issueValid(t)

	tampered := *c
	tampered.SignedAt = "2027-01-01T00:00:00Z"
	tampered.Assessment.SignedAt = "2027-01-01T00:00:00Z"
	tampered.CertificateID = CertificateID(&tampered)
	tampered.HTML = HTML(&tampered)

	if err := Verify(&tampered); err == nil {
		t.Fatal("a certificate with a rewritten signing time verified")
	}
}

// TestVerifyRejectsTamperedSealFingerprint is the H-1 regression for the most
// misleading seal edit: replacing the key fingerprint makes the page name a
// different signer. The document hash cannot see it (the seal is excluded), so
// only the v2 rendered-page check catches it.
func TestVerifyRejectsTamperedSealFingerprint(t *testing.T) {
	c := issueValid(t)

	fingerprint := groupHex(c.PublicKey, 4)
	if !strings.Contains(c.HTML, fingerprint) {
		t.Fatalf("test precondition: seal does not display the fingerprint")
	}
	first := strings.SplitN(fingerprint, " ", 2)[0]
	replacement := "0000"
	if first == replacement {
		replacement = "1111"
	}

	tampered := *c
	tampered.HTML = strings.Replace(tampered.HTML, fingerprint, replacement+strings.TrimPrefix(fingerprint, first), 1)

	if tampered.HTML == c.HTML {
		t.Fatal("test precondition: seal fingerprint was not replaced")
	}
	// The document hash still matches: the seal block is outside it.
	if got := documentSHA(tampered.HTML); got != tampered.Assessment.DocumentSHA {
		t.Fatalf("test precondition: document hash changed (got %s, want %s)", got, tampered.Assessment.DocumentSHA)
	}
	if err := Verify(&tampered); err == nil {
		t.Fatal("a certificate whose seal names a different key fingerprint verified")
	}
}

// TestVerifyRejectsTamperedSealIssuer covers the seal's issuer line, the value
// a reader trusts first.
func TestVerifyRejectsTamperedSealIssuer(t *testing.T) {
	c := issueValid(t)

	sealAt := strings.Index(c.HTML, `<div class="seal">`)
	if sealAt < 0 {
		t.Fatal("test precondition: no seal block")
	}
	seal := c.HTML[sealAt:]
	if !strings.Contains(seal, "QA Lead") {
		t.Fatalf("test precondition: seal does not display the issuer")
	}

	tampered := *c
	// Replace only inside the seal block: the issuer also appears in the body,
	// and an edit there is already caught by the document hash.
	tampered.HTML = c.HTML[:sealAt] + strings.Replace(seal, "QA Lead", "Someone Else", 1)
	if tampered.HTML == c.HTML {
		t.Fatal("test precondition: seal issuer was not replaced")
	}
	if got := documentSHA(tampered.HTML); got != tampered.Assessment.DocumentSHA {
		t.Fatalf("test precondition: document hash changed (got %s, want %s)", got, tampered.Assessment.DocumentSHA)
	}
	if err := Verify(&tampered); err == nil {
		t.Fatal("a certificate whose seal names a different issuer verified")
	}
}

// TestVerifyRejectsTamperedSealValidityDisplay covers the validity shown in the
// seal footnote: changing only what is displayed, not the signed field.
func TestVerifyRejectsTamperedSealValidityDisplay(t *testing.T) {
	c := issueValid(t)
	if !strings.Contains(c.HTML, validityPeriod) {
		t.Fatalf("test precondition: seal does not display the validity period")
	}

	tampered := *c
	tampered.HTML = strings.Replace(c.HTML, validityPeriod, "36500 days (no expiry)", 1)
	if got := documentSHA(tampered.HTML); got != tampered.Assessment.DocumentSHA {
		t.Fatalf("test precondition: document hash changed (got %s, want %s)", got, tampered.Assessment.DocumentSHA)
	}
	if err := Verify(&tampered); err == nil {
		t.Fatal("a certificate whose seal displays a different validity verified")
	}
}

// TestVerifyStillAcceptsV1 pins the compatibility guarantee: a certificate
// issued before v2 — signed over the assessment only, envelope filled in
// afterwards — must keep verifying, because the v2 rules cannot be applied
// retroactively.
func TestVerifyStillAcceptsV1(t *testing.T) {
	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	a := validAssessment()
	bound := RenderHTML(a, "SIGNATURE_PLACEHOLDER", "KEY_PLACEHOLDER", a.SignedAt, Version)
	c, err := Sign(kp, a, bound)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// What the v1 Issue path did after signing.
	c.PreviousCertificateHash = strings.Repeat("a", 64)
	c.ExperimentReference = "exp-ref"
	c.ValidityPeriod = validityPeriod
	c.CertificateID = CertificateID(c)
	c.HTML = HTML(c)

	if c.Version != Version {
		t.Fatalf("version = %q, want %q", c.Version, Version)
	}
	if err := Verify(c); err != nil {
		t.Fatalf("a v1 certificate must keep verifying: %v", err)
	}
}

// TestV1EnvelopeRemainsOutsideTheSignature documents the known v1 limitation
// rather than pretending it was fixed: old certificates are accepted as they
// were issued, but the envelope is still editable. Everything this build issues
// is v2, where TestVerifyRejectsTamperedValidityPeriod applies.
func TestV1EnvelopeRemainsOutsideTheSignature(t *testing.T) {
	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	a := validAssessment()
	c, err := Sign(kp, a, RenderHTML(a, "SIGNATURE_PLACEHOLDER", "KEY_PLACEHOLDER", a.SignedAt, Version))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	c.PreviousCertificateHash = strings.Repeat("a", 64)
	c.ExperimentReference = "exp-ref"
	c.ValidityPeriod = validityPeriod
	c.CertificateID = CertificateID(c)
	c.HTML = HTML(c)

	legacy := *c
	legacy.ValidityPeriod = "36500 days (no expiry)"
	legacy.CertificateID = CertificateID(&legacy)
	legacy.HTML = HTML(&legacy)

	if err := Verify(&legacy); err != nil {
		t.Fatalf("v1 compatibility broke: %v", err)
	}
}

// TestPDFLinesNameTheSealFormat pins that a printed page names the format its
// seal actually uses. A v2 certificate must not print "ss-cert/v1": the reader
// would be told the weaker contract applies to a page that carries the stronger
// one. A v1 certificate keeps the original wording so copies already handed out
// re-render to the same bytes.
func TestPDFLinesNameTheSealFormat(t *testing.T) {
	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	a := validAssessment()

	v2, err := Issue(kp, a, "", "exp-pdf")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if got, want := PDFLines(v2.Assessment, v2)[0], "Sift - Security Assessment Certificate (ss-cert/v2)"; got != want {
		t.Errorf("v2 title = %q, want %q", got, want)
	}

	v1, err := Sign(kp, a, RenderHTML(a, "SIGNATURE_PLACEHOLDER", "KEY_PLACEHOLDER", a.SignedAt, Version))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	v1.CertificateID = CertificateID(v1)
	v1.HTML = HTML(v1)
	if got, want := PDFLines(v1.Assessment, v1)[0], "Sift - Security Assessment Certificate (ss-cert/v1)"; got != want {
		t.Errorf("v1 title = %q, want %q", got, want)
	}

	// No certificate at all is the pre-v2 shape the golden fixture uses.
	if got, want := PDFLines(a, nil)[0], "Sift - Security Assessment Certificate (ss-cert/v1)"; got != want {
		t.Errorf("nil-cert title = %q, want %q", got, want)
	}
}
