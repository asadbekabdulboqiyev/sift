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

// TestVerifyStillAcceptsV1 pins the compatibility guarantee for the shape v1
// itself produced: a bare certificate signed over the assessment only, with no
// unverifiable envelope claims, must keep verifying. The v2 rules cannot be
// applied retroactively to that signed payload.
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
	c.CertificateID = CertificateID(c)

	if c.Version != Version {
		t.Fatalf("version = %q, want %q", c.Version, Version)
	}
	if err := Verify(c); err != nil {
		t.Fatalf("a bare v1 certificate must keep verifying: %v", err)
	}
}

// TestV1RejectsUnverifiableEnvelope is the CWE-347 regression: v1 did not sign
// the envelope, so a holder could rewrite validity, the chain link or the source
// reference and recompute the derived id. A v1 certificate that asserts those
// fields must now be refused and re-issued as v2; recomputing CertificateID no
// longer launders the edit.
func TestV1RejectsUnverifiableEnvelope(t *testing.T) {
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

	if err := Verify(c); err == nil {
		t.Fatal("a v1 certificate with unsigned envelope claims verified")
	}

	for _, tc := range []struct {
		name   string
		mutate func(*Certificate)
	}{
		{"validity", func(c *Certificate) { c.ValidityPeriod = "36500 days (no expiry)" }},
		{"previous hash", func(c *Certificate) { c.PreviousCertificateHash = strings.Repeat("b", 64) }},
		{"reference", func(c *Certificate) { c.ExperimentReference = "some-other-run" }},
		{"signed_at", func(c *Certificate) { c.SignedAt = "2027-01-01T00:00:00Z" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tampered := *c
			tc.mutate(&tampered)
			tampered.CertificateID = CertificateID(&tampered) // recomputing the id must not help
			tampered.HTML = HTML(&tampered)
			if err := Verify(&tampered); err == nil {
				t.Fatal("tampered v1 envelope verified")
			}
		})
	}
}

// TestSignedCertificateIDExcludesUnsignedV1Fields pins the derivation used by
// the v1 guard: envelope-only edits must leave the signed id unchanged.
func TestSignedCertificateIDExcludesUnsignedV1Fields(t *testing.T) {
	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	v1, err := Sign(kp, validAssessment(), "")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	base := signedCertificateID(v1)
	v1.ValidityPeriod = "36500 days (no expiry)"
	v1.PreviousCertificateHash = strings.Repeat("c", 64)
	v1.ExperimentReference = "other"
	if got := signedCertificateID(v1); got != base {
		t.Fatalf("v1 signed id changed with unsigned envelope fields: %q -> %q", base, got)
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

// TestSealNamesTheVerifierForItsOwnFormat pins the instruction printed on the
// seal. It used to tell the reader to run `python3 sift_verify.py`, which
// verifies vpmp/v1 evidence bundles and rejects a certificate file — so a
// reader following the document's own instructions got an error instead of an
// answer. The seal must name the command that accepts what it is printed on.
func TestSealNamesTheVerifierForItsOwnFormat(t *testing.T) {
	c := issueValid(t)

	if !strings.Contains(c.HTML, "sift certificate cert.json") {
		t.Error("seal does not name `sift certificate cert.json`")
	}
	if strings.Contains(c.HTML, "sift_verify.py") {
		t.Error("seal points at sift_verify.py, which does not accept a certificate")
	}
}
