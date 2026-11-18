package certificate

// trust_test.go — the identity half of certificate verification.
//
// Verify answers "is this document self-consistent?". These tests cover the
// separate question VerifyWithTrust answers: "was it issued by a key I accept?".
// The load-bearing case is TestVerifyWithTrustRejectsForeignSigner: a
// certificate that passes every existing check must still be refused when its
// signer is not pinned.

import (
	"strings"
	"testing"

	"github.com/asadbekabdulboqiyev/sift/internal/attest"
)

// issueWithKey seals the shared valid assessment with a caller-supplied key, so
// a test can produce two certificates that differ only in their signer.
func issueWithKey(t *testing.T, kp *attest.Keypair) *Certificate {
	t.Helper()
	c, err := Issue(kp, validAssessment(), strings.Repeat("a", 64), "exp-ref")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return c
}

func TestVerifyWithTrustPinnedSigner(t *testing.T) {
	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	c := issueWithKey(t, kp)

	store := attest.NewTrustStore()
	if err := store.Add(kp.Public, "TechCorp"); err != nil {
		t.Fatalf("Add: %v", err)
	}

	check, err := VerifyWithTrust(c, store, true)
	if err != nil {
		t.Fatalf("pinned certificate rejected: %v", err)
	}
	if check.Status != attest.IssuerPinned {
		t.Fatalf("Status = %q, want pinned", check.Status)
	}
	if !check.Trusted() {
		t.Fatal("a pinned signer must report Trusted()")
	}
	if check.Label != "TechCorp" {
		t.Fatalf("Label = %q, want TechCorp", check.Label)
	}
	if check.Fingerprint() != attest.FingerprintHex(c.PublicKey) {
		t.Fatal("Fingerprint does not match the signer key")
	}
}

func TestVerifyWithTrustRejectsForeignSigner(t *testing.T) {
	school, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	forger, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	// The forged certificate is perfect in every existing sense: signature,
	// document hash, id, timing all check out.
	c := issueWithKey(t, forger)
	if err := Verify(c); err != nil {
		t.Fatalf("forged certificate is not self-consistent, so the test proves nothing: %v", err)
	}

	store := attest.NewTrustStore()
	if err := store.Add(school.Public, "School #12"); err != nil {
		t.Fatalf("Add: %v", err)
	}

	check, err := VerifyWithTrust(c, store, false)
	if err == nil {
		t.Fatal("a certificate from an unknown signer was accepted")
	}
	if check.Status != attest.IssuerUntrusted {
		t.Fatalf("Status = %q, want untrusted", check.Status)
	}
	if check.Trusted() {
		t.Fatal("an untrusted signer reported Trusted()")
	}
	if !strings.Contains(err.Error(), "not in the trust store") {
		t.Fatalf("error does not explain the trust failure: %v", err)
	}
}

func TestVerifyWithTrustUnpinnedWithoutStore(t *testing.T) {
	c := issueValid(t)

	check, err := VerifyWithTrust(c, nil, false)
	if err != nil {
		t.Fatalf("historical behaviour broke: %v", err)
	}
	if check.Status != attest.IssuerUnpinned {
		t.Fatalf("Status = %q, want unpinned", check.Status)
	}
	if check.Trusted() {
		t.Fatal("an unpinned signer reported Trusted()")
	}
	if check.Key == "" {
		t.Fatal("the claimed signer key was not echoed")
	}
}

func TestVerifyWithTrustRequireAnchorWithoutStore(t *testing.T) {
	c := issueValid(t)

	check, err := VerifyWithTrust(c, nil, true)
	if err == nil {
		t.Fatal("RequireTrustAnchor was set but no anchor was required")
	}
	if check.Status != attest.IssuerUnpinned {
		t.Fatalf("Status = %q, want unpinned", check.Status)
	}
}

func TestVerifyWithTrustEmptyStoreRejectsEverything(t *testing.T) {
	c := issueValid(t)

	check, err := VerifyWithTrust(c, attest.NewTrustStore(), false)
	if err == nil {
		t.Fatal("an empty trust store accepted a certificate")
	}
	if check.Status != attest.IssuerUntrusted {
		t.Fatalf("Status = %q, want untrusted", check.Status)
	}
}

func TestVerifyWithTrustTamperedCertificateStaysInvalid(t *testing.T) {
	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	c := issueWithKey(t, kp)
	store := attest.NewTrustStore()
	if err := store.Add(kp.Public, "TechCorp"); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Pin the right signer but alter the assessment: the signature check must
	// still fail, so trust never papers over tampering.
	c.Assessment.RiskScore = 0
	check, err := VerifyWithTrust(c, store, true)
	if err == nil {
		t.Fatal("a tampered certificate passed because its signer was pinned")
	}
	if check.Status != attest.IssuerPinned {
		t.Fatalf("Status = %q: the identity should still be reported", check.Status)
	}
}

func TestVerifyWithTrustMissingSignerKey(t *testing.T) {
	c := issueValid(t)
	c.PublicKey = ""

	check, err := VerifyWithTrust(c, nil, false)
	if err == nil {
		t.Fatal("a certificate with no signer key was accepted")
	}
	if check.Status != attest.IssuerMissing {
		t.Fatalf("Status = %q, want missing", check.Status)
	}
}

func TestVerifyBytesWithTrustRoundTrip(t *testing.T) {
	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	c := issueWithKey(t, kp)
	raw, err := c.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}

	store := attest.NewTrustStore()
	if err := store.Add(kp.Public, "TechCorp"); err != nil {
		t.Fatalf("Add: %v", err)
	}

	got, check, err := VerifyBytesWithTrust(raw, store, true)
	if err != nil {
		t.Fatalf("VerifyBytesWithTrust: %v", err)
	}
	if got.CertificateID != c.CertificateID {
		t.Fatalf("certificate id = %q, want %q", got.CertificateID, c.CertificateID)
	}
	if !check.Trusted() {
		t.Fatalf("Status = %q, want pinned", check.Status)
	}

	// And the old entry point keeps its behaviour: valid, no identity claim.
	if _, err := VerifyBytes(raw); err != nil {
		t.Fatalf("VerifyBytes broke for a valid certificate: %v", err)
	}
}
