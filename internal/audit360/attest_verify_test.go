package audit360

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/asadbekabdulboqiyev/sift/internal/attest"
)

// sealedFixture returns a report sealed with a real key, plus that key.
func sealedFixture(t *testing.T) (*Audit360Report, *attest.Keypair) {
	t.Helper()
	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	rep := &Audit360Report{
		TargetURL:       "https://example.test/app",
		Timestamp:       "2026-01-02T03:04:05Z",
		RiskLevel:       "low",
		ResilienceScore: 82,
		DurationMS:      1200,
		Findings: []Finding{{
			Title:    "Verbose error page",
			Severity: "high",
			Evidence: "HTTP 500 body contained /srv/app/main.go",
		}},
	}
	if _, _, _, err := SealWithKey(rep, kp); err != nil {
		t.Fatalf("SealWithKey: %v", err)
	}
	return rep, kp
}

// TestSealWithKeyVerifies is the base contract: a report sealed with a key
// verifies, names that key, and reports the same fingerprint the attestation
// package computes.
func TestSealWithKeyVerifies(t *testing.T) {
	rep, kp := sealedFixture(t)

	if rep.VPMPSignature == "" || rep.CertificateID == "" {
		t.Fatal("seal did not populate signature and certificate id")
	}
	if got := SignerPublicKey(rep); got != attest.PublicKeyHex(kp.Public) {
		t.Fatalf("signer note = %q, want the sealing key", got)
	}

	check, err := VerifyReport(rep, "")
	if err != nil {
		t.Fatalf("VerifyReport: %v", err)
	}
	if !check.Signed {
		t.Fatal("sealed report reported unsigned")
	}
	if check.Fingerprint != attest.Fingerprint(kp.Public) {
		t.Fatalf("fingerprint = %q, want %q", check.Fingerprint, attest.Fingerprint(kp.Public))
	}
	if check.CertificateID != rep.CertificateID {
		t.Fatalf("certificate id = %q, want %q", check.CertificateID, rep.CertificateID)
	}
}

// TestVerifyReportRejectsTamperedField is the reason the seal exists: one
// changed number and the digest no longer matches.
func TestVerifyReportRejectsTamperedField(t *testing.T) {
	rep, _ := sealedFixture(t)
	rep.ResilienceScore = 99

	if _, err := VerifyReport(rep, ""); err == nil {
		t.Fatal("a tampered score must fail verification")
	}
}

// TestVerifyReportRejectsTamperedFinding covers the payload members a reader
// cares about most.
func TestVerifyReportRejectsTamperedFinding(t *testing.T) {
	rep, _ := sealedFixture(t)
	rep.Findings[0].Severity = "info"

	if _, err := VerifyReport(rep, ""); err == nil {
		t.Fatal("a tampered finding must fail verification")
	}
}

// TestVerifyReportRejectsTamperedNote covers the notes, which carry the signer
// key: editing them must not be a way to swap identity.
func TestVerifyReportRejectsTamperedNote(t *testing.T) {
	rep, _ := sealedFixture(t)
	other, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	for i, n := range rep.Notes {
		if strings.HasPrefix(n, SignerNotePrefix) {
			rep.Notes[i] = SignerNotePrefix + attest.PublicKeyHex(other.Public)
		}
	}

	if _, err := VerifyReport(rep, ""); err == nil {
		t.Fatal("a swapped signer note must fail verification")
	}
}

// TestVerifyReportPinnedKey is the attribution half: the same intact report
// passes with its own key pinned and fails with any other.
func TestVerifyReportPinnedKey(t *testing.T) {
	rep, kp := sealedFixture(t)

	check, err := VerifyReport(rep, attest.PublicKeyHex(kp.Public))
	if err != nil {
		t.Fatalf("VerifyReport with the right key: %v", err)
	}
	if !check.Signed {
		t.Fatal("pinned verification reported unsigned")
	}

	other, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	if _, err := VerifyReport(rep, attest.PublicKeyHex(other.Public)); err == nil {
		t.Fatal("a pinned key that did not sign the report must fail")
	}
}

// TestVerifyReportUnsigned makes the "no key, no claim" rule explicit: a report
// with no seal is invalid, not vacuously valid.
func TestVerifyReportUnsigned(t *testing.T) {
	rep := &Audit360Report{TargetURL: "https://example.test", Timestamp: "2026-01-02T03:04:05Z"}

	check, err := VerifyReport(rep, "")
	if err == nil {
		t.Fatal("an unsigned report must not verify")
	}
	if check == nil || check.Signed {
		t.Fatal("unsigned report reported signed")
	}
	if !strings.Contains(err.Error(), "signature") && !strings.Contains(err.Error(), "key") {
		t.Fatalf("error should say what is missing, got %v", err)
	}
}

// TestVerifyReportNil covers the guard.
func TestVerifyReportNil(t *testing.T) {
	if _, err := VerifyReport(nil, ""); err == nil {
		t.Fatal("nil report must fail")
	}
}

// TestSealWithKeyRejectsNilKey keeps the "no key, no seal" rule on the writer
// side too.
func TestSealWithKeyRejectsNilKey(t *testing.T) {
	rep := &Audit360Report{TargetURL: "https://example.test"}
	if _, _, _, err := SealWithKey(rep, nil); err == nil {
		t.Fatal("SealWithKey(nil key) must fail")
	}
	if rep.VPMPSignature != "" {
		t.Fatal("a failed seal must not leave a signature behind")
	}
}

// TestSignerPublicKeyNil covers the helper on the empty path.
func TestSignerPublicKeyNil(t *testing.T) {
	if got := SignerPublicKey(nil); got != "" {
		t.Fatalf("SignerPublicKey(nil) = %q, want empty", got)
	}
}

// TestVerifyReportAcceptsLegacyEphemeralSeal guards the reports already handed
// out. Before a persistent identity existed, the orchestrator sealed inline with
// a per-run key: append the signer note, canonicalize, sign. The bytes on disk
// are identical to what SealWithKey produces, so a verifier that rejected them
// would invalidate every report already issued.
func TestVerifyReportAcceptsLegacyEphemeralSeal(t *testing.T) {
	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	rep := &Audit360Report{
		TargetURL:       "https://legacy.example.test",
		Timestamp:       "2026-05-01T00:00:00Z",
		RiskLevel:       "medium",
		ResilienceScore: 61,
		DurationMS:      5000,
	}
	// The pre-persistent-key sealing path, reproduced verbatim.
	pubHex := attest.PublicKeyHex(kp.Public)
	rep.Notes = append(rep.Notes, "VPMP signer public key (hex): "+pubHex)
	payload, err := canonicalSealPayload(rep)
	if err != nil {
		t.Fatalf("canonicalSealPayload: %v", err)
	}
	digest := sha256.Sum256(payload)
	rep.CertificateID = hex.EncodeToString(digest[:16])
	sig, err := attest.Sign(kp, digest[:])
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	rep.VPMPSignature = hex.EncodeToString(sig)

	check, err := VerifyReport(rep, pubHex)
	if err != nil {
		t.Fatalf("a report sealed before persistent keys must still verify: %v", err)
	}
	if !check.Signed {
		t.Fatal("legacy report reported unsigned")
	}
	if check.CertificateID != rep.CertificateID {
		t.Fatalf("certificate id = %q, want %q", check.CertificateID, rep.CertificateID)
	}
}
