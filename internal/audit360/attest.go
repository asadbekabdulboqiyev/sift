package audit360

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/attest"
)

// Seal signs the audit report using VPMP v1-compatible attestation primitives
// (Ed25519 signature over a canonical SHA-256 digest of the report payload).
// It returns (certificate_id, vpmp_signature, signer_public_key_hex, error).
// No metrics are fabricated; sealing only attests to the provided report content.
func Seal(report *Audit360Report) (certID, signature, pubHex string, err error) {
	if report == nil {
		return "", "", "", fmt.Errorf("audit360: cannot seal nil report")
	}

	// Fresh keypair per seal (self-contained attestation artifact). If key
	// generation fails, fall back to a random certificate id without claiming a
	// cryptographic signature.
	kp, kerr := attest.GenerateKeypair()
	if kerr != nil || kp == nil || len(kp.Private) != ed25519.PrivateKeySize {
		certID = randomIDFallback()
		return certID, "", "", fmt.Errorf("audit360: signing key unavailable: %w", kerr)
	}

	payload, err := canonicalSealPayload(report)
	if err != nil {
		certID = randomIDFallback()
		return certID, "", "", err
	}
	digest := sha256.Sum256(payload)
	certID = hex.EncodeToString(digest[:16]) // 128-bit stable certificate identifier

	sig, err := attest.Sign(kp, digest[:])
	if err != nil {
		return certID, "", attest.PublicKeyHex(kp.Public), fmt.Errorf("audit360: sign failed: %w", err)
	}
	signature = hex.EncodeToString(sig)
	pubHex = attest.PublicKeyHex(kp.Public)

	// Store digest-binding metadata into signature envelope string form is kept
	// simple for API compatibility; full verification can recompute digest from
	// canonical payload if exposed later.
	_ = payload
	return certID, signature, pubHex, nil
}

// SignerNotePrefix is the note prefix that records the signer's public key
// inside the report body. It is part of the sealed payload, so the key a
// verifier reads is the key the signature was made with.
const SignerNotePrefix = "VPMP signer public key (hex): "

// SealWithKey seals the report in place with kp.
//
// The signer's public key is appended to the notes before the payload is
// canonicalized, so the key is covered by the signature it is used to check.
// That is what makes verification self-contained; it is also why the key alone
// proves nothing about identity — pin it out of band (see VerifyReport).
//
// Call it once per report: a second call appends a second note and re-signs the
// changed payload.
func SealWithKey(report *Audit360Report, kp *attest.Keypair) (certID, signature, pubHex string, err error) {
	if report == nil {
		return "", "", "", fmt.Errorf("audit360: cannot seal nil report")
	}
	if kp == nil || len(kp.Private) != ed25519.PrivateKeySize {
		return "", "", "", fmt.Errorf("audit360: sealing requires a valid Ed25519 private key")
	}

	pubHex = attest.PublicKeyHex(kp.Public)
	report.Notes = append(report.Notes, SignerNotePrefix+pubHex)

	payload, err := canonicalSealPayload(report)
	if err != nil {
		return "", "", pubHex, err
	}
	digest := sha256.Sum256(payload)
	certID = hex.EncodeToString(digest[:16])

	sig, err := attest.Sign(kp, digest[:])
	if err != nil {
		return certID, "", pubHex, fmt.Errorf("audit360: sign failed: %w", err)
	}
	signature = hex.EncodeToString(sig)
	report.CertificateID = certID
	report.VPMPSignature = signature
	return certID, signature, pubHex, nil
}

// VerifySeal verifies a VPMP-style Ed25519 signature over the canonical report
// digest. Returns (valid, reason). Useful for tests and future verification APIs.
func VerifySeal(report *Audit360Report, signatureHex, pubKeyHex string) (bool, string) {
	if report == nil {
		return false, "nil report"
	}
	if signatureHex == "" || pubKeyHex == "" {
		return false, "signature or public key missing"
	}
	pub, err := attest.ParsePublicKeyHex(pubKeyHex)
	if err != nil {
		return false, "invalid public key: " + err.Error()
	}
	sig, err := hex.DecodeString(signatureHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false, "invalid signature encoding"
	}
	payload, err := canonicalSealPayload(report)
	if err != nil {
		return false, "cannot canonicalize report: " + err.Error()
	}
	digest := sha256.Sum256(payload)
	if !ed25519.Verify(pub, digest[:], sig) {
		return false, "signature verification failed"
	}
	// The certificate id is not covered by the signature itself: it is derived
	// from the sealed payload digest, so verification recomputes it and requires
	// an exact match. Skipping the check when the field was blank (or the old
	// "unavailable" display sentinel) let anyone strip the id from an otherwise
	// valid report and still get Signed=true.
	expected := hex.EncodeToString(digest[:16])
	if report.CertificateID != expected {
		return false, "certificate id does not match sealed payload digest"
	}
	return true, "ok"
}

// SealCheck is the outcome of checking a sealed 360° report.
type SealCheck struct {
	// Signed is true when the signature verifies against the key the report
	// names in its notes and the certificate id matches the sealed payload.
	Signed bool
	// SignerKey is the hex public key the report claims signed it, and
	// Fingerprint the same key rendered for out-of-band comparison.
	SignerKey   string
	Fingerprint string
	// CertificateID is the 128-bit id derived from the sealed payload digest.
	CertificateID string
	// Reason explains a failed check.
	Reason string
}

// SignerPublicKey returns the public key the report's notes claim signed it.
//
// The key lives inside the signed payload, so a verifier that only reads it can
// prove "this file is internally consistent" — never "this came from Sift". Use
// VerifyReport with a pinned key for the latter.
func SignerPublicKey(r *Audit360Report) string {
	if r == nil {
		return ""
	}
	return extractSignerPublicKey(r.Notes)
}

// VerifyReport checks a sealed 360° report.
//
// pinnedPubKeyHex, when non-empty, requires the seal to be attributable to that
// exact key; otherwise the check answers only whether the file is intact. A
// report whose notes carry no key is treated as unsigned, not as valid.
func VerifyReport(r *Audit360Report, pinnedPubKeyHex string) (*SealCheck, error) {
	if r == nil {
		return nil, fmt.Errorf("audit360: nil report")
	}
	claimed := SignerPublicKey(r)
	out := &SealCheck{
		SignerKey:     claimed,
		CertificateID: r.CertificateID,
	}
	if pub, err := attest.ParsePublicKeyHex(claimed); err == nil {
		out.Fingerprint = attest.Fingerprint(pub)
	}

	ok, reason := VerifySeal(r, r.VPMPSignature, claimed)
	out.Signed = ok
	out.Reason = reason
	if !ok {
		return out, fmt.Errorf("audit360: seal invalid: %s", reason)
	}

	if pinned := strings.TrimSpace(pinnedPubKeyHex); pinned != "" && !strings.EqualFold(pinned, claimed) {
		return out, fmt.Errorf("audit360: signer key %s does not match the pinned key", shortKey(claimed))
	}
	return out, nil
}

func shortKey(hexKey string) string {
	hexKey = strings.TrimSpace(hexKey)
	if len(hexKey) <= 16 {
		return hexKey
	}
	return hexKey[:16] + "..."
}

type sealPayload struct {
	Format               string    `json:"format"`
	TargetURL            string    `json:"target_url"`
	Timestamp            string    `json:"timestamp"`
	ResilienceScore      int       `json:"resilience_score"` // overall (backward compatibility)
	RiskLevel            string    `json:"risk_level"`
	BreakingPointUsers   int       `json:"breaking_point_users,omitempty"`
	MaxSafeRPS           float64   `json:"max_safe_rps,omitempty"`
	MaxObservedRPS       float64   `json:"max_observed_rps,omitempty"`
	MaxObservedUsers     int       `json:"max_observed_users,omitempty"`
	BreakingPointReached bool      `json:"breaking_point_reached"`
	StressTestAvailable  bool      `json:"stress_test_available"`
	SecurityScanPartial  bool      `json:"security_scan_partial,omitempty"`
	CapacityBlocked      bool      `json:"capacity_blocked,omitempty"`
	BlockedStatus        int       `json:"blocked_status,omitempty"`
	BlockedSharePct      float64   `json:"blocked_share_pct,omitempty"`
	LoadTestSkipped      bool      `json:"load_test_skipped,omitempty"`
	Findings             []Finding `json:"findings"`
	Notes                []string  `json:"notes,omitempty"`
	DurationMS           int64     `json:"duration_ms"`
	// Additive integrity fields.
	ScoringVersion    string             `json:"scoring_version,omitempty"`
	Scores            *ScoreBreakdown    `json:"scores,omitempty"`
	TestConfiguration *TestConfiguration `json:"test_configuration,omitempty"`
	RawEvidenceHash   string             `json:"raw_evidence_hash,omitempty"`
	RawEvidenceFormat string             `json:"raw_evidence_format,omitempty"`
}

func canonicalSealPayload(report *Audit360Report) ([]byte, error) {
	p := sealPayload{
		Format:               "sift.audit360/v2",
		TargetURL:            report.TargetURL,
		Timestamp:            report.Timestamp,
		ResilienceScore:      report.ResilienceScore,
		RiskLevel:            report.RiskLevel,
		BreakingPointUsers:   report.BreakingPointUsers,
		MaxSafeRPS:           report.MaxSafeRPS,
		MaxObservedRPS:       report.MaxObservedRPS,
		MaxObservedUsers:     report.MaxObservedUsers,
		BreakingPointReached: report.BreakingPointReached,
		StressTestAvailable:  report.StressTestAvailable,
		SecurityScanPartial:  report.SecurityScanPartial,
		CapacityBlocked:      report.CapacityBlocked,
		BlockedStatus:        report.BlockedStatus,
		BlockedSharePct:      report.BlockedSharePct,
		LoadTestSkipped:      report.LoadTestSkipped,
		Findings:             append([]Finding(nil), report.Findings...),
		Notes:                append([]string(nil), report.Notes...),
		DurationMS:           report.DurationMS,
		ScoringVersion:       report.ScoringVersion,
		Scores:               report.Scores,
		TestConfiguration:    report.TestConfiguration,
		RawEvidenceHash:      report.RawEvidenceHash,
		RawEvidenceFormat:    report.RawEvidenceFormat,
	}
	// Deterministic for this use (struct field order fixed; findings/notes preserved in report order).
	b, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("audit360: marshal seal payload: %w", err)
	}
	return b, nil
}

func randomIDFallback() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("cert-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
