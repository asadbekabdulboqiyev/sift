package audit360

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	return true, "ok"
}

type sealPayload struct {
	Format               string    `json:"format"`
	TargetURL            string    `json:"target_url"`
	Timestamp            string    `json:"timestamp"`
	ResilienceScore      int       `json:"resilience_score"`
	RiskLevel            string    `json:"risk_level"`
	BreakingPointUsers   int       `json:"breaking_point_users,omitempty"`
	MaxSafeRPS           float64   `json:"max_safe_rps,omitempty"`
	BreakingPointReached bool      `json:"breaking_point_reached"`
	StressTestAvailable  bool      `json:"stress_test_available"`
	SecurityScanPartial  bool      `json:"security_scan_partial,omitempty"`
	Findings             []Finding `json:"findings"`
	Notes                []string  `json:"notes,omitempty"`
	DurationMS           int64     `json:"duration_ms"`
}

func canonicalSealPayload(report *Audit360Report) ([]byte, error) {
	p := sealPayload{
		Format:               "sift.audit360/v1",
		TargetURL:            report.TargetURL,
		Timestamp:            report.Timestamp,
		ResilienceScore:      report.ResilienceScore,
		RiskLevel:            report.RiskLevel,
		BreakingPointUsers:   report.BreakingPointUsers,
		MaxSafeRPS:           report.MaxSafeRPS,
		BreakingPointReached: report.BreakingPointReached,
		StressTestAvailable:  report.StressTestAvailable,
		SecurityScanPartial:  report.SecurityScanPartial,
		Findings:             append([]Finding(nil), report.Findings...),
		Notes:                append([]string(nil), report.Notes...),
		DurationMS:           report.DurationMS,
	}
	// Deterministic enough for this use (struct field order fixed; findings kept in report order).
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
