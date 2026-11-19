// Package certificate issues and verifies signed assessment certificates.
//
// A certificate is an English, self-contained attestation that a Sift
// security assessment ran against a target, what it found, and its overall
// grade/verdict. It is sealed with an Ed25519 signature over the canonical
// assessment JSON, and the signer's public key travels inside the certificate
// so anyone can verify it with this tool alone — no external service, no
// network, no shared secret.
//
// Cryptographic boundary: the signature covers the assessment JSON, which now
// includes DocumentSHA256 — the SHA-256 of the rendered certificate document
// body (the signature seal block is excluded). Thus both the assessment data
// AND its rendered presentation are cryptographically tamper-evident.
//
// Format: ss-cert/v1 and ss-cert/v2 (v2 also signs the envelope and binds
// the rendered seal; v1 certificates keep verifying as issued).
package certificate

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/attest"
	"github.com/asadbekabdulboqiyev/sift/internal/finding"
)

// Version is the original ss-cert envelope format. This build issues VersionV2;
// v1 certificates are still accepted so documents already issued keep verifying.
const Version = "ss-cert/v1"

// VersionV2 signs the envelope as well as the assessment: validity, chain link,
// source reference, envelope signing time and signer key are covered by the
// signature, and the rendered seal must match the signed values exactly.
const VersionV2 = "ss-cert/v2"

// Finding is one assessed defect.
type Finding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"` // critical, high, medium, low, info
	Title    string `json:"title"`
	Evidence string `json:"evidence,omitempty"`
}

// Canonical converts a certificate finding into the shared model. Only the
// fields this legacy shape carries are set; canonical-only fields stay at
// their zero values. The signed assessment payload keeps its exact JSON form.
func (f Finding) Canonical() finding.Finding {
	return finding.Finding{
		ID:       f.ID,
		Severity: f.Severity,
		Title:    f.Title,
		Evidence: f.Evidence,
	}
}

// ToCanonical is the function form of Finding.Canonical.
func ToCanonical(f Finding) finding.Finding { return f.Canonical() }

// FromCanonical converts a shared finding back into the legacy certificate
// shape. Canonical-only fields have no certificate representation and are
// intentionally dropped.
func FromCanonical(f finding.Finding) Finding {
	return Finding{
		ID:       f.ID,
		Severity: f.Severity,
		Title:    f.Title,
		Evidence: f.Evidence,
	}
}

// ComplianceResult maps one framework control to pass/fail.
type ComplianceResult struct {
	Framework string `json:"framework"`
	ID        string `json:"id"`
	Title     string `json:"title"`
	Status    string `json:"status"` // PASS / FAIL / NOT TESTED
}

// Counts is the severity histogram of all findings.
type Counts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// Assessment is the signed payload of a certificate. Only structs and slices
// are used (no maps) so JSON encoding is deterministic across runs.
type Assessment struct {
	// Tool identifies the issuing build.
	Tool        string `json:"tool"`
	ToolVersion string `json:"tool_version"`
	// Target and scope.
	Target   string `json:"target"`
	Scope    string `json:"scope"`
	Started  string `json:"started"`
	Ended    string `json:"ended"`
	Duration string `json:"duration"`
	// Outcome.
	RiskScore   int                `json:"risk_score"`
	Grade       string             `json:"grade"`
	Verdict     string             `json:"verdict"`
	Counts      Counts             `json:"counts"`
	OWASPPass   int                `json:"owasp_pass"`
	Findings    []Finding          `json:"findings,omitempty"`
	Compliance  []ComplianceResult `json:"compliance,omitempty"`
	Covered     []string           `json:"covered,omitempty"` // scanner families that ran
	DocumentSHA string             `json:"document_sha"`      // sha256 of rendered document body (seal excluded)
	// Issuance.
	Issuer   string `json:"issuer"`
	SignedAt string `json:"signed_at"`
}

// Certificate is the sealed envelope: a signed assessment plus the signer's
// public key, so the file verifies by itself. HTML carries the full rendered
// document (signature seal included) for display/printing.
//
// Hash chain: CertificateID is a unique per-certificate identifier and
// PreviousCertificateHash binds this certificate to the one issued before it,
// so any removed or re-ordered certificate breaks the chain and is detectable
// during verification.
type Certificate struct {
	Assessment              Assessment `json:"assessment"`
	Signature               string     `json:"signature"`  // hex Ed25519 over the signed payload (v1: assessment, v2: assessment + envelope)
	PublicKey               string     `json:"public_key"` // hex Ed25519 signer public key
	SignedAt                string     `json:"signed_at"`
	Version                 string     `json:"version"`                   // ss-cert/v1 or ss-cert/v2
	HTML                    string     `json:"html"`                      // full rendered document (signature seal included)
	CertificateID           string     `json:"certificate_id"`            // unique per-certificate id
	PreviousCertificateHash string     `json:"previous_certificate_hash"` // sha256 of previous certificate JSON
	ExperimentReference     string     `json:"experiment_reference"`      // source experiment/run id this cert attests to
	ValidityPeriod          string     `json:"validity_period"`           // e.g. "90 days"
}

// NewFromPentest builds an Assessment from a pentest report's summary fields.
// Callers fill in the scanner-specific slices before calling Sign.
func NewFromPentest(target, scope, issuer, toolVersion string, risk int, grade, verdict string,
	counts Counts, owaspPass int, started, ended, duration string) Assessment {
	return Assessment{
		Tool:        "Sift",
		ToolVersion: toolVersion,
		Target:      target,
		Scope:       scope,
		Started:     started,
		Ended:       ended,
		Duration:    duration,
		RiskScore:   risk,
		Grade:       grade,
		Verdict:     verdict,
		Counts:      counts,
		OWASPPass:   owaspPass,
		Issuer:      issuer,
		SignedAt:    time.Now().UTC().Format(time.RFC3339),
	}
}

// ValidateAssessmentInput checks that an assessment is internally consistent and
// safe to sign. It rejects contradictory metrics and impossible timing values so
// certificates fail closed instead of attesting fabricated or incoherent state.
func ValidateAssessmentInput(a Assessment) error {
	if strings.TrimSpace(a.Target) == "" {
		return fmt.Errorf("certificate: assessment target is empty")
	}
	if a.RiskScore < 0 || a.RiskScore > 100 {
		return fmt.Errorf("certificate: risk_score %d is outside 0..100", a.RiskScore)
	}
	if a.OWASPPass < 0 || a.OWASPPass > 10 {
		return fmt.Errorf("certificate: owasp_pass %d is outside 0..10", a.OWASPPass)
	}
	for name, n := range map[string]int{
		"critical": a.Counts.Critical,
		"high":     a.Counts.High,
		"medium":   a.Counts.Medium,
		"low":      a.Counts.Low,
		"info":     a.Counts.Info,
	} {
		if n < 0 {
			return fmt.Errorf("certificate: %s count %d is negative", name, n)
		}
	}
	derived := Counts{}
	for _, f := range a.Findings {
		switch strings.ToLower(strings.TrimSpace(f.Severity)) {
		case "critical":
			derived.Critical++
		case "high":
			derived.High++
		case "medium":
			derived.Medium++
		case "low":
			derived.Low++
		default:
			derived.Info++
		}
	}
	if derived != a.Counts {
		return fmt.Errorf("certificate: severity counts do not match findings (counts %+v, findings %+v)", a.Counts, derived)
	}
	if err := validateAssessmentTiming(a); err != nil {
		return err
	}
	return nil
}

// canonical returns the deterministic JSON bytes to sign. Struct field order
// is fixed by the type declaration, so this is stable across runs and builds.
// Slices are copied before sorting so the caller's assessment is not mutated
// (slice headers are passed by value, but the backing arrays are shared).
func canonical(a Assessment) ([]byte, error) {
	findings := make([]Finding, len(a.Findings))
	copy(findings, a.Findings)
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return severityRank(findings[i].Severity) < severityRank(findings[j].Severity)
		}
		return findings[i].ID < findings[j].ID
	})
	a.Findings = findings

	compliance := make([]ComplianceResult, len(a.Compliance))
	copy(compliance, a.Compliance)
	sort.SliceStable(compliance, func(i, j int) bool {
		if compliance[i].Framework != compliance[j].Framework {
			return compliance[i].Framework < compliance[j].Framework
		}
		return compliance[i].ID < compliance[j].ID
	})
	a.Compliance = compliance

	covered := make([]string, len(a.Covered))
	copy(covered, a.Covered)
	sort.Strings(covered)
	a.Covered = covered

	return json.Marshal(a)
}

// severityRank orders severities most-to-least for stable sorting.
func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

// stripSeal removes the signature seal block from rendered HTML so the hash is
// computed over the document body only (the seal content — signature value,
// public key — is intentionally outside the cryptographic boundary to avoid a
// circular dependency: signature covers document, document displays signature).
func stripSeal(html string) string {
	const open = `<div class="seal">`
	const close = `</div>`
	start := strings.Index(html, open)
	if start < 0 {
		return html
	}
	rest := html[start:]
	// The seal block contains nested <div> elements. Find the matching closing
	// tag for the seal container itself so the surrounding document remains in
	// the cryptographic boundary.
	depth := 0
	for i := 0; i < len(rest); i++ {
		switch {
		case strings.HasPrefix(rest[i:], "<div"):
			depth++
		case strings.HasPrefix(rest[i:], close):
			depth--
			if depth == 0 {
				return html[:start] + rest[i+len(close):]
			}
			if depth < 0 {
				return html[:start]
			}
		}
	}
	return html[:start]
}

// documentSHA returns the SHA-256 hex of the rendered document body, with the
// signature seal block excluded.
func documentSHA(html string) string {
	sum := sha256.Sum256([]byte(stripSeal(html)))
	return hex.EncodeToString(sum[:])
}

// Sign seals an assessment with the keypair and returns a self-verifying
// ss-cert/v1 Certificate. boundHTML is the rendered document body whose SHA-256
// is bound into the signed assessment (DocumentSHA). The seal block is excluded
// from the hash, so the caller may render the final seal afterward.
//
// Deprecated: v1 leaves the envelope (validity, previous link, source
// reference, envelope signing time) outside the signature. Use Issue or SignV2
// for new certificates.
func Sign(kp *attest.Keypair, a Assessment, boundHTML string) (*Certificate, error) {
	if kp == nil || len(kp.Private) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("certificate: signing requires a valid Ed25519 private key")
	}
	a.DocumentSHA = documentSHA(boundHTML)
	msg, err := canonical(a)
	if err != nil {
		return nil, fmt.Errorf("certificate: canonicalize assessment: %w", err)
	}
	sig, err := attest.Sign(kp, msg)
	if err != nil {
		return nil, fmt.Errorf("certificate: sign: %w", err)
	}
	return &Certificate{
		Assessment: a,
		Signature:  hex.EncodeToString(sig),
		PublicKey:  hex.EncodeToString(kp.Public),
		SignedAt:   a.SignedAt,
		Version:    Version,
		HTML:       boundHTML,
	}, nil
}

// Envelope carries the certificate fields that ss-cert/v2 signs together with
// the assessment. In v1 these lived only in the envelope, outside the
// signature: changing the validity, the chain link or the source reference and
// then recomputing the derived certificate id produced a certificate that still
// verified. v2 makes them signed facts.
type Envelope struct {
	// SignedAt is the envelope signing time. Empty means the assessment's
	// SignedAt, which is what v1 did implicitly.
	SignedAt string
	// ValidityPeriod is the human-readable validity shown in the seal and PDF.
	ValidityPeriod string
	// PreviousCertificateHash links this certificate to the one before it.
	PreviousCertificateHash string
	// ExperimentReference names the source experiment/run.
	ExperimentReference string
}

// SignV2 seals an assessment together with its envelope (ss-cert/v2).
//
// The signed payload is the canonical assessment plus the envelope fields and
// the signer's public key, so the rendered seal — issuer, fingerprint, sealed
// time, validity, previous link — describes signed values rather than fields a
// holder can edit. boundHTML is the rendered document body whose SHA-256 is
// bound into the assessment (DocumentSHA); the seal block stays outside that
// hash so the real signature can be rendered into it afterward.
func SignV2(kp *attest.Keypair, a Assessment, boundHTML string, env Envelope) (*Certificate, error) {
	if kp == nil || len(kp.Private) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("certificate: signing requires a valid Ed25519 private key")
	}
	a.DocumentSHA = documentSHA(boundHTML)
	signedAt := strings.TrimSpace(env.SignedAt)
	if signedAt == "" {
		signedAt = a.SignedAt
	}
	c := &Certificate{
		Assessment:              a,
		PublicKey:               hex.EncodeToString(kp.Public),
		SignedAt:                signedAt,
		Version:                 VersionV2,
		HTML:                    boundHTML,
		PreviousCertificateHash: env.PreviousCertificateHash,
		ExperimentReference:     env.ExperimentReference,
		ValidityPeriod:          env.ValidityPeriod,
	}
	msg, err := canonicalV2(c)
	if err != nil {
		return nil, fmt.Errorf("certificate: canonicalize envelope: %w", err)
	}
	sig, err := attest.Sign(kp, msg)
	if err != nil {
		return nil, fmt.Errorf("certificate: sign: %w", err)
	}
	c.Signature = hex.EncodeToString(sig)
	return c, nil
}

// canonicalV2 is the ss-cert/v2 signed payload: the canonical assessment plus
// every envelope field that the rendered document displays. Marshaling a
// json.RawMessage keeps the assessment's canonical byte form (sorted findings,
// compliance and coverage) instead of re-encoding it with map ordering.
func canonicalV2(c *Certificate) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("certificate: nil certificate")
	}
	assessment, err := canonical(c.Assessment)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Version                 string          `json:"version"`
		SignedAt                string          `json:"signed_at"`
		ValidityPeriod          string          `json:"validity_period"`
		PreviousCertificateHash string          `json:"previous_certificate_hash"`
		ExperimentReference     string          `json:"experiment_reference"`
		PublicKey               string          `json:"public_key"`
		Assessment              json.RawMessage `json:"assessment"`
	}{
		Version:                 c.Version,
		SignedAt:                c.SignedAt,
		ValidityPeriod:          c.ValidityPeriod,
		PreviousCertificateHash: c.PreviousCertificateHash,
		ExperimentReference:     c.ExperimentReference,
		PublicKey:               c.PublicKey,
		Assessment:              assessment,
	})
}

// Verify checks the certificate's Ed25519 signature over its signed payload,
// recomputes the document SHA-256 from the embedded HTML, and validates that
// the signed assessment/envelope do not contain contradictory or impossible
// values. It returns nil when the certificate is valid.
//
// v1 and v2 are both accepted. v1 certificates were signed over the assessment
// alone, so their envelope fields remain outside the signature; requiring the
// v2 rules would reject certificates already issued. Everything this build
// issues is v2.
func Verify(c *Certificate) error {
	if c == nil {
		return fmt.Errorf("certificate: nil certificate")
	}
	pub, sig, err := decodeSignature(c)
	if err != nil {
		return err
	}

	switch c.Version {
	case Version:
		return verifyV1(c, pub, sig)
	case VersionV2:
		return verifyV2(c, pub, sig)
	default:
		return fmt.Errorf("certificate: unsupported version %q", c.Version)
	}
}

// decodeSignature decodes the public key and signature an envelope carries.
func decodeSignature(c *Certificate) (ed25519.PublicKey, []byte, error) {
	pub, err := hex.DecodeString(c.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, nil, fmt.Errorf("certificate: malformed public key")
	}
	sig, err := hex.DecodeString(c.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, nil, fmt.Errorf("certificate: malformed signature")
	}
	return pub, sig, nil
}

// verifyV1 keeps the original ss-cert/v1 contract byte for byte so certificates
// issued before v2 continue to verify.
func verifyV1(c *Certificate, pub ed25519.PublicKey, sig []byte) error {
	msg, err := canonical(c.Assessment)
	if err != nil {
		return fmt.Errorf("certificate: canonicalize assessment: %w", err)
	}
	if !attest.VerifySig(pub, msg, sig) {
		return fmt.Errorf("certificate: signature invalid — assessment or signature was altered")
	}
	if got := documentSHA(c.HTML); got != c.Assessment.DocumentSHA {
		return fmt.Errorf("certificate: document hash mismatch — rendered body was altered")
	}
	if err := validateAssessment(c.Assessment); err != nil {
		return err
	}
	return validateEnvelope(c)
}

// verifyV2 checks the signed payload that covers the assessment and the
// envelope, then requires the embedded page to be exactly what this certificate
// renders.
func verifyV2(c *Certificate, pub ed25519.PublicKey, sig []byte) error {
	msg, err := canonicalV2(c)
	if err != nil {
		return fmt.Errorf("certificate: canonicalize envelope: %w", err)
	}
	if !attest.VerifySig(pub, msg, sig) {
		return fmt.Errorf("certificate: signature invalid — assessment, envelope or signature was altered")
	}
	if got := documentSHA(c.HTML); got != c.Assessment.DocumentSHA {
		return fmt.Errorf("certificate: document hash mismatch — rendered body was altered")
	}
	if err := validateAssessment(c.Assessment); err != nil {
		return err
	}
	if err := validateEnvelope(c); err != nil {
		return err
	}
	// The seal block sits outside the document hash by construction (it holds
	// the signature, which cannot cover itself). That left the values the seal
	// displays — issuer, key fingerprint, sealed time, validity, previous link —
	// editable on their own. v2 closes that by requiring the stored page to be
	// the page this certificate renders: any edit inside the seal changes the
	// bytes and fails here.
	if strings.TrimSpace(c.HTML) != "" && c.HTML != HTML(c) {
		return fmt.Errorf("certificate: rendered document does not match the sealed certificate — the seal block was altered")
	}
	return nil
}

// validateAssessment rejects contradictory or impossible signed values. This is
// a fail-closed integrity check: a certificate must not attest to an internally
// inconsistent assessment.
func validateAssessment(a Assessment) error {
	if strings.TrimSpace(a.Target) == "" {
		return fmt.Errorf("certificate: assessment target is empty")
	}
	if a.RiskScore < 0 || a.RiskScore > 100 {
		return fmt.Errorf("certificate: risk_score %d is outside 0..100", a.RiskScore)
	}
	if a.OWASPPass < 0 || a.OWASPPass > 10 {
		return fmt.Errorf("certificate: owasp_pass %d is outside 0..10", a.OWASPPass)
	}
	for name, n := range map[string]int{
		"critical": a.Counts.Critical,
		"high":     a.Counts.High,
		"medium":   a.Counts.Medium,
		"low":      a.Counts.Low,
		"info":     a.Counts.Info,
	} {
		if n < 0 {
			return fmt.Errorf("certificate: %s count %d is negative", name, n)
		}
	}
	derived := Counts{}
	for _, f := range a.Findings {
		switch strings.ToLower(strings.TrimSpace(f.Severity)) {
		case "critical":
			derived.Critical++
		case "high":
			derived.High++
		case "medium":
			derived.Medium++
		case "low":
			derived.Low++
		default:
			derived.Info++
		}
	}
	if derived != a.Counts {
		return fmt.Errorf("certificate: severity counts do not match findings (counts %+v, findings %+v)", a.Counts, derived)
	}
	if a.DocumentSHA == "" || len(a.DocumentSHA) != 64 {
		return fmt.Errorf("certificate: document_sha is missing or malformed")
	}
	if _, err := hex.DecodeString(a.DocumentSHA); err != nil {
		return fmt.Errorf("certificate: document_sha is not hex: %w", err)
	}
	if err := validateAssessmentTiming(a); err != nil {
		return err
	}
	return nil
}

func parseAssessmentTime(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, s)
}

func validateAssessmentTiming(a Assessment) error {
	if strings.TrimSpace(a.Started) == "" || strings.TrimSpace(a.Ended) == "" {
		return fmt.Errorf("certificate: assessment timestamps are missing")
	}
	start, err := parseAssessmentTime(a.Started)
	if err != nil {
		return fmt.Errorf("certificate: started timestamp is invalid: %w", err)
	}
	end, err := parseAssessmentTime(a.Ended)
	if err != nil {
		return fmt.Errorf("certificate: ended timestamp is invalid: %w", err)
	}
	if end.Before(start) {
		return fmt.Errorf("certificate: ended timestamp is before started timestamp")
	}
	if strings.TrimSpace(a.Duration) == "" {
		return fmt.Errorf("certificate: duration is missing")
	}
	dur, err := time.ParseDuration(a.Duration)
	if err != nil {
		return fmt.Errorf("certificate: duration is invalid: %w", err)
	}
	if dur <= 0 {
		return fmt.Errorf("certificate: duration must be greater than zero")
	}
	// Duration must be consistent with the timestamps. Sub-second precision in
	// timestamps is preserved (RFC3339Nano) so fractional-second scans do not
	// fail validation due to second-level truncation.
	if got := end.Sub(start); got != dur {
		return fmt.Errorf("certificate: duration %s does not match timestamps (%s)", a.Duration, got)
	}
	return nil
}

func validateEnvelope(c *Certificate) error {
	if strings.TrimSpace(c.CertificateID) == "" {
		return fmt.Errorf("certificate: certificate_id is missing")
	}
	wantID := CertificateID(c)
	if c.CertificateID != wantID {
		return fmt.Errorf("certificate: certificate_id does not match certificate contents")
	}
	if c.PreviousCertificateHash != "" {
		if len(c.PreviousCertificateHash) != 64 {
			return fmt.Errorf("certificate: previous_certificate_hash is malformed")
		}
		if _, err := hex.DecodeString(c.PreviousCertificateHash); err != nil {
			return fmt.Errorf("certificate: previous_certificate_hash is not hex: %w", err)
		}
	}
	if c.Version == VersionV2 {
		// Both values are signed in v2, so this is a consistency rule rather
		// than a security boundary: the seal and the assessment must not claim
		// two different signing times.
		if c.SignedAt != c.Assessment.SignedAt {
			return fmt.Errorf("certificate: signed_at does not match the assessment")
		}
	}
	return nil
}

// CertificateID derives a deterministic, tamper-evident identifier from the
// certificate's signed and envelope material. It is verifiable from the
// certificate itself.
func CertificateID(c *Certificate) string {
	if c == nil {
		return ""
	}
	h := sha256.Sum256([]byte(c.Signature + "\x00" + c.PublicKey + "\x00" + c.Assessment.SignedAt + "\x00" + c.Assessment.Target + "\x00" + c.PreviousCertificateHash + "\x00" + c.ExperimentReference + "\x00" + c.ValidityPeriod))
	return "ss-cert-" + hex.EncodeToString(h[:])[:16]
}

// VerifyBytes parses a JSON certificate and verifies it.
func VerifyBytes(data []byte) (*Certificate, error) {
	var c Certificate
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("certificate: parse: %w", err)
	}
	if err := Verify(&c); err != nil {
		return nil, err
	}
	return &c, nil
}

// TrustCheck is the answer to the question Verify cannot answer on its own:
// who issued this certificate?
//
// A certificate carries the public key that signed it, so a passing signature
// proves the document is self-consistent and nothing more — anyone can mint a
// keypair and seal any assessment. Status reports whether the signer is one the
// verifier chose to accept.
type TrustCheck struct {
	// Status is pinned, unpinned, untrusted or missing.
	Status attest.IssuerTrust
	// Label is the trust-store label of the signer, when pinned.
	Label string
	// Key is the signer public key as lowercase hex, echoed for the report.
	Key string
}

// Trusted reports whether the signer was positively established.
func (t TrustCheck) Trusted() bool { return t.Status.Trusted() }

// Fingerprint renders the signer key in the grouped form printed on documents.
func (t TrustCheck) Fingerprint() string { return attest.FingerprintHex(t.Key) }

// VerifyWithTrust verifies c and then establishes whether its signer is
// accepted by store.
//
// The two questions are kept separate on purpose:
//
//   - store == nil — the signature is checked and Status is unpinned. This is
//     the historical behaviour, so existing callers and certificates keep
//     working; the report simply stops implying an identity it cannot prove.
//   - store != nil — a signer that is not in the store fails verification, even
//     when every byte of the certificate is internally consistent.
//   - requireAnchor turns "no store configured" into a failure.
//
// A returned error never hides the trust verdict: the TrustCheck is populated
// before verification runs, so a rejection report can name the claimed signer.
func VerifyWithTrust(c *Certificate, store *attest.TrustStore, requireAnchor bool) (TrustCheck, error) {
	if c == nil {
		return TrustCheck{Status: attest.IssuerMissing}, fmt.Errorf("certificate: nil certificate")
	}

	check := TrustCheck{Key: strings.ToLower(strings.TrimSpace(c.PublicKey))}
	switch {
	case check.Key == "":
		check.Status = attest.IssuerMissing
	case store == nil:
		check.Status = attest.IssuerUnpinned
	default:
		if entry, ok := store.Lookup(check.Key); ok {
			check.Status = attest.IssuerPinned
			check.Label = entry.Label
		} else {
			check.Status = attest.IssuerUntrusted
		}
	}

	if err := Verify(c); err != nil {
		return check, err
	}

	switch {
	case check.Status == attest.IssuerMissing:
		return check, fmt.Errorf("certificate: the envelope carries no signer key, so no issuer can be established")
	case check.Status == attest.IssuerUntrusted:
		return check, fmt.Errorf("certificate: signer %s is not in the trust store (%d accepted issuers)",
			check.Fingerprint(), store.Len())
	case check.Status == attest.IssuerUnpinned && requireAnchor:
		return check, fmt.Errorf("certificate: signer %s is unpinned and a trust anchor is required",
			check.Fingerprint())
	}
	return check, nil
}

// VerifyBytesWithTrust parses a JSON certificate, verifies it, and checks its
// signer against store.
func VerifyBytesWithTrust(data []byte, store *attest.TrustStore, requireAnchor bool) (*Certificate, TrustCheck, error) {
	var c Certificate
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, TrustCheck{Status: attest.IssuerMissing}, fmt.Errorf("certificate: parse: %w", err)
	}
	check, err := VerifyWithTrust(&c, store, requireAnchor)
	if err != nil {
		return nil, check, err
	}
	return &c, check, nil
}

// MarshalJSON writes the certificate as JSON.
func (c *Certificate) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Assessment              Assessment `json:"assessment"`
		Signature               string     `json:"signature"`
		PublicKey               string     `json:"public_key"`
		SignedAt                string     `json:"signed_at"`
		Version                 string     `json:"version"`
		HTML                    string     `json:"html"`
		CertificateID           string     `json:"certificate_id"`
		PreviousCertificateHash string     `json:"previous_certificate_hash"`
		ExperimentReference     string     `json:"experiment_reference"`
		ValidityPeriod          string     `json:"validity_period"`
	}{
		Assessment:              c.Assessment,
		Signature:               c.Signature,
		PublicKey:               c.PublicKey,
		SignedAt:                c.SignedAt,
		Version:                 c.Version,
		HTML:                    c.HTML,
		CertificateID:           c.CertificateID,
		PreviousCertificateHash: c.PreviousCertificateHash,
		ExperimentReference:     c.ExperimentReference,
		ValidityPeriod:          c.ValidityPeriod,
	})
}
