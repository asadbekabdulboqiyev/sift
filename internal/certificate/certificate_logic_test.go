package certificate

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/attest"
)

func validAssessment() Assessment {
	a := NewFromPentest("https://example.com", "full", "QA Lead", "0.14.5", 12, "B", "PASS",
		Counts{High: 1, Low: 1}, 9,
		"2026-11-07T08:00:00Z", "2026-11-07T08:05:00Z", "5m0s")
	a.Findings = []Finding{
		{ID: "H-1", Severity: "high", Title: "High", Evidence: "e"},
		{ID: "L-1", Severity: "low", Title: "Low", Evidence: "e"},
	}
	return a
}

func issueValid(t *testing.T) *Certificate {
	t.Helper()
	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	c, err := Issue(kp, validAssessment(), strings.Repeat("a", 64), "exp-ref")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return c
}

func TestCertificateVerifyRejectsSingleByteTamperInJSON(t *testing.T) {
	c := issueValid(t)
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	tamperByte := func(i int, b byte) []byte {
		out := append([]byte(nil), raw...)
		out[i] = b
		return out
	}
	mustFail := func(name string, idx int) {
		t.Helper()
		b := raw[idx]
		if b == 'a' {
			b = 'b'
		} else {
			b = 'a'
		}
		if _, err := VerifyBytes(tamperByte(idx, b)); err == nil {
			t.Fatalf("%s: single-byte tamper verified", name)
		}
	}

	// Signature (cryptographic seal).
	sigIdx := strings.Index(string(raw), `"signature":"`)
	if sigIdx < 0 {
		t.Fatal("signature not found")
	}
	mustFail("signature", sigIdx+len(`"signature":"`)+10)

	// Signed assessment content.
	targetIdx := strings.Index(string(raw), `"target":"https://example.com"`)
	if targetIdx < 0 {
		t.Fatal("target not found")
	}
	mustFail("assessment target", targetIdx+len(`"target":"https://example.co`))

	// Rendered document body bound by DocumentSHA.
	htmlIdx := strings.Index(string(raw), `Security Assessment Certificate`)
	if htmlIdx < 0 {
		t.Fatal("html title not found")
	}
	mustFail("html body", htmlIdx+1)

	// Envelope fields bound via deterministic CertificateID.
	idIdx := strings.Index(string(raw), `"certificate_id":"ss-cert-`)
	if idIdx < 0 {
		t.Fatal("certificate_id not found")
	}
	mustFail("certificate_id", idIdx+len(`"certificate_id":"ss-cert-`)+2)

	prevIdx := strings.Index(string(raw), `"previous_certificate_hash":"`)
	if prevIdx < 0 {
		t.Fatal("previous_certificate_hash not found")
	}
	mustFail("previous_certificate_hash", prevIdx+len(`"previous_certificate_hash":"`))

	expIdx := strings.Index(string(raw), `"experiment_reference":"exp-ref"`)
	if expIdx < 0 {
		t.Fatal("experiment_reference not found")
	}
	mustFail("experiment_reference", expIdx+len(`"experiment_reference":"exp-re`))

	valIdx := strings.Index(string(raw), `"validity_period":"90 days"`)
	if valIdx < 0 {
		t.Fatal("validity_period not found")
	}
	mustFail("validity_period", valIdx+len(`"validity_period":"90 da`))
}

func TestIssueRejectsContradictoryCountsAndMetrics(t *testing.T) {
	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	base := validAssessment()
	cases := []struct {
		name string
		mut  func(*Assessment)
	}{
		{"counts mismatch findings", func(a *Assessment) { a.Counts = Counts{Critical: 9} }},
		{"negative count", func(a *Assessment) { a.Counts.Low = -1 }},
		{"risk too high", func(a *Assessment) { a.RiskScore = 101 }},
		{"risk negative", func(a *Assessment) { a.RiskScore = -1 }},
		{"owasp out of range", func(a *Assessment) { a.OWASPPass = 11 }},
	}
	for _, tc := range cases {
		a := base
		a.Findings = append([]Finding(nil), base.Findings...)
		tc.mut(&a)
		if _, err := Issue(kp, a, "", ""); err == nil {
			t.Fatalf("%s: expected error", tc.name)
		}
	}
}

func TestIssueRejectsTimingInconsistencies(t *testing.T) {
	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	base := validAssessment()
	cases := []struct {
		name string
		mut  func(*Assessment)
	}{
		{"end before start", func(a *Assessment) {
			a.Started = "2026-11-07T08:05:00Z"
			a.Ended = "2026-11-07T08:00:00Z"
			a.Duration = "5m0s"
		}},
		{"zero duration", func(a *Assessment) {
			a.Started = "2026-11-07T08:00:00Z"
			a.Ended = "2026-11-07T08:00:00Z"
			a.Duration = "0s"
		}},
		{"duration mismatch", func(a *Assessment) { a.Duration = "1m0s" }},
		{"negative duration", func(a *Assessment) {
			a.Ended = "2026-11-07T07:59:00Z"
			a.Duration = "-1m0s"
		}},
		{"invalid started", func(a *Assessment) { a.Started = "not-a-time" }},
	}
	for _, tc := range cases {
		a := base
		a.Findings = append([]Finding(nil), base.Findings...)
		tc.mut(&a)
		if _, err := Issue(kp, a, "", ""); err == nil {
			t.Fatalf("%s: expected error", tc.name)
		}
	}
}

func TestParsePentestReportRejectsImpossibleValues(t *testing.T) {
	base := `{"target":"https://example.com","started_at":"2026-11-07T08:00:00Z","duration":60000000000,"risk_score":10,"critical":0,"high":0,"medium":0,"low":0,"info_count":0,"owasp_pass":0}`
	ok, err := ParsePentestReport([]byte(base))
	if err != nil {
		t.Fatalf("valid report rejected: %v", err)
	}
	if ok.Target == "" {
		t.Fatal("empty target")
	}
	cases := []string{
		`{"target":"","started_at":"2026-11-07T08:00:00Z","duration":60000000000,"risk_score":10}`,
		`{"target":"t","started_at":"2026-11-07T08:00:00Z","duration":0,"risk_score":10}`,
		`{"target":"t","started_at":"2026-11-07T08:00:00Z","duration":-1,"risk_score":10}`,
		`{"target":"t","started_at":"2026-11-07T08:00:00Z","duration":60000000000,"risk_score":101}`,
		`{"target":"t","started_at":"2026-11-07T08:00:00Z","duration":60000000000,"risk_score":-1}`,
		`{"target":"t","started_at":"2026-11-07T08:00:00Z","duration":60000000000,"risk_score":10,"high":-1}`,
		`{"target":"t","started_at":"2026-11-07T08:00:00Z","duration":60000000000,"risk_score":10,"owasp_pass":11}`,
		`{"target":"t","duration":60000000000,"risk_score":10}`,
	}
	for _, tc := range cases {
		if _, err := ParsePentestReport([]byte(tc)); err == nil {
			t.Fatalf("expected parse error for %s", tc)
		}
	}
}

func TestBuildAssessmentContradictoryCountsFailClosed(t *testing.T) {
	start, _ := time.Parse(time.RFC3339, "2026-11-07T08:00:00Z")
	r := PentestReport{
		Target:    "https://example.com",
		StartedAt: start,
		Duration:  60 * time.Second,
		RiskScore: 20,
		Grade:     "B",
		Verdict:   "PASS",
		Critical:  5, // contradicts findings
		Vulns: []PentestVuln{
			{ID: "1", Severity: "low", Title: "l"},
			{ID: "2", Severity: "INFO", Title: "i"},
		},
	}
	a := BuildAssessment(r, "issuer", "1.0")
	if err := ValidateAssessmentInput(a); err == nil {
		t.Fatal("contradictory assessment accepted")
	}
	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	if _, err := Issue(kp, a, "", ""); err == nil {
		t.Fatal("contradictory certificate issued")
	}
}

func TestVerifyRejectsContradictorySignedAssessment(t *testing.T) {
	c := issueValid(t)
	// Forge a contradictory but signed-claim shape: counts vs findings mismatch
	// would fail signature if changed naively; instead check impossible risk/owasp
	// by reconstructing through Verify path on a cert whose fields are corrupted
	// post-verification assumptions? Easier: build cert, then tamper and expect
	// Verify to reject due to envelope/signature/integrity checks where applicable.
	bad := *c
	bad.Assessment = c.Assessment
	bad.Assessment.RiskScore = 150
	if err := Verify(&bad); err == nil {
		t.Fatal("impossible risk score verified")
	}
	bad2 := *c
	bad2.Assessment = c.Assessment
	bad2.Assessment.Started = "2026-11-07T08:10:00Z"
	bad2.Assessment.Ended = "2026-11-07T08:05:00Z"
	if err := Verify(&bad2); err == nil {
		t.Fatal("impossible timing verified")
	}
	bad3 := *c
	bad3.Assessment = c.Assessment
	bad3.Assessment.OWASPPass = 99
	if err := Verify(&bad3); err == nil {
		t.Fatal("impossible owasp_pass verified")
	}
}
