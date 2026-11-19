package certificate

import (
	"bytes"
	"strings"
	"testing"

	"github.com/asadbekabdulboqiyev/sift/internal/attest"
)

func TestCertificateSignVerifyRoundtrip(t *testing.T) {
	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	a := NewFromPentest("https://example.com", "full", "QA Lead", "0.14.5", 42, "C", "REVIEW",
		Counts{Critical: 1, High: 1, Medium: 0, Low: 0, Info: 0}, 6,
		"2026-11-07T08:00:00Z", "2026-11-07T08:05:00Z", "5m0s")
	a.Findings = []Finding{
		{ID: "HDR-001", Severity: "high", Title: "Missing Strict-Transport-Security", Evidence: "no HSTS header"},
		{ID: "SENS-001", Severity: "critical", Title: "Exposed .env", Evidence: "HTTP 200 on /.env"},
	}
	a.Compliance = []ComplianceResult{
		{Framework: "PCI DSS v4.0", ID: "PCI-6.4.3", Title: "Public-Facing Page Script Protection", Status: "FAIL"},
	}
	a.Covered = []string{"dirbust", "owasp", "tls"}

	c, err := Issue(kp, a, "", "exp-1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if c.Version != VersionV2 {
		t.Fatalf("version = %q, want %q", c.Version, VersionV2)
	}
	if c.PublicKey == "" || c.Signature == "" {
		t.Fatal("empty signature or public key")
	}
	if c.Assessment.DocumentSHA == "" {
		t.Fatal("document sha not bound")
	}
	if c.CertificateID == "" {
		t.Fatal("certificate_id not set")
	}
	docSHA := c.Assessment.DocumentSHA
	if err := Verify(c); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// JSON must round-trip and re-verify.
	data, err := c.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	c2, err := VerifyBytes(data)
	if err != nil {
		t.Fatalf("VerifyBytes: %v", err)
	}
	if c2.Assessment.Target != a.Target {
		t.Fatal("target mismatch after roundtrip")
	}
	if c2.Assessment.DocumentSHA != docSHA {
		t.Fatalf("document sha mismatch after roundtrip: %q != %q", c2.Assessment.DocumentSHA, docSHA)
	}
}

func TestCertificateRejectsTamper(t *testing.T) {
	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	a := NewFromPentest("https://example.com", "full", "QA Lead", "0.14.5", 1, "A", "PASS",
		Counts{High: 1}, 10, "2026-11-07T08:00:00Z", "2026-11-07T08:01:00Z", "1m0s")
	a.Findings = []Finding{{ID: "HDR-001", Severity: "high", Title: "Missing Strict-Transport-Security", Evidence: "no HSTS header"}}
	c, err := Issue(kp, a, "", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Flip a risk score -> signature must fail.
	tampered := *c
	tampered.Assessment.RiskScore = 99
	if err := Verify(&tampered); err == nil {
		t.Fatal("tampered risk score verified")
	}

	// Flip a finding title -> signature must fail.
	tampered2 := *c
	tampered2.Assessment = c.Assessment
	tampered2.Assessment.Findings = []Finding{{ID: "X", Severity: "low", Title: "changed", Evidence: ""}}
	tampered2.Assessment.Counts = Counts{Low: 1}
	if err := Verify(&tampered2); err == nil {
		t.Fatal("tampered findings verified")
	}

	// Alter the rendered document body (a finding title in HTML) without
	// changing the assessment -> document hash must fail.
	tampered3 := *c
	tampered3.HTML = strings.Replace(tampered3.HTML, "Missing Strict-Transport-Security", "ALtered", 1)
	if err := Verify(&tampered3); err == nil {
		t.Fatal("tampered document body verified")
	}

	// Wrong version -> fail.
	badVer := *c
	badVer.Version = "ss-cert/v3"
	if err := Verify(&badVer); err == nil {
		t.Fatal("wrong version verified")
	}

	// Nil cert -> fail.
	if err := Verify(nil); err == nil {
		t.Fatal("nil certificate verified")
	}
}

func TestCertificateHTMLAndPDF(t *testing.T) {
	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	a := NewFromPentest("https://example.com", "full", "QA Lead", "0.14.5", 0, "A", "PASS",
		Counts{}, 10, "2026-11-07T08:00:00Z", "2026-11-07T08:01:00Z", "1m0s")
	c, err := Issue(kp, a, "", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	html := HTML(c)
	if !strings.Contains(html, "Security Assessment Certificate") {
		t.Fatal("html missing title")
	}
	if !strings.Contains(html, c.Signature) {
		t.Fatal("html missing signature")
	}

	pdf := NewPDF().Text("Sift certificate").Page().Text("target: https://example.com")
	out, err := pdf.Bytes()
	if err != nil {
		t.Fatalf("PDF: %v", err)
	}
	if !bytes.HasPrefix(out, []byte("%PDF-1.4")) {
		t.Fatalf("PDF bad header: %q", out[:20])
	}
	if !bytes.Contains(out, []byte("%%EOF")) {
		t.Fatalf("PDF bad trailer: %q", out[len(out)-40:])
	}
}
