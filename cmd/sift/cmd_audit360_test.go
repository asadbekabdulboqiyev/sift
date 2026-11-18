package main

// cmd_audit360_test.go — in-process coverage for `Sift audit360 verify`.
//
// The command exists because a 360° report's seal was previously unverifiable
// outside the package's own tests: the PDF printed a signature nobody could
// check. These tests drive the real dispatch, so a regression in flag parsing,
// output or exit codes fails here rather than at a customer.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/asadbekabdulboqiyev/sift/internal/attest"
	"github.com/asadbekabdulboqiyev/sift/internal/audit360"
)

// writeSealedReport seals a report with kp, writes it, and returns the path.
func writeSealedReport(t *testing.T, kp *attest.Keypair, mutate func(*audit360.Audit360Report)) string {
	t.Helper()
	rep := &audit360.Audit360Report{
		TargetURL:       "https://example.test/app",
		Timestamp:       "2026-01-02T03:04:05Z",
		RiskLevel:       "low",
		ResilienceScore: 82,
		DurationMS:      1200,
		Findings: []audit360.Finding{{
			Title:    "Verbose error page",
			Severity: "high",
			Evidence: "HTTP 500 body contained /srv/app/main.go",
		}},
	}
	if _, _, _, err := audit360.SealWithKey(rep, kp); err != nil {
		t.Fatalf("SealWithKey: %v", err)
	}
	if mutate != nil {
		mutate(rep)
	}
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write report: %v", err)
	}
	return path
}

func newTestKey(t *testing.T) *attest.Keypair {
	t.Helper()
	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	return kp
}

func TestAudit360VerifyAcceptsSealedReport(t *testing.T) {
	kp := newTestKey(t)
	path := writeSealedReport(t, kp, nil)

	res := runCLIInProcess(t, "audit360", "verify", path)
	if res.code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr=%s)", res.code, res.stderr)
	}
	if !strings.Contains(res.stdout, "VALID") {
		t.Fatalf("stdout missing VALID verdict: %s", res.stdout)
	}
	if !strings.Contains(res.stdout, "sift.audit360/v2") {
		t.Fatalf("stdout missing format: %s", res.stdout)
	}
	if !strings.Contains(res.stdout, "https://example.test/app") {
		t.Fatalf("stdout missing target: %s", res.stdout)
	}
	// Without --key the output must say what the check does and does not prove.
	if !strings.Contains(res.stdout, "not who produced it") {
		t.Fatalf("stdout must state the attribution caveat: %s", res.stdout)
	}
}

func TestAudit360VerifyJSON(t *testing.T) {
	kp := newTestKey(t)
	path := writeSealedReport(t, kp, nil)

	res := runCLIInProcess(t, "audit360", "verify", path, "--json")
	if res.code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr=%s)", res.code, res.stderr)
	}
	var out struct {
		Valid             bool   `json:"valid"`
		Format            string `json:"format"`
		CertificateID     string `json:"certificate_id"`
		SignerKey         string `json:"signer_key"`
		SignerFingerprint string `json:"signer_fingerprint"`
		KeyPinned         bool   `json:"key_pinned"`
	}
	if err := json.Unmarshal([]byte(res.stdout), &out); err != nil {
		t.Fatalf("decode json: %v (%s)", err, res.stdout)
	}
	if !out.Valid {
		t.Fatal("valid report reported invalid")
	}
	if out.Format != "sift.audit360/v2" {
		t.Fatalf("format = %q", out.Format)
	}
	if out.CertificateID == "" || out.SignerKey == "" || out.SignerFingerprint == "" {
		t.Fatalf("json missing seal fields: %+v", out)
	}
	if out.KeyPinned {
		t.Fatal("key_pinned must be false without --key")
	}
}

func TestAudit360VerifyRejectsTamperedReport(t *testing.T) {
	kp := newTestKey(t)
	path := writeSealedReport(t, kp, func(r *audit360.Audit360Report) {
		r.ResilienceScore = 99
	})

	res := runCLIInProcess(t, "audit360", "verify", path)
	if res.code != 1 {
		t.Fatalf("exit = %d, want 1 (stdout=%s)", res.code, res.stdout)
	}
	if !strings.Contains(res.stderr, "INVALID") {
		t.Fatalf("stderr missing INVALID: %s", res.stderr)
	}
}

func TestAudit360VerifyPinnedKey(t *testing.T) {
	kp := newTestKey(t)
	path := writeSealedReport(t, kp, nil)
	ownKey := attest.PublicKeyHex(kp.Public)

	res := runCLIInProcess(t, "audit360", "verify", path, "--key", ownKey)
	if res.code != 0 {
		t.Fatalf("pinned own key: exit = %d, want 0 (stderr=%s)", res.code, res.stderr)
	}

	other := newTestKey(t)
	res = runCLIInProcess(t, "audit360", "verify", path, "--key", attest.PublicKeyHex(other.Public))
	if res.code != 1 {
		t.Fatalf("pinned foreign key: exit = %d, want 1 (stdout=%s)", res.code, res.stdout)
	}
	if !strings.Contains(res.stderr, "pinned key") {
		t.Fatalf("stderr should name the pinned-key mismatch: %s", res.stderr)
	}
}

func TestAudit360VerifyQuiet(t *testing.T) {
	kp := newTestKey(t)
	path := writeSealedReport(t, kp, nil)

	res := runCLIInProcess(t, "audit360", "verify", path, "--quiet")
	if res.code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr=%s)", res.code, res.stderr)
	}
	if strings.TrimSpace(res.stdout) != "" {
		t.Fatalf("--quiet printed: %q", res.stdout)
	}
}

func TestAudit360VerifyMissingFile(t *testing.T) {
	res := runCLIInProcess(t, "audit360", "verify", filepath.Join(t.TempDir(), "nope.json"))
	if res.code != 1 {
		t.Fatalf("exit = %d, want 1", res.code)
	}
	if !strings.Contains(res.stderr, "INVALID") {
		t.Fatalf("stderr missing INVALID: %s", res.stderr)
	}
}

func TestAudit360VerifyNoArgsShowsGuide(t *testing.T) {
	res := runCLIInProcess(t, "audit360")
	if res.code != 0 {
		t.Fatalf("exit = %d, want 0", res.code)
	}
	if !strings.Contains(res.stderr, "audit360") || !strings.Contains(res.stderr, "verify") {
		t.Fatalf("guide not printed: %s", res.stderr)
	}
}

func TestAudit360VerifyUnknownSubcommand(t *testing.T) {
	res := runCLIInProcess(t, "audit360", "frobnicate")
	if res.code != 2 {
		t.Fatalf("exit = %d, want 2", res.code)
	}
}

// TestAudit360VerifyFlagBeforePath pins order independence: Go's flag package
// stops at the first positional, so `verify --key <hex> report.json` and
// `verify report.json --key <hex>` must reach the same verdict. A verification
// command that silently ignores a flag is worse than one that rejects it.
func TestAudit360VerifyFlagBeforePath(t *testing.T) {
	kp := newTestKey(t)
	path := writeSealedReport(t, kp, nil)

	res := runCLIInProcess(t, "audit360", "verify", "--key", attest.PublicKeyHex(kp.Public), path)
	if res.code != 0 {
		t.Fatalf("flags before path: exit = %d, want 0 (stderr=%s)", res.code, res.stderr)
	}

	other := newTestKey(t)
	res = runCLIInProcess(t, "audit360", "verify", "--key", attest.PublicKeyHex(other.Public), path)
	if res.code != 1 {
		t.Fatalf("foreign pinned key before path: exit = %d, want 1", res.code)
	}
}

// TestAudit360VerifyRejectsExtraPositionals: two files is a mistake, not a
// request to check the first one and ignore the second.
func TestAudit360VerifyRejectsExtraPositionals(t *testing.T) {
	kp := newTestKey(t)
	path := writeSealedReport(t, kp, nil)

	res := runCLIInProcess(t, "audit360", "verify", path, path)
	if res.code != 2 {
		t.Fatalf("exit = %d, want 2 (stdout=%s)", res.code, res.stdout)
	}
	if !strings.Contains(res.stderr, "unexpected arguments") {
		t.Fatalf("stderr should name the extra arguments: %s", res.stderr)
	}
}
