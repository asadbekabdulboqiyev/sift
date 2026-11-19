package main

// BE-1: the dashboard's `format=json|signed-json` download wraps the sealed
// report in {"job_id", "state", "report"}. The CLI verifier read the file as a
// bare Audit360Report, so unknown wrapper keys were dropped and every seal
// field came back empty — a genuinely signed report was reported INVALID.
// The verifier must unwrap the download while still accepting bare reports.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/asadbekabdulboqiyev/sift/internal/attest"
	"github.com/asadbekabdulboqiyev/sift/internal/audit360"
)

// writeWrappedReport writes the exact shape the dashboard download emits.
func writeWrappedReport(t *testing.T, kp *attest.Keypair, mutate func(*audit360.Audit360Report)) string {
	t.Helper()
	bare := writeSealedReport(t, kp, mutate)
	raw, err := os.ReadFile(bare)
	if err != nil {
		t.Fatalf("read sealed report: %v", err)
	}
	wrapper, err := json.Marshal(map[string]any{
		"job_id": "job-be1",
		"state":  "completed",
		"report": json.RawMessage(raw),
	})
	if err != nil {
		t.Fatalf("marshal wrapper: %v", err)
	}
	path := filepath.Join(t.TempDir(), "download.json")
	if err := os.WriteFile(path, wrapper, 0o600); err != nil {
		t.Fatalf("write wrapper: %v", err)
	}
	return path
}

func TestAudit360VerifyAcceptsDashboardDownload(t *testing.T) {
	kp := newTestKey(t)
	path := writeWrappedReport(t, kp, nil)

	res := runCLIInProcess(t, "audit360", "verify", path, "--json")
	if res.code != 0 {
		t.Fatalf("exit = %d, want 0 (stdout=%s stderr=%s)", res.code, res.stdout, res.stderr)
	}
	var out struct {
		Valid         bool   `json:"valid"`
		Target        string `json:"target"`
		CertificateID string `json:"certificate_id"`
		SignerKey     string `json:"signer_key"`
	}
	if err := json.Unmarshal([]byte(res.stdout), &out); err != nil {
		t.Fatalf("decode json: %v (%s)", err, res.stdout)
	}
	if !out.Valid {
		t.Fatalf("wrapped sealed report reported invalid: %s", res.stdout)
	}
	if out.Target != "https://example.test/app" {
		t.Errorf("target = %q, want the sealed report target", out.Target)
	}
	if out.CertificateID == "" || out.SignerKey == "" {
		t.Errorf("missing seal fields from unwrapped report: %+v", out)
	}
}

func TestAudit360VerifyRejectsTamperedWrappedReport(t *testing.T) {
	kp := newTestKey(t)
	path := writeWrappedReport(t, kp, func(r *audit360.Audit360Report) {
		r.ResilienceScore = 1
	})

	res := runCLIInProcess(t, "audit360", "verify", path, "--json")
	if res.code == 0 {
		t.Fatalf("tampered wrapped report accepted: %s", res.stdout)
	}
	if !strings.Contains(res.stdout, "seal invalid") {
		t.Fatalf("unexpected error for tampered wrapped report: %s", res.stdout)
	}
	// The inner report WAS read and verified: the failure is a broken seal,
	// not the "could not find seal fields" error of an unread wrapper.
	if strings.Contains(res.stdout, "signature or public key missing") {
		t.Fatalf("wrapper was not unwrapped before verification: %s", res.stdout)
	}
}
