package dashboard

// audit360_gate_test.go — the 360° audit sends traffic at the target (a load
// test in standard mode), so the browser path must run the same authorization
// gate the CLI runs. Before this, POST /api/audit-360 accepted any http(s) URL:
// a dashboard user could point the audit at cloud instance metadata or a
// private host and the server would start sending requests there.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/asadbekabdulboqiyev/sift/internal/audit360"
	"github.com/asadbekabdulboqiyev/sift/internal/authz"
)

// audit360GateEnv isolates the policy and audit trail from the real install.
func audit360GateEnv(t *testing.T) {
	t.Helper()
	t.Setenv("SIFT_HOME", t.TempDir())
	t.Setenv("SIFT_POLICY", "")
	t.Setenv("SIFT_ALLOW", "")
	t.Setenv("SIFT_AUDIT_LOG", "")
}

func postAudit360Start(t *testing.T, body string) (*httptest.ResponseRecorder, audit360.StartResponse) {
	t.Helper()
	s := NewServer()
	req := httptest.NewRequest(http.MethodPost, "/api/audit-360", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	var out audit360.StartResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode start response (status %d): %v; body=%s", rec.Code, err, rec.Body.String())
	}
	return rec, out
}

// TestAudit360StartDeniesMetadataTarget is the H-3 regression test: the
// metadata service is the credential-theft path, and the handler used to accept
// it and start a job.
func TestAudit360StartDeniesMetadataTarget(t *testing.T) {
	audit360GateEnv(t)

	rec, out := postAudit360Start(t,
		`{"target_url":"http://169.254.169.254/latest/meta-data/","mode":"passive"}`)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
	if out.JobID != "" {
		t.Fatalf("a denied start must not create a job, got job_id=%q", out.JobID)
	}
	if !strings.Contains(strings.ToLower(out.Error), "metadata") {
		t.Fatalf("error should name the metadata denial, got %q", out.Error)
	}
}

// TestAudit360StartDeniesPrivateTarget covers the other half of the class
// boundary: a private address needs an explicit authorization rule.
func TestAudit360StartDeniesPrivateTarget(t *testing.T) {
	audit360GateEnv(t)

	rec, out := postAudit360Start(t,
		`{"target_url":"http://10.0.0.1/","authorized":true,"mode":"standard","max_duration_sec":10}`)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
	if out.JobID != "" {
		t.Fatalf("a denied start must not create a job, got job_id=%q", out.JobID)
	}
	if !strings.Contains(strings.ToLower(out.Error), "private") {
		t.Fatalf("error should say the target is private, got %q", out.Error)
	}
}

// TestAudit360StartRecordsTheDecision keeps the audit trail honest: a refusal
// is recorded too, in the same hash-chained file the CLI writes.
func TestAudit360StartRecordsTheDecision(t *testing.T) {
	audit360GateEnv(t)

	rec, _ := postAudit360Start(t, `{"target_url":"http://169.254.169.254/","mode":"passive"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}

	n, err := authz.Verify(filepath.Join(os.Getenv("SIFT_HOME"), "audit.jsonl"))
	if err != nil {
		t.Fatalf("audit trail verify: %v", err)
	}
	if n != 1 {
		t.Fatalf("audit entries = %d, want 1 (the denial must be recorded)", n)
	}
}

// TestAudit360GateAllowsTheDemoFlow pins what the gate must not break: the
// demo store is loopback, and a public target needs no ticket for an OpScan.
func TestAudit360GateAllowsTheDemoFlow(t *testing.T) {
	audit360GateEnv(t)

	for _, target := range []string{"http://127.0.0.1:8090/", "http://93.184.216.34/"} {
		out, err := audit360Gate(target)
		if err != nil {
			t.Fatalf("gate(%s): %v", target, err)
		}
		if !out.Allowed {
			t.Fatalf("gate(%s) denied a target the 360° audit must still accept: %+v", target, out)
		}
	}
}
