package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditActorFromContext(t *testing.T) {
	const subject = "oidc:engineer@example.test"
	ctx := WithPrincipalAndRoles(t.Context(), subject, []string{"engineer"})
	if got := auditActor(ctx); got != subject {
		t.Fatalf("auditActor with principal = %q, want %q", got, subject)
	}
}

func TestAuditActorBareContext(t *testing.T) {
	// With no principal the helper must return "" so authz can fall back to
	// currentUser() instead of recording a fabricated subject.
	if got := auditActor(t.Context()); got != "" {
		t.Fatalf("auditActor without principal = %q, want empty", got)
	}
}

// TestAuditActorOnScanEntry drives a real scan endpoint through the auth
// middleware and checks that the decision in SIFT_AUDIT_LOG is attributed to
// the injected caller. The metadata target is always denied and needs no DNS,
// so the whole path (gate -> audit -> refusal) runs without network traffic.
func TestAuditActorOnScanEntry(t *testing.T) {
	s := owaspTestServer(t) // isolates SIFT_HOME, policy and audit via t.Setenv
	audit := filepath.Join(t.TempDir(), "audit.jsonl")
	t.Setenv("SIFT_AUDIT_LOG", audit)

	const subject = "oidc:auditor@example.test"
	s.SetAuthMiddleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(WithPrincipalAndRoles(r.Context(), subject, nil)))
		})
	})

	req := httptest.NewRequest(http.MethodPost, "/api/owasp/scan",
		strings.NewReader(`{"target":"http://169.254.169.254/"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req) // through ServeHTTP so the auth middleware runs
	if rec.Code != http.StatusForbidden {
		t.Fatalf("metadata scan status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}

	raw, err := os.ReadFile(audit)
	if err != nil {
		t.Fatalf("read SIFT_AUDIT_LOG: %v", err)
	}
	if !strings.Contains(string(raw), `"actor":"`+subject+`"`) {
		t.Errorf("audit log has no actor %q: %s", subject, raw)
	}

	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 1 {
		t.Fatalf("audit log has %d entries, want 1: %s", len(lines), raw)
	}
	var entry struct {
		Actor   string `json:"actor"`
		Action  string `json:"action"`
		Allowed bool   `json:"allowed"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("decode audit entry: %v\n%s", err, lines[0])
	}
	if entry.Actor != subject {
		t.Errorf("audit actor = %q, want %q", entry.Actor, subject)
	}
	if entry.Action != "scan" {
		t.Errorf("audit action = %q, want scan", entry.Action)
	}
	if entry.Allowed {
		t.Error("audit entry allowed a metadata target")
	}
}
