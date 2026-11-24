package gate

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/asadbekabdulboqiyev/sift/internal/authz"
)

func gateTestConfig(t *testing.T, rules ...authz.Rule) Config {
	t.Helper()
	dir := t.TempDir()
	policy := filepath.Join(dir, "policy.json")
	raw, err := json.Marshal(authz.Policy{Mode: authz.ModePermissive, Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policy, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return Config{
		PolicyPath:  policy,
		AuditPath:   filepath.Join(dir, "audit.jsonl"),
		AdminBypass: func() bool { return false },
	}
}

func TestReplayOperationUsesSharedMetadataRule(t *testing.T) {
	cfg := gateTestConfig(t)
	for _, op := range []authz.Operation{authz.OpLoadTest, authz.OpPentest, authz.OpReplay} {
		out, err := Evaluate(op, []string{"http://169.254.169.254/latest/meta-data/"}, cfg)
		if err != nil {
			t.Fatalf("op %v: %v", op, err)
		}
		if out.Allowed {
			t.Errorf("op %v allowed instance metadata", op)
		}
		if !strings.Contains(strings.ToLower(out.Reason), "metadata") {
			t.Errorf("op %v reason = %q", op, out.Reason)
		}
	}
	if got := OperationName(authz.OpReplay); got != "replay" {
		t.Errorf("OperationName(OpReplay) = %q, want replay", got)
	}
}

func TestReplayApprovesTicketedLoopbackIPs(t *testing.T) {
	cfg := gateTestConfig(t, authz.Rule{
		Pattern: "127.0.0.1", Approver: "qa", Ticket: "CHG-1",
	})
	cfg.Authorized = "CHG-1"

	out, err := Evaluate(authz.OpReplay, []string{"http://127.0.0.1:8080/replay"}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Allowed || len(out.ApprovedIPs) != 1 || !out.ApprovedIPs[0].Equal(netParseLoopback(t)) {
		t.Fatalf("outcome = %+v", out)
	}

	cfg.Authorized = ""
	out, err = Evaluate(authz.OpReplay, []string{"http://127.0.0.1:8080/replay"}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if out.Allowed || !strings.Contains(out.Reason, "--authorized") {
		t.Fatalf("unticketed outcome = %+v", out)
	}
}

func netParseLoopback(t *testing.T) net.IP {
	t.Helper()
	ip := net.ParseIP("127.0.0.1")
	if ip == nil {
		t.Fatal("ParseIP(127.0.0.1) failed")
	}
	return ip
}
