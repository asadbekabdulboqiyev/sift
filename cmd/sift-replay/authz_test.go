package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/asadbekabdulboqiyev/sift/internal/authz"
	"github.com/asadbekabdulboqiyev/sift/internal/gate"
)

// testReplayGate builds an isolated shared-gate config: a real policy file,
// a real audit path and a pinned (inactive) admin unlock.
func testReplayGate(t *testing.T, rules ...authz.Rule) gate.Config {
	t.Helper()
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	raw, err := json.Marshal(authz.Policy{Mode: authz.ModePermissive, Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return gate.Config{
		PolicyPath:  policyPath,
		AuditPath:   filepath.Join(dir, "audit.jsonl"),
		StrictAudit: true,
		AdminBypass: func() bool { return false },
	}
}

func pinReplayGate(t *testing.T, cfg gate.Config) {
	t.Helper()
	prevCfg, prevBypass := replayGateConfig, replayAdminBypass
	prevExit, prevFatal := exitProcess, fatalf
	t.Cleanup(func() {
		replayGateConfig, replayAdminBypass = prevCfg, prevBypass
		exitProcess, fatalf = prevExit, prevFatal
	})
	replayAdminBypass = cfg.AdminBypass
	replayGateConfig = cfg
	// A denial in a unit test must fail the test, not terminate the runner.
	exitProcess = func(c int) { panic(mainExit{c}) }
	fatalf = func(format string, v ...any) { panic(mainExit{1}) }
}

// TestReplayDialControl verifies that the CLI derives its socket control from
// the shared gate's ticket approval and refuses every other peer, including a
// DNS rebind to a different public address.
func TestReplayDialControl(t *testing.T) {
	cfg := testReplayGate(t, authz.Rule{
		Pattern: "127.0.0.1", Approver: "qa", Ticket: "CHG-REPLAY",
	})
	cfg.Authorized = "CHG-REPLAY"
	pinReplayGate(t, cfg)

	control := replayDialControl([]string{"http://127.0.0.1:8080/replay"})
	if control == nil {
		t.Fatal("approved replay produced no socket control")
	}
	if err := control("tcp", "127.0.0.1:8080", nil); err != nil {
		t.Fatalf("approved loopback peer refused: %v", err)
	}
	for _, peer := range []string{
		"169.254.169.254:80", // instance metadata
		"127.0.0.2:8080",     // loopback rebind
		"93.184.216.34:443",  // public rebind: exact-IP pin only
		"not-an-ip:80",       // unparseable peer fails closed
	} {
		if err := control("tcp", peer, nil); err == nil {
			t.Errorf("peer %q was not refused by the approved set", peer)
		}
	}

	entries, err := authz.ReadAll(cfg.AuditPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("audit records = %d, want exactly one per run", len(entries))
	}
	if entries[0].Action != "replay" {
		t.Errorf("audit action = %q, want replay", entries[0].Action)
	}
	if !entries[0].Allowed || len(entries[0].IPs) != 1 || entries[0].IPs[0] != "127.0.0.1" {
		t.Errorf("audit decision = %+v", entries[0])
	}
}

// TestReplayGateRefusesMetadataAndUnticketedLoopback covers the two capture
// cases that must never leave the machine: HAR entries pointing at instance
// metadata, and entries pointing at the runner itself without a ticket.
func TestReplayGateRefusesMetadataAndUnticketedLoopback(t *testing.T) {
	cfg := testReplayGate(t)
	for _, target := range []string{
		"http://169.254.169.254/latest/meta-data",
		"http://metadata.google.internal/",
	} {
		out, err := gate.Evaluate(authz.OpReplay, []string{target}, cfg)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		if out.Allowed {
			t.Errorf("%s was allowed", target)
		}
		if !strings.Contains(strings.ToLower(out.Reason), "metadata") {
			t.Errorf("%s reason does not name metadata: %q", target, out.Reason)
		}
	}

	out, err := gate.Evaluate(authz.OpReplay, []string{"http://127.0.0.1:8080/api"}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if out.Allowed {
		t.Fatal("unticketed loopback replay was allowed")
	}
	if !strings.Contains(out.Reason, "--authorized") {
		t.Errorf("reason does not explain the ticket requirement: %q", out.Reason)
	}

	// Even the local admin unlock never opens the credential-theft path.
	cfg.AdminBypass = func() bool { return true }
	out, err = gate.Evaluate(authz.OpReplay, []string{"http://169.254.169.254/"}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if out.Allowed {
		t.Fatal("admin bypass unlocked instance metadata")
	}
}

// TestCLIsShareGateEvaluation is an anti-drift check: both entry points must
// delegate to internal/gate, not keep a local copy of the security decision.
func TestCLIsShareGateEvaluation(t *testing.T) {
	for _, rel := range []string{"authz.go", filepath.Join("..", "sift", "cmd_authz.go")} {
		src, err := os.ReadFile(rel)
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		if !strings.Contains(string(src), "gate.Enforce(") {
			t.Errorf("%s no longer delegates to gate.Enforce", rel)
		}
	}
	src, err := os.ReadFile("authz.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "gate.Enforce(authz.OpReplay") {
		t.Error("replay CLI does not enforce the replay operation through the shared gate")
	}
}
