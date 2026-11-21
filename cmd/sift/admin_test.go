package main

// admin_test.go drives `Sift admin` in-process so the command dispatch, flag
// parsing, output and state transitions are covered by the test binary itself.
// All state lives under SIFT_HOME; no test touches the operator's admin code.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/adminlock"
	"github.com/asadbekabdulboqiyev/sift/internal/authz"
)

func adminCLITestHome(t *testing.T) {
	t.Helper()
	scanCLIHome(t)
	// Inherited state must not change what these tests exercise.
	t.Setenv("SIFT_AUDIT_LOG", "")
	t.Setenv("SIFT_ADMIN_CODE", "")
}

func adminCLITestStore(t *testing.T) *adminlock.Store {
	t.Helper()
	s, err := adminlock.Open(adminlock.DefaultPath())
	if err != nil {
		t.Fatalf("open admin state: %v", err)
	}
	return s
}

func adminCLITestCode(t *testing.T, s *adminlock.Store) string {
	t.Helper()
	code, err := s.Code()
	if err != nil {
		t.Fatalf("read admin code: %v", err)
	}
	return code
}

func adminCLITestStatus(t *testing.T, s *adminlock.Store) adminlock.Status {
	t.Helper()
	st, err := s.Status()
	if err != nil {
		t.Fatalf("read admin status: %v", err)
	}
	return st
}

func adminCLITestAuditRules(t *testing.T, path string) []string {
	t.Helper()
	n, err := authz.Verify(path)
	if err != nil {
		t.Fatalf("audit trail failed verification: %v", err)
	}
	if n == 0 {
		t.Fatal("expected at least one audit entry, got none")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit trail: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != n {
		t.Fatalf("audit lines = %d, verified entries = %d", len(lines), n)
	}

	rules := make([]string, 0, n)
	for _, line := range lines {
		var entry authz.Entry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("decode audit entry: %v", err)
		}
		if entry.Actor != "local-admin" || !entry.Allowed {
			t.Fatalf("unexpected admin audit actor/verdict: %q, allowed=%v", entry.Actor, entry.Allowed)
		}
		rules = append(rules, entry.Rule)
	}
	return rules
}

func TestAdminCodePrintsCurrentCode(t *testing.T) {
	// Arrange.
	adminCLITestHome(t)
	store := adminCLITestStore(t)
	want := adminCLITestCode(t, store)

	// Act.
	res := runCommandFn(t, cmdAdmin, "admin", "code")

	// Assert.
	if res.code != 0 {
		t.Fatalf("admin code exit = %d, want 0\nstderr:\n%s", res.code, res.stderr)
	}
	if got := strings.TrimSpace(res.stdout); got != want {
		t.Fatal("admin code did not print the stored code")
	}
}

func TestAdminStatusReportsInactiveAndActiveWindows(t *testing.T) {
	// Arrange.
	adminCLITestHome(t)
	store := adminCLITestStore(t)
	code := adminCLITestCode(t, store)

	// Act: no subcommand defaults to status.
	inactive := runCommandFn(t, cmdAdmin, "admin")

	// Assert.
	if inactive.code != 0 {
		t.Fatalf("admin status exit = %d, want 0\nstderr:\n%s", inactive.code, inactive.stderr)
	}
	if !strings.Contains(inactive.stdout, "bypass      off") {
		t.Fatalf("fresh window was not reported as closed:\n%s", inactive.stdout)
	}
	if !strings.Contains(inactive.stdout, adminlock.DefaultPath()) {
		t.Fatalf("status did not name the code file:\n%s", inactive.stdout)
	}

	// Arrange: open a bounded window directly on the isolated store.
	if _, err := store.Unlock(code, 5*time.Minute); err != nil {
		t.Fatalf("open admin window: %v", err)
	}

	// Act.
	active := runCommandFn(t, cmdAdmin, "admin", "status")

	// Assert.
	if active.code != 0 {
		t.Fatalf("admin status exit = %d, want 0\nstderr:\n%s", active.code, active.stderr)
	}
	if !strings.Contains(active.stdout, "bypass      ON") {
		t.Fatalf("open window was not reported:\n%s", active.stdout)
	}
	if !strings.Contains(active.stdout, "scans run WITHOUT an authorization ticket") {
		t.Fatalf("status did not explain the bypass effect:\n%s", active.stdout)
	}
}

func TestAdminRotateReplacesCodeAndClosesWindow(t *testing.T) {
	// Arrange.
	adminCLITestHome(t)
	store := adminCLITestStore(t)
	oldCode := adminCLITestCode(t, store)
	if _, err := store.Unlock(oldCode, 30*time.Minute); err != nil {
		t.Fatalf("open admin window: %v", err)
	}
	if !adminCLITestStatus(t, store).Active {
		t.Fatal("precondition: window must be active before rotate")
	}

	// Act.
	res := runCommandFn(t, cmdAdmin, "admin", "rotate")

	// Assert.
	if res.code != 0 {
		t.Fatalf("admin rotate exit = %d, want 0\nstderr:\n%s", res.code, res.stderr)
	}
	newCode := adminCLITestCode(t, store)
	if newCode == oldCode {
		t.Fatal("rotate left the admin code unchanged")
	}
	if ok, err := store.Verify(oldCode); err != nil || ok {
		t.Fatalf("old code still verifies after rotate: %v, %v", ok, err)
	}
	if ok, err := store.Verify(newCode); err != nil || !ok {
		t.Fatalf("new code does not verify after rotate: %v, %v", ok, err)
	}
	if st := adminCLITestStatus(t, store); st.Active || !st.ExpiresAt.IsZero() {
		t.Fatalf("rotate left a bypass window open: %+v", st)
	}
}

func TestAdminUnlockOpensWindowAndAuditsIt(t *testing.T) {
	// Arrange.
	adminCLITestHome(t)
	store := adminCLITestStore(t)
	code := adminCLITestCode(t, store)

	// Act.
	res := runCommandFn(t, cmdAdmin, "admin", "unlock", "--code", code, "--minutes", "5")

	// Assert.
	if res.code != 0 {
		t.Fatalf("admin unlock exit = %d, want 0\nstderr:\n%s", res.code, res.stderr)
	}
	if !strings.Contains(res.stdout, "Admin bypass is ON") {
		t.Fatalf("unlock did not report the open window:\n%s", res.stdout)
	}
	st := adminCLITestStatus(t, store)
	if !st.Active {
		t.Fatalf("window is not active after unlock: %+v", st)
	}
	if st.SecondsLeft < 299 || st.SecondsLeft > 300 {
		t.Fatalf("unlock window = %d seconds, want ~300", st.SecondsLeft)
	}
	rules := adminCLITestAuditRules(t, authz.DefaultAuditPath())
	if len(rules) != 1 || rules[0] != "admin-unlock" {
		t.Fatalf("audit rules = %v, want [admin-unlock]", rules)
	}
}

func TestAdminUnlockRejectsWrongCodeWithoutOpening(t *testing.T) {
	// Arrange.
	adminCLITestHome(t)
	store := adminCLITestStore(t)
	code := adminCLITestCode(t, store)
	wrong := "WRONGCODE"
	if wrong == code {
		t.Fatal("precondition: wrong code collided with the generated code")
	}

	// Act.
	res := runCommandFn(t, cmdAdmin, "admin", "unlock", "--code", wrong)

	// Assert.
	if res.code != 1 {
		t.Fatalf("unlock with wrong code exit = %d, want 1\nstdout:\n%s", res.code, res.stdout)
	}
	if !strings.Contains(res.stderr, "admin code does not match") {
		t.Fatalf("wrong code was not explained:\n%s", res.stderr)
	}
	if st := adminCLITestStatus(t, store); st.Active {
		t.Fatalf("wrong code opened a bypass window: %+v", st)
	}
	if _, err := os.Stat(authz.DefaultAuditPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed unlock wrote an audit log: %v", err)
	}
}

func TestAdminUnlockRequiresACode(t *testing.T) {
	// Arrange.
	adminCLITestHome(t)
	store := adminCLITestStore(t)

	// Act: no flag, no environment and empty stdin.
	res := runCommandFn(t, cmdAdmin, "admin", "unlock")

	// Assert.
	if res.code != 1 {
		t.Fatalf("unlock without a code exit = %d, want 1\nstdout:\n%s", res.code, res.stdout)
	}
	if !strings.Contains(res.stderr, "no admin code given") {
		t.Fatalf("missing code was not explained:\n%s", res.stderr)
	}
	if st := adminCLITestStatus(t, store); st.Active {
		t.Fatalf("missing code opened a bypass window: %+v", st)
	}
}

func TestAdminUnlockRejectsInvalidFlags(t *testing.T) {
	// Arrange.
	adminCLITestHome(t)

	// Act.
	res := runCommandFn(t, cmdAdmin, "admin", "unlock", "--minutes", "soon")

	// Assert.
	if res.code != 1 {
		t.Fatalf("invalid flag exit = %d, want 1\nstdout:\n%s", res.code, res.stdout)
	}
	if !strings.Contains(res.stderr, "invalid value") {
		t.Fatalf("invalid flag was not explained:\n%s", res.stderr)
	}
	if _, err := os.Stat(adminlock.DefaultPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("flag parsing created admin state: %v", err)
	}
}

func TestAdminLockClosesWindowAndAuditsIt(t *testing.T) {
	// Arrange.
	adminCLITestHome(t)
	store := adminCLITestStore(t)
	code := adminCLITestCode(t, store)
	if _, err := store.Unlock(code, 30*time.Minute); err != nil {
		t.Fatalf("open admin window: %v", err)
	}

	// Act.
	res := runCommandFn(t, cmdAdmin, "admin", "lock")

	// Assert.
	if res.code != 0 {
		t.Fatalf("admin lock exit = %d, want 0\nstderr:\n%s", res.code, res.stderr)
	}
	if !strings.Contains(res.stdout, "Admin bypass is OFF") {
		t.Fatalf("lock did not report the closed window:\n%s", res.stdout)
	}
	st := adminCLITestStatus(t, store)
	if st.Active || !st.ExpiresAt.IsZero() || !st.UnlockedAt.IsZero() {
		t.Fatalf("lock left bypass state behind: %+v", st)
	}
	rules := adminCLITestAuditRules(t, authz.DefaultAuditPath())
	if len(rules) != 1 || rules[0] != "admin-lock" {
		t.Fatalf("audit rules = %v, want [admin-lock]", rules)
	}
}

func TestAdminUnknownSubcommandExitsTwo(t *testing.T) {
	// Arrange.
	adminCLITestHome(t)

	// Act.
	res := runCommandFn(t, cmdAdmin, "admin", "not-a-command")

	// Assert.
	if res.code != 2 {
		t.Fatalf("unknown subcommand exit = %d, want 2\nstdout:\n%s", res.code, res.stdout)
	}
	if !strings.Contains(res.stderr, "unknown admin subcommand") {
		t.Fatalf("unknown subcommand was not named:\n%s", res.stderr)
	}
	if !strings.Contains(res.stderr, "usage: Sift admin") {
		t.Fatalf("unknown subcommand did not print usage:\n%s", res.stderr)
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("SIFT_HOME"), "admin.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unknown subcommand created admin state: %v", err)
	}
}
