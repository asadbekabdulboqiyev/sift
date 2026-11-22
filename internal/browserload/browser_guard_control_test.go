package browserload

// browser_guard_control_test.go proves the independent Chromium load-test
// stack can be put behind the same guard proxy as browser crawl mode. It
// inspects the allocator options, so no Chrome binary is needed.

import (
	"syscall"
	"testing"
)

func TestNewRunnerWithControlInstallsGuardFlags(t *testing.T) {
	r, err := NewRunnerWithControl(func(_, _ string, _ syscall.RawConn) error { return nil })
	if err != nil {
		t.Fatalf("NewRunnerWithControl: %v", err)
	}
	if r == nil {
		t.Fatal("NewRunnerWithControl returned a nil runner")
	}
	want := len(defaultRunnerOptions()) + 4
	if len(r.opts) != want {
		t.Fatalf("allocator options = %d, want %d (4 guard flags added)", len(r.opts), want)
	}
	if r.close == nil {
		t.Fatal("controlled runner has no closer")
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close must be idempotent: %v", err)
	}
}

func TestNewRunnerWithNilControlKeepsDirectBehavior(t *testing.T) {
	r, err := NewRunnerWithControl(nil)
	if err != nil {
		t.Fatalf("NewRunnerWithControl(nil): %v", err)
	}
	if got, want := len(r.opts), len(defaultRunnerOptions()); got != want {
		t.Fatalf("nil control added %d flags, want 0", got-want)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("nil-control Close: %v", err)
	}
}

func TestNewRunnerCloseIsSafeWithoutGuard(t *testing.T) {
	r := NewRunner()
	if err := r.Close(); err != nil {
		t.Fatalf("uncontrolled runner Close: %v", err)
	}
	var nilRunner *Runner
	if err := nilRunner.Close(); err != nil {
		t.Fatalf("nil runner Close: %v", err)
	}
}
