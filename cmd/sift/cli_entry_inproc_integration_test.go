//go:build integration

package main

import (
	"bufio"
	"github.com/asadbekabdulboqiyev/sift/internal/dashboard"
	"github.com/asadbekabdulboqiyev/sift/internal/engine"
	prom "github.com/asadbekabdulboqiyev/sift/internal/metrics/exporter"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInprocRunSubCommandSibling(t *testing.T) {
	skipUnlessPOSIXExec(t)

	writeExecSibling(t, "Sift-test-ok", "#!/bin/sh\nexit 0\n")
	res := runCommandFn(t, func() { runSubCommand("Sift-test-ok", []string{"--flag"}) }, "x")
	if res.code != 0 {
		t.Fatalf("sibling success: exit = %d, want 0 (stderr: %s)", res.code, res.stderr)
	}

	writeExecSibling(t, "Sift-test-fail", "#!/bin/sh\nexit 7\n")
	res = runCommandFn(t, func() { runSubCommand("Sift-test-fail", nil) }, "x")
	if res.code != 7 {
		t.Fatalf("sibling failure: exit = %d, want 7 (stderr: %s)", res.code, res.stderr)
	}
}

// TestInprocRunSubCommandGoFallback replaces `go` on PATH: the missing sibling
// falls through to `go run`, which the stub answers without compiling anything.
func TestInprocRunSubCommandGoFallback(t *testing.T) {
	skipUnlessPOSIXExec(t)
	dir := t.TempDir()
	goStub := "#!/bin/sh\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "go"), []byte(goStub), 0o755); err != nil {
		t.Fatalf("write go stub: %v", err)
	}
	t.Setenv("PATH", dir)

	res := runCommandFn(t, func() { runSubCommand("Sift-no-such-subcommand-xyz", nil) }, "x")
	if res.code != 0 {
		t.Fatalf("fallback success: exit = %d, want 0 (stderr: %s)", res.code, res.stderr)
	}

	if err := os.WriteFile(filepath.Join(dir, "go"), []byte("#!/bin/sh\nexit 4\n"), 0o755); err != nil {
		t.Fatalf("rewrite go stub: %v", err)
	}
	res = runCommandFn(t, func() { runSubCommand("Sift-no-such-subcommand-xyz", nil) }, "x")
	if res.code != 4 {
		t.Fatalf("fallback failure: exit = %d, want 4 (stderr: %s)", res.code, res.stderr)
	}
	if !strings.Contains(res.stderr, "Build with: go build") {
		t.Errorf("stderr = %q, want the build hint", res.stderr)
	}
}

// TestInprocSubCommandWrappers drives the five one-line dispatchers. Each
// finds the sibling script it names, so the real sub-binaries are never built.
func TestInprocSubCommandWrappers(t *testing.T) {
	skipUnlessPOSIXExec(t)
	cases := []struct {
		name string
		fn   func()
	}{
		{"Sift-replay", cmdReplay},
		{"Sift-scan", cmdScan},
		{"Sift-dashboard", cmdDashboard},
		{"Sift-master", cmdMaster},
		{"Sift-worker", cmdWorker},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			writeExecSibling(t, tc.name, "#!/bin/sh\nexit 0\n")
			res := runCommandFn(t, tc.fn, tc.name, "--help")
			if res.code != 0 {
				t.Fatalf("exit = %d, want 0 (stderr: %s)", res.code, res.stderr)
			}
		})
	}
}

func TestInprocStreamTelemetry(t *testing.T) {
	srv := okServer(t)
	sc, err := quickScenario("t", srv.URL, "GET", "", headerFlags{},
		"steady", 1, 1, 0, 0, 0, 0, 0, 0, 0, 2, true)
	if err != nil {
		t.Fatalf("quickScenario: %v", err)
	}
	eng, err := engine.New(sc)
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}

	t.Run("nil metrics", func(t *testing.T) {
		stop := make(chan struct{})
		go func() {
			time.Sleep(550 * time.Millisecond)
			close(stop)
		}()
		streamTelemetry(dashboard.NewServer(), eng, sc, nil, stop)
	})

	t.Run("with metrics", func(t *testing.T) {
		stop := make(chan struct{})
		go func() {
			time.Sleep(550 * time.Millisecond)
			close(stop)
		}()
		streamTelemetry(dashboard.NewServer(), eng, sc, prom.NewMetrics(), stop)
	})
}

func TestInprocInteractiveCLIRun(t *testing.T) {
	scanCLIHome(t)
	t.Chdir(t.TempDir())
	withHistoryFile(t)
	srv := okServer(t)

	stdin := "1\n" + srv.URL + "\n1\n1\n"
	res := driveCommand(t, stdin, interactivePicker)
	if res.code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr tail: %s)", res.code, tail(res.stderr, 1200))
	}
	if !strings.Contains(res.stdout, "Running load test") {
		t.Errorf("stdout = %q, want the run notice", res.stdout)
	}
	if !strings.Contains(res.stderr, "Reports written:") {
		t.Errorf("stderr = %q, want the reports notice", res.stderr)
	}
}

func TestInprocInteractiveWizardExpertRun(t *testing.T) {
	scanCLIHome(t)
	t.Chdir(t.TempDir())
	withHistoryFile(t)
	srv := okServer(t)

	// Expert flow: mode 2, URL, GET, no headers, 1 user, 1s, steady profile,
	// unlimited RPS, 1s timeout, no keep-alive, no capture, no gate, name,
	// confirm.
	lines := []string{
		"2", srv.URL, "", "", "1", "1", "1", "0", "1", "n", "0", "n", "e2e", "y",
	}
	stdin := strings.Join(lines, "\n") + "\n"

	res := driveCommand(t, stdin, func() {
		interactiveWizard(bufio.NewReader(os.Stdin))
	})
	if res.code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr tail: %s)", res.code, tail(res.stderr, 1200))
	}
	if !strings.Contains(res.stdout, "Running load test") {
		t.Errorf("stdout = %q, want the run notice", res.stdout)
	}
	if !strings.Contains(res.stderr, "Reports written:") {
		t.Errorf("stderr = %q, want the reports notice", res.stderr)
	}
}
