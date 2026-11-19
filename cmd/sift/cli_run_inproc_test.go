package main

// cli_run_inproc_test.go — in-process coverage for `Sift run`.
//
// The load engine talks to a loopback httptest server, so the whole happy path
// (plan, run, report, save) executes for real without leaving the machine. One
// virtual user for one second keeps the suite fast.

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/asadbekabdulboqiyev/sift/internal/config"
)

// runTestServer starts a loopback server that answers every request 200.
func runTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok"}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// deadLoopbackURL returns a loopback URL every request to it fails on.
//
// The port is held for the whole test by a listener that accepts the
// connection and resets it immediately, so the client sees the same
// connection_error a closed port produces.
//
// The obvious implementation — bind an ephemeral port, close it, use the freed
// number — has a race: any other program on the host can take that port in
// the window between the close and the first request. Under a parallel test
// run that happens often enough to matter: the "unreachable target" starts
// answering normally, the load test reports a green run, and the safety net
// under test never fires. Holding the port removes the race entirely.
func deadLoopbackURL(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return // the listener was closed by the test cleanup
			}
			// Linger 0 makes Close send a RST instead of a FIN, so the
			// client fails the request instead of waiting for a response.
			if tcp, ok := c.(*net.TCPConn); ok {
				_ = tcp.SetLinger(0)
			}
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })

	return fmt.Sprintf("http://127.0.0.1:%d/", port)
}

// runArgs builds the common flag set a load-test invocation needs so the
// authorization layer stays inside the throwaway home.
func runArgs(home string, extra ...string) []string {
	base := []string{
		"run",
		"--policy", filepath.Join(home, "authz.json"),
		"--audit-log", filepath.Join(home, "audit.jsonl"),
		"--allow-private",
	}
	return append(base, extra...)
}

func TestInprocRunHelpAndVersion(t *testing.T) {
	scanCLIHome(t)

	res := runCLIInProcess(t, "run", "--help")
	if res.code != 0 {
		t.Fatalf("help exit = %d, want 0 (stderr: %s)", res.code, res.stderr)
	}
	if !strings.Contains(res.stderr, "Sift run") || !strings.Contains(res.stderr, "FLAGS") {
		t.Errorf("help text incomplete: %q", res.stderr)
	}

	res = runCLIInProcess(t, "run", "--version")
	if res.code != 0 {
		t.Fatalf("version exit = %d, want 0", res.code)
	}
	if !strings.Contains(res.stdout, "Sift v"+buildVersion) {
		t.Errorf("stdout = %q, want the version", res.stdout)
	}
}

func TestInprocRunUsageAndConfigErrors(t *testing.T) {
	home := scanCLIHome(t)
	cases := []struct {
		name string
		args []string
		code int
		want string
	}{
		{"no target", runArgs(home), 1, "either --config or --url is required"},
		{"missing config", runArgs(home, "--config", filepath.Join(home, "nope.yaml")), 1, "error:"},
		{"bad mode", runArgs(home, "--url", "http://127.0.0.1:1/", "--mode", "bogus"), 1, "invalid --mode"},
		{"bad tls fingerprint", runArgs(home, "--url", "http://127.0.0.1:1/", "--tls-fingerprint", "netscape"), 1, "unknown -tls-fingerprint"},
		{"bad header", runArgs(home, "--url", "http://127.0.0.1:1/", "--header", "no-equals"), 2, "header"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			res := runCLIInProcess(t, tc.args...)
			if res.code != tc.code {
				t.Fatalf("exit = %d, want %d (stderr: %s)", res.code, tc.code, res.stderr)
			}
			if !strings.Contains(res.stderr, tc.want) {
				t.Errorf("stderr = %q, want %q", res.stderr, tc.want)
			}
		})
	}
}

func TestInprocRunHelpers(t *testing.T) {
	// defaultWorkerID returns "hostname-pid".
	got := defaultWorkerID()
	if got == "" {
		t.Fatalf("defaultWorkerID = %q, want non-empty", got)
	}

	// coCorrectionGate: unpaced → message; paced steady/soak → empty.
	if msg := coCorrectionGate(&config.Scenario{}, 0); msg == "" {
		t.Errorf("coCorrectionGate(unpaced) = empty, want a message")
	}
	sc := &config.Scenario{Profile: config.Profile{Type: config.ProfileSteady}}
	if msg := coCorrectionGate(sc, 500); msg != "" {
		t.Errorf("coCorrectionGate(steady,paced) = %q, want empty", msg)
	}
	sc = &config.Scenario{Profile: config.Profile{Type: config.ProfileSpike}}
	if msg := coCorrectionGate(sc, 500); msg == "" {
		t.Errorf("coCorrectionGate(spike,paced) = empty, want a message")
	}

	// millisInterval formats the bounds.
	if got := millisInterval(0, 1_500_000_000); got != "[0.000ms, 1500.000ms]" {
		t.Errorf("millisInterval = %q", got)
	}
}
