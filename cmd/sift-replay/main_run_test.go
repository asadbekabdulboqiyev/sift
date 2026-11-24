package main

// main_run_test.go — in-process coverage for the replay CLI entry point.
//
// main() calls os.Exit / log.Fatalf on every failure path, so the harness swaps
// the hooks declared in hooks.go (and cliux.ExitProcess) for sentinel panics.
// Each invocation gets a fresh flag.CommandLine because main() re-registers its
// flags on every call.

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/asadbekabdulboqiyev/sift/internal/authz"
	"github.com/asadbekabdulboqiyev/sift/internal/cliux"
)

// mainExit is the sentinel panic payload carrying the would-be exit code.
type mainExit struct{ code int }

func runReplayMain(t *testing.T, args ...string) (stdout string, code int) {
	t.Helper()
	stdout, _, code = runReplayMainWithStderr(t, args...)
	return stdout, code
}

func runReplayMainWithStderr(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()

	prevArgs, prevStdout, prevStderr, prevFS := os.Args, os.Stdout, os.Stderr, flag.CommandLine
	prevExit, prevFatal, prevCliExit, prevAdmin := exitProcess, fatalf, cliux.ExitProcess, replayAdminBypass
	defer func() {
		os.Args, os.Stdout, os.Stderr, flag.CommandLine = prevArgs, prevStdout, prevStderr, prevFS
		exitProcess, fatalf, cliux.ExitProcess, replayAdminBypass = prevExit, prevFatal, prevCliExit, prevAdmin
	}()

	flag.CommandLine = flag.NewFlagSet("sift-replay", flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)

	dir := t.TempDir()
	outFile, err := os.CreateTemp(dir, "stdout-*")
	if err != nil {
		t.Fatalf("temp stdout: %v", err)
	}
	errFile, err := os.CreateTemp(dir, "stderr-*")
	if err != nil {
		t.Fatalf("temp stderr: %v", err)
	}
	os.Stdout, os.Stderr = outFile, errFile

	os.Args = append([]string{"sift-replay"}, args...)
	exitProcess = func(c int) { panic(mainExit{c}) }
	cliux.ExitProcess = func(c int) { panic(mainExit{c}) }
	fatalf = func(format string, v ...any) {
		fmt.Fprintf(os.Stderr, format+"\n", v...)
		panic(mainExit{1})
	}
	// Never let a developer's admin unlock decide an in-process test case.
	replayAdminBypass = func() bool { return false }

	func() {
		defer func() {
			if r := recover(); r != nil {
				if e, ok := r.(mainExit); ok {
					code = e.code
					return
				}
				panic(r)
			}
		}()
		main()
	}()

	stdout = readTempFile(t, outFile)
	stderr = readTempFile(t, errFile)
	return stdout, stderr, code
}

func readTempFile(t *testing.T, f *os.File) string {
	t.Helper()
	if err := f.Sync(); err != nil {
		t.Fatalf("sync %s: %v", f.Name(), err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("seek %s: %v", f.Name(), err)
	}
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read %s: %v", f.Name(), err)
	}
	_ = f.Close()
	return string(b)
}

// writeReplayPolicy writes a policy naming one target with a ticket, plus the
// audit path for the same run. Both are passed as flags so tests never touch
// the operator's real policy or audit trail.
func writeReplayPolicy(t *testing.T, pattern, ticket string) (policyPath, auditPath string) {
	t.Helper()
	dir := t.TempDir()
	policyPath = filepath.Join(dir, "policy.json")
	auditPath = filepath.Join(dir, "audit.jsonl")
	raw, err := json.Marshal(authz.Policy{
		Mode: authz.ModePermissive,
		Rules: []authz.Rule{
			{Pattern: pattern, Approver: "qa", Ticket: ticket},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return policyPath, auditPath
}

func harWithURLs(urls ...string) string {
	var b strings.Builder
	b.WriteString(`{"log":{"version":"1.2","entries":[`)
	for i, u := range urls {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"startedDateTime":"2025-01-15T10:30:00.000Z","time":1,`+
			`"request":{"method":"GET","url":%q,"headers":[],"queryString":[]},`+
			`"response":{"status":200,"headers":[],"content":{"size":2,"mimeType":"text/plain"}}}`, u)
	}
	b.WriteString(`]}}`)
	return b.String()
}

func TestReplayMainHelp(t *testing.T) {
	if _, code := runReplayMain(t, "--help"); code != 0 {
		t.Errorf("--help exit = %d, want 0", code)
	}
}

func TestReplayMainMissingInput(t *testing.T) {
	if _, code := runReplayMain(t); code != 1 {
		t.Errorf("no args exit = %d, want 1", code)
	}
}

func TestReplayMainFlagErrors(t *testing.T) {
	cases := map[string][]string{
		"bad rate":      {"-input", "x.har", "-rate", "fast"},
		"bad pace":      {"-input", "x.har", "-pace", "warp"},
		"rps without":   {"-input", "x.har", "-pace", "rps"},
		"bad duration":  {"-input", "x.har", "-duration", "soon"},
		"missing keys":  {"-input", "x.har", "-tls-key", "/nope/key", "-tls-cert", "/nope/cert"},
		"bad extension": {"-input", "capture.txt"},
		"missing file":  {"-input", filepath.Join(t.TempDir(), "absent.har")},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			if _, code := runReplayMain(t, args...); code != 1 {
				t.Errorf("%v exit = %d, want 1", args, code)
			}
		})
	}
}

const replayHAR = `{
  "log": {
    "version": "1.2",
    "creator": {"name": "test", "version": "1.0"},
    "entries": [
      {
        "startedDateTime": "2025-01-15T10:30:00.000Z",
        "time": 10.0,
        "request": {
          "method": "GET",
          "url": "https://example.com/api/one",
          "headers": [{"name": "Accept", "value": "application/json"}],
          "queryString": []
        },
        "response": {
          "status": 200,
          "headers": [{"name": "Content-Type", "value": "application/json"}],
          "content": {"size": 2, "mimeType": "application/json", "text": "ok"}
        }
      },
      {
        "startedDateTime": "2025-01-15T10:30:00.100Z",
        "time": 12.0,
        "request": {
          "method": "POST",
          "url": "https://example.com/api/two",
          "headers": [{"name": "Content-Type", "value": "application/json"}],
          "queryString": [],
          "postData": {"mimeType": "application/json", "text": "{\"a\":1}"}
        },
        "response": {
          "status": 201,
          "headers": [],
          "content": {"size": 2, "mimeType": "text/plain", "text": "ok"}
        }
      }
    ]
  }
}`

func TestReplayMainFullRun(t *testing.T) {
	var got atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()

	dir := t.TempDir()
	harPath := filepath.Join(dir, "traffic.har")
	if err := os.WriteFile(harPath, []byte(replayHAR), 0o644); err != nil {
		t.Fatal(err)
	}

	policyPath, auditPath := writeReplayPolicy(t, "127.0.0.1", "CHG-REPLAY")
	out, code := runReplayMain(t,
		"-input", harPath,
		"-pace", "legacy",
		"-rate", "100x",
		"-concurrency", "2",
		"-duration", "30s",
		"-base-url", target.URL,
		"-policy", policyPath,
		"-audit-log", auditPath,
		"-authorized", "CHG-REPLAY",
		"-skip-tls-verify",
		"-follow-redirects",
		"-validate",
		"-assert-status", "200",
		"-assert-regex", "ok",
		"-methods", "GET,POST",
		"-url-pattern", "*",
		"-status", "200,201",
		"-output-json", "replay.json",
		"-output-csv", "latency.csv",
		"-report-dir", dir,
	)
	if code != 0 {
		t.Fatalf("full run exit = %d, want 0\n%s", code, out)
	}
	for _, want := range []string{
		"Loading capture...",
		"Loading HAR:",
		"Loaded 2 packets",
		"Filtered: 2 → 2 packets",
		"REPLAY COMPLETE",
		"JSON report:",
		"CSV report:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if n := got.Load(); n < 2 {
		t.Errorf("target saw %d requests, want at least 2", n)
	}
	for _, name := range []string{"replay.json", "latency.csv"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s not written: %v", name, err)
		}
	}

	// Regression: the CSV export is published atomically with an explicit
	// 0600 mode (previously os.Create left it at 0666 & ~umask, typically 0644).
	csvPath := filepath.Join(dir, "latency.csv")
	info, err := os.Stat(csvPath)
	if err != nil {
		t.Fatalf("stat latency.csv: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("latency.csv mode = %04o, want 0600", perm)
	}
	csvBytes, err := os.ReadFile(csvPath)
	if err != nil {
		t.Fatalf("read latency.csv: %v", err)
	}
	if !strings.HasPrefix(string(csvBytes), "index,latency_ms,status\n") {
		t.Errorf("latency.csv lost its header: %q", csvBytes)
	}

	entries, err := authz.ReadAll(auditPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if len(entries) != 1 || !entries[0].Allowed || entries[0].Action != "replay" {
		t.Errorf("audit records = %+v, want one allowed replay", entries)
	}
}

func TestReplayMainNoDerivableDestination(t *testing.T) {
	dir := t.TempDir()
	harPath := filepath.Join(dir, "traffic.har")
	if err := os.WriteFile(harPath, []byte(replayHAR), 0o644); err != nil {
		t.Fatal(err)
	}
	policyPath, auditPath := writeReplayPolicy(t, "127.0.0.1", "CHG-REPLAY")

	// No --base-url and no --allow-original-destinations: the run must stop
	// before the engine (and before the gate, so no audit record is written).
	out, errOut, code := runReplayMainWithStderr(t,
		"-input", harPath,
		"-policy", policyPath,
		"-audit-log", auditPath,
	)
	if code != 1 {
		t.Fatalf("no-destination exit = %d, want 1\n%s", code, out)
	}
	if !strings.Contains(errOut, "cannot derive any replay destination") {
		t.Errorf("error does not explain the missing destination:\n%s", errOut)
	}
	if strings.Contains(out, "REPLAY COMPLETE") {
		t.Error("engine ran despite having no derivable destination")
	}
	if _, err := os.Stat(auditPath); !os.IsNotExist(err) {
		t.Errorf("audit record written for a run that never reached the gate: %v", err)
	}
}

func TestReplayMainStrictAuditFailureStopsRun(t *testing.T) {
	var hits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	dir := t.TempDir()
	harPath := filepath.Join(dir, "traffic.har")
	if err := os.WriteFile(harPath, []byte(replayHAR), 0o644); err != nil {
		t.Fatal(err)
	}
	// Make the audit parent a regular file so authz.Open cannot succeed.
	badParent := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(badParent, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	policyPath, _ := writeReplayPolicy(t, "127.0.0.1", "CHG-REPLAY")

	_, errOut, code := runReplayMainWithStderr(t,
		"-input", harPath,
		"-base-url", target.URL,
		"-policy", policyPath,
		"-audit-log", filepath.Join(badParent, "audit.jsonl"),
		"-authorized", "CHG-REPLAY",
	)
	if code != 1 {
		t.Fatalf("unwritable audit exit = %d, want 1\n%s", code, errOut)
	}
	if got := hits.Load(); got != 0 {
		t.Errorf("target saw %d requests after an audit failure, want 0", got)
	}
	if !strings.Contains(errOut, "cannot write audit log") {
		t.Errorf("audit failure not explained:\n%s", errOut)
	}
}

func TestReplayMainRefusesCapturedMetadataAndLoopback(t *testing.T) {
	var hits atomic.Int64
	loopback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer loopback.Close()

	dir := t.TempDir()
	harPath := filepath.Join(dir, "traffic.har")
	har := harWithURLs(
		"http://169.254.169.254/latest/meta-data/",
		loopback.URL+"/api",
	)
	if err := os.WriteFile(harPath, []byte(har), 0o644); err != nil {
		t.Fatal(err)
	}
	policyPath, auditPath := writeReplayPolicy(t, "127.0.0.1", "CHG-REPLAY")

	_, errOut, code := runReplayMainWithStderr(t,
		"-input", harPath,
		"-allow-original-destinations",
		"-policy", policyPath,
		"-audit-log", auditPath,
		"-authorized", "CHG-REPLAY",
	)
	if code != 3 {
		t.Fatalf("captured metadata exit = %d, want 3 (authorization denied)\n%s", code, errOut)
	}
	if got := hits.Load(); got != 0 {
		t.Errorf("captured loopback target saw %d requests, want 0", got)
	}
	if !strings.Contains(errOut, "BLOCKED by authorization policy") {
		t.Errorf("denial banner missing:\n%s", errOut)
	}
	if !strings.Contains(strings.ToLower(errOut), "metadata") {
		t.Errorf("denial does not name the metadata path:\n%s", errOut)
	}
	entries, err := authz.ReadAll(auditPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("audit records = %d, want 1", len(entries))
	}
	if entries[0].Action != "replay" || entries[0].Allowed || len(entries[0].Targets) != 2 {
		t.Errorf("audit record = %+v", entries[0])
	}
}

func TestReplayMainRedirectPinWithGateInstalled(t *testing.T) {
	var stolen atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stolen.Add(1)
		_, _ = w.Write([]byte("secret-from-other-port"))
	}))
	defer target.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/steal", http.StatusFound)
	}))
	defer origin.Close()

	dir := t.TempDir()
	harPath := filepath.Join(dir, "traffic.har")
	if err := os.WriteFile(harPath, []byte(harWithURLs(origin.URL+"/start")), 0o644); err != nil {
		t.Fatal(err)
	}
	policyPath, auditPath := writeReplayPolicy(t, "127.0.0.1", "CHG-REPLAY")

	out, code := runReplayMain(t,
		"-input", harPath,
		"-base-url", origin.URL,
		"-follow-redirects",
		"-pace", "legacy",
		"-rate", "100x",
		"-policy", policyPath,
		"-audit-log", auditPath,
		"-authorized", "CHG-REPLAY",
	)
	if code != 0 {
		t.Fatalf("redirect run exit = %d, want 0\n%s", code, out)
	}
	if got := stolen.Load(); got != 0 {
		t.Errorf("cross-port redirect target saw %d requests, want 0", got)
	}
	entries, err := authz.ReadAll(auditPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if len(entries) != 1 || !entries[0].Allowed {
		t.Fatalf("audit records = %+v, want one allowed replay", entries)
	}
}

func TestReplayMainFilterDropsEverything(t *testing.T) {
	dir := t.TempDir()
	harPath := filepath.Join(dir, "traffic.har")
	if err := os.WriteFile(harPath, []byte(replayHAR), 0o644); err != nil {
		t.Fatal(err)
	}

	// DELETE matches nothing: the run must report a filter-empty failure.
	if _, code := runReplayMain(t,
		"-input", harPath,
		"-pace", "legacy",
		"-rate", "100x",
		"-methods", "DELETE",
		"-duration", "5s",
	); code != 1 {
		t.Errorf("empty filter exit = %d, want 1", code)
	}
}
