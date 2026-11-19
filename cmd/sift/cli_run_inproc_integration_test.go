//go:build integration

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInprocRunHappyPath(t *testing.T) {
	home := scanCLIHome(t)
	reportDir := filepath.Join(t.TempDir(), "reports")
	srv := runTestServer(t)

	args := runArgs(home,
		"--url", srv.URL+"/health",
		"--users", "1",
		"--duration", "1",
		"--timeout", "2",
		"--quiet",
		"--pre-warm",
		"--pre-warm-conns", "1",
		"--timeline",
		"--report-dir", reportDir,
	)
	res := runCLIInProcess(t, args...)
	if res.code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", res.code, res.stderr)
	}
	for _, want := range []string{"WARNING: Sift is a load testing tool", "Sift v" + buildVersion, "Reports written:"} {
		if !strings.Contains(res.stderr, want) {
			t.Errorf("stderr missing %q:\n%s", want, res.stderr)
		}
	}
	entries, err := os.ReadDir(reportDir)
	if err != nil {
		t.Fatalf("read report dir: %v", err)
	}
	var json, txt, csv bool
	for _, e := range entries {
		switch filepath.Ext(e.Name()) {
		case ".json":
			json = true
		case ".txt":
			txt = true
		case ".csv":
			csv = true
		}
	}
	if !json || !txt || !csv {
		t.Errorf("reports: json=%v txt=%v csv=%v (want all three)", json, txt, csv)
	}
}

func TestInprocRunPacedWithCoordinatedOmission(t *testing.T) {
	home := scanCLIHome(t)
	srv := runTestServer(t)

	res := runCLIInProcess(t, runArgs(home,
		"--url", srv.URL,
		"--users", "1",
		"--duration", "1",
		"--target-rps", "20",
		"--coordinated-omission",
		"--no-http2",
		"--quiet",
		"--report-dir", t.TempDir(),
	)...)
	if res.code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", res.code, res.stderr)
	}
}

func TestInprocRunCoordinatedOmissionWarning(t *testing.T) {
	home := scanCLIHome(t)
	srv := runTestServer(t)

	res := runCLIInProcess(t, runArgs(home,
		"--url", srv.URL,
		"--users", "1",
		"--duration", "1",
		"--coordinated-omission",
		"--quiet",
		"--report-dir", t.TempDir(),
	)...)
	if res.code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", res.code, res.stderr)
	}
	if !strings.Contains(res.stderr, "--coordinated-omission has no effect without pacing") {
		t.Errorf("stderr = %q, want the pacing warning", res.stderr)
	}
}

func TestInprocRunSLAFailureExitsTwo(t *testing.T) {
	home := scanCLIHome(t)
	srv := runTestServer(t)

	res := runCLIInProcess(t, runArgs(home,
		"--url", srv.URL,
		"--users", "1",
		"--duration", "1",
		"--quiet",
		"--expect-p99-ms", "0.000001",
		"--report-dir", t.TempDir(),
	)...)
	if res.code != 2 {
		t.Fatalf("exit = %d, want 2 (stderr: %s)", res.code, res.stderr)
	}
	if !strings.Contains(res.stderr, "SLA gate FAILED") {
		t.Errorf("stderr = %q, want the SLA gate message", res.stderr)
	}
}

func TestInprocRunAllRequestsFailExitsOne(t *testing.T) {
	home := scanCLIHome(t)
	// A port nothing listens on: every request fails, which the safety net
	// must surface as exit 1 instead of a green run.
	dead := deadLoopbackURL(t)

	res := runCLIInProcess(t, runArgs(home,
		"--url", dead,
		"--users", "1",
		"--duration", "1",
		"--timeout", "1",
		"--quiet",
		"--report-dir", t.TempDir(),
	)...)
	if res.code != 1 {
		t.Fatalf("exit = %d, want 1 (stderr: %s)", res.code, res.stderr)
	}
	if !strings.Contains(res.stderr, "100% of requests failed") {
		t.Errorf("stderr = %q, want the unreachable-target warning", res.stderr)
	}
}

func TestInprocRunEvidenceBundle(t *testing.T) {
	home := scanCLIHome(t)
	srv := runTestServer(t)
	dir := t.TempDir()
	bundle := filepath.Join(dir, "bundle.json")

	res := runCLIInProcess(t, runArgs(home,
		"--url", srv.URL,
		"--users", "1",
		"--duration", "1",
		"--quiet",
		"--emit-bundle", bundle,
		"--bundle-worker", "test-worker",
		"--report-dir", filepath.Join(dir, "reports"),
	)...)
	if res.code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", res.code, res.stderr)
	}
	data, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	if !strings.Contains(string(data), "vpmp/v1") {
		t.Errorf("bundle = %q, want a vpmp/v1 document", data)
	}
	if _, err := os.Stat(strings.TrimSuffix(bundle, ".json") + ".samples.jsonl"); err != nil {
		t.Errorf("samples sidecar missing: %v", err)
	}
}
