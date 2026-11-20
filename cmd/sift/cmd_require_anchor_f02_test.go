package main

// cmd_require_anchor_f02_test.go — regression tests for F-02 (2026-11-20).
//
// Before the fix, --require-anchor defaulted to false: an IssuerUnpinned
// certificate or bundle was reported VALID/PASS with exit 0 even with no trust
// store configured. These tests pin the new CLI policy: anchoring is ON by
// default, --allow-unpinned is an explicit opt-out, and an explicit --trust-store
// still works. They run the command functions in-process through the existing
// exitProcess harness, so no binary build and no network are needed.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/asadbekabdulboqiyev/sift/internal/attest"
	"github.com/asadbekabdulboqiyev/sift/internal/certificate"
)

func f02Keypair(t *testing.T) *attest.Keypair {
	t.Helper()
	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	return kp
}

func f02WriteCertificate(t *testing.T, kp *attest.Keypair) string {
	t.Helper()
	a := certificate.NewFromPentest("https://example.test", "full", "TechCorp", "test",
		12, "B", "PASS", certificate.Counts{High: 1}, 9,
		"2026-11-20T08:00:00Z", "2026-11-20T08:05:00Z", "5m0s")
	a.Findings = []certificate.Finding{{ID: "H-1", Severity: "high", Title: "High"}}
	cert, err := certificate.Issue(kp, a, "", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	raw, err := cert.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	path := filepath.Join(t.TempDir(), "cert.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write certificate: %v", err)
	}
	return path
}

func f02WriteStore(t *testing.T, kp *attest.Keypair, path string) {
	t.Helper()
	store := attest.NewTrustStore()
	if err := store.Add(kp.Public, "TechCorp"); err != nil {
		t.Fatalf("store.Add: %v", err)
	}
	if err := store.Save(path); err != nil {
		t.Fatalf("store.Save: %v", err)
	}
}

// (a) no trust store + default policy => exit 1, INVALID, no VALID claim.
func TestF02CertificateNoStoreDefaultIsInvalid(t *testing.T) {
	t.Setenv("SIFT_HOME", t.TempDir())
	certPath := f02WriteCertificate(t, f02Keypair(t))

	res := runCommandFn(t, cmdCertificate, "certificate", certPath)
	if res.code != 1 {
		t.Fatalf("default certificate verify exit = %d, want 1\nstdout:\n%s\nstderr:\n%s", res.code, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stderr, "INVALID") {
		t.Fatalf("failure is not marked INVALID:\n%s", res.stderr)
	}
	if strings.Contains(res.stdout, "VALID —") {
		t.Fatalf("unpinned signer was reported VALID:\n%s", res.stdout)
	}
	if !strings.Contains(res.stderr, "--allow-unpinned") {
		t.Fatalf("failure does not offer the explicit opt-out:\n%s", res.stderr)
	}
}

// (b) explicit opt-out => VALID with exit 0, and the report says why.
func TestF02CertificateAllowUnpinnedIsValid(t *testing.T) {
	t.Setenv("SIFT_HOME", t.TempDir())
	certPath := f02WriteCertificate(t, f02Keypair(t))

	// The flag also has to work after the positional file name: cmdCertificate
	// re-parses trailing flags.
	res := runCommandFn(t, cmdCertificate, "certificate", certPath, "--allow-unpinned")
	if res.code != 0 {
		t.Fatalf("--allow-unpinned exit = %d, want 0\nstdout:\n%s\nstderr:\n%s", res.code, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, "VALID —") || strings.Contains(res.stdout, "(pinned)") {
		t.Fatalf("unexpected certificate report:\n%s", res.stdout)
	}
	if !strings.Contains(res.stdout, "F-02 opt-out") {
		t.Fatalf("report does not disclose the opt-out:\n%s", res.stdout)
	}

	// Machine-readable output agrees: internally valid, issuer explicitly
	// unpinned.
	res = runCommandFn(t, cmdCertificate, "certificate", certPath, "--allow-unpinned", "--json")
	if res.code != 0 {
		t.Fatalf("--allow-unpinned --json exit = %d, want 0\nstdout:\n%s\nstderr:\n%s", res.code, res.stdout, res.stderr)
	}
	var got certificateVerifyJSON
	if err := json.Unmarshal([]byte(res.stdout), &got); err != nil {
		t.Fatalf("--json is not JSON: %v\n%s", err, res.stdout)
	}
	if !got.Valid || got.IssuerTrust != string(attest.IssuerUnpinned) {
		t.Fatalf("report = %+v, want valid with issuer_trust=%s", got, attest.IssuerUnpinned)
	}
}

// (c) an explicit trust store that pins the signer => VALID with exit 0.
func TestF02CertificateExplicitTrustStoreStillValid(t *testing.T) {
	t.Setenv("SIFT_HOME", t.TempDir())
	kp := f02Keypair(t)
	certPath := f02WriteCertificate(t, kp)
	storePath := filepath.Join(t.TempDir(), "trust.json")
	f02WriteStore(t, kp, storePath)

	res := runCommandFn(t, cmdCertificate, "certificate", certPath, "--trust-store", storePath)
	if res.code != 0 {
		t.Fatalf("pinned certificate exit = %d, want 0\nstdout:\n%s\nstderr:\n%s", res.code, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, "VALID —") || !strings.Contains(res.stdout, "TechCorp (pinned)") {
		t.Fatalf("pinned issuer not reported:\n%s", res.stdout)
	}

	// The default $SIFT_HOME/trust.json path still resolves the anchor.
	defaultStore := filepath.Join(os.Getenv("SIFT_HOME"), "trust.json")
	f02WriteStore(t, kp, defaultStore)
	res = runCommandFn(t, cmdCertificate, "certificate", certPath)
	if res.code != 0 || !strings.Contains(res.stdout, "TechCorp (pinned)") {
		t.Fatalf("default store exit = %d, want pinned VALID\nstdout:\n%s\nstderr:\n%s", res.code, res.stdout, res.stderr)
	}
}

// Contradictory flags are a usage error, not a silent weaken, on both commands.
func TestF02ConflictingFlagsFailClosed(t *testing.T) {
	t.Setenv("SIFT_HOME", t.TempDir())
	kp := f02Keypair(t)
	certPath := f02WriteCertificate(t, kp)
	storePath := filepath.Join(t.TempDir(), "trust.json")
	f02WriteStore(t, kp, storePath)

	res := runCommandFn(t, cmdCertificate, "certificate", certPath,
		"--trust-store", storePath, "--require-anchor", "--allow-unpinned")
	if res.code != 1 || !strings.Contains(res.stderr, "conflicts") {
		t.Fatalf("certificate conflict exit = %d, want 1 with conflict error\nstderr:\n%s", res.code, res.stderr)
	}
	// The trailing-flag re-parse must not bypass the conflict check.
	res = runCommandFn(t, cmdCertificate, "certificate", certPath, "--allow-unpinned", "--require-anchor")
	if res.code != 1 || !strings.Contains(res.stderr, "conflicts") {
		t.Fatalf("certificate trailing conflict exit = %d, want 1 with conflict error\nstderr:\n%s", res.code, res.stderr)
	}

	coord, worker := vbFreshKeys(t)
	bundlePath, samplesPath, _ := vbWritePack(t, coord, worker, "w1", vbRecords("w1", 5))
	res = runCommandFn(t, cmdVerify, "verify", "--bundle", bundlePath, "--samples", samplesPath,
		"--require-anchor", "--allow-unpinned")
	if res.code != 1 || !strings.Contains(res.stderr, "conflicts") {
		t.Fatalf("verify conflict exit = %d, want 1 with conflict error\nstderr:\n%s", res.code, res.stderr)
	}
}

// The verify half of F-02: same policy, same exit codes.
func TestF02VerifyAnchorPolicy(t *testing.T) {
	t.Setenv("SIFT_HOME", t.TempDir())
	coord, worker := vbFreshKeys(t)
	bundlePath, samplesPath, _ := vbWritePack(t, coord, worker, "w1", vbRecords("w1", 5))

	res := runCommandFn(t, cmdVerify, "verify", "--bundle", bundlePath, "--samples", samplesPath)
	if res.code != 1 {
		t.Fatalf("default verify exit = %d, want 1\nstdout:\n%s\nstderr:\n%s", res.code, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stderr, "INVALID") || strings.Contains(res.stdout, "PASS —") {
		t.Fatalf("unpinned bundle not rejected:\nstdout:\n%s\nstderr:\n%s", res.stdout, res.stderr)
	}

	res = runCommandFn(t, cmdVerify, "verify", "--bundle", bundlePath, "--samples", samplesPath, "--allow-unpinned")
	if res.code != 0 || !strings.Contains(res.stdout, "PASS —") {
		t.Fatalf("--allow-unpinned verify exit = %d, want 0\nstdout:\n%s\nstderr:\n%s", res.code, res.stdout, res.stderr)
	}

	storePath := filepath.Join(t.TempDir(), "trust.json")
	store := attest.NewTrustStore()
	if err := store.Add(coord.Public, "TechCorp"); err != nil {
		t.Fatalf("store.Add: %v", err)
	}
	if err := store.Save(storePath); err != nil {
		t.Fatalf("store.Save: %v", err)
	}
	res = runCommandFn(t, cmdVerify, "verify", "--bundle", bundlePath, "--samples", samplesPath,
		"--trust-store", storePath)
	if res.code != 0 || !strings.Contains(res.stdout, "(pinned)") {
		t.Fatalf("pinned bundle exit = %d, want 0\nstdout:\n%s\nstderr:\n%s", res.code, res.stdout, res.stderr)
	}
}

// Pure policy helper: default true, opt-out false, contradiction rejected.
func TestF02ResolveAnchorPolicy(t *testing.T) {
	cases := []struct {
		name                       string
		require, allow, requireSet bool
		want                       bool
		wantErr                    bool
	}{
		{"default", true, false, false, true, false},
		{"opt-out alone", true, true, false, false, false},
		{"both explicit", true, true, true, false, true},
		{"explicit false plus opt-out", false, true, true, false, false},
		{"explicit anchor", true, false, true, true, false},
		{"explicit false", false, false, true, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveAnchorPolicy(tc.require, tc.allow, tc.requireSet)
			if (err != nil) != tc.wantErr {
				t.Fatalf("resolveAnchorPolicy(%v, %v, %v) error = %v, wantErr %v", tc.require, tc.allow, tc.requireSet, err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Fatalf("resolveAnchorPolicy(%v, %v, %v) = %v, want %v", tc.require, tc.allow, tc.requireSet, got, tc.want)
			}
		})
	}
}

// User-facing help has to describe the new default and the opt-out.
func TestF02HelpReflectsNewDefault(t *testing.T) {
	res := runCommandFn(t, cmdCertificate, "certificate", "--explain")
	for _, want := range []string{"F-02", "--allow-unpinned", "INVALID", "by default"} {
		if !strings.Contains(res.stdout, want) {
			t.Fatalf("certificate --explain is missing %q:\n%s", want, res.stdout)
		}
	}

	res = runCommandFn(t, cmdVerify, "verify", "--help")
	for _, want := range []string{"F-02", "--allow-unpinned", "DEFAULT"} {
		if !strings.Contains(res.stderr, want) {
			t.Fatalf("verify --help is missing %q:\n%s", want, res.stderr)
		}
	}
}
