package main

// cmd_trust_test.go — black-box tests for the issuer trust store and the
// verification commands that consult it.
//
// These drive the shipped binary, not the library: the point of the trust
// anchor is what an operator sees at the command line. The two cases that
// matter most are TestCLIVerifyRejectsForgedBundle (a self-consistent bundle
// from an unknown key must fail) and TestCLIVerifyPinnedBundlePasses (the same
// bundle must pass once its issuer is enrolled), because together they show the
// check is doing real work rather than failing everything.

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/asadbekabdulboqiyev/sift/internal/attest"
	"github.com/asadbekabdulboqiyev/sift/internal/certificate"
)

// runCLIEnv is runCLI with extra environment variables, so a test can point
// SIFT_HOME at a temporary directory and leave the developer's real trust store
// untouched.
//
// Keys present in env are removed from the inherited environment first: a
// duplicated variable in an exec environment is resolved inconsistently across
// platforms, so an override has to be the only copy to be reliable.
func runCLIEnv(t *testing.T, env []string, args ...string) cliResult {
	t.Helper()
	if cliBuildErr != nil {
		t.Fatalf("CLI build failed: %v", cliBuildErr)
	}
	if cliBin == "" {
		t.Fatal("CLI binary was not built")
	}

	overridden := make(map[string]bool, len(env))
	for _, kv := range env {
		if k, _, ok := strings.Cut(kv, "="); ok {
			overridden[k] = true
		}
	}
	base := make([]string, 0, len(os.Environ())+len(env))
	for _, kv := range os.Environ() {
		if k, _, ok := strings.Cut(kv, "="); ok && overridden[k] {
			continue
		}
		base = append(base, kv)
	}

	cmd := exec.Command(cliBin, args...)
	cmd.Env = append(base, env...)
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()

	code := 0
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("run %v: %v", args, err)
		}
		code = ee.ExitCode()
	}
	return cliResult{stdout: out.String(), stderr: errb.String(), code: code}
}

// writeKeypair writes kp as PEM and returns the path.
func writeKeypair(t *testing.T, kp *attest.Keypair, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := attest.SaveKeypairPEM(kp, path); err != nil {
		t.Fatalf("SaveKeypairPEM: %v", err)
	}
	return path
}

func TestCLITrustAddListCheckRemove(t *testing.T) {
	home := t.TempDir()
	env := []string{"SIFT_HOME=" + home}
	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	keyPath := writeKeypair(t, kp, "school.pem")
	fp := attest.Fingerprint(kp.Public)

	// An empty store is a valid starting point, not an error.
	res := runCLIEnv(t, env, "trust", "list")
	if res.code != 0 {
		t.Fatalf("trust list on a fresh home exit = %d, want 0\nstderr:\n%s", res.code, res.stderr)
	}
	if !strings.Contains(res.stdout, "does not exist yet") {
		t.Fatalf("fresh store was not reported as absent:\n%s", res.stdout)
	}

	res = runCLIEnv(t, env, "trust", "add", "--key", keyPath, "--label", "School #12")
	if res.code != 0 {
		t.Fatalf("trust add exit = %d\nstderr:\n%s", res.code, res.stderr)
	}
	if !strings.Contains(res.stdout, fp) {
		t.Fatalf("add did not print the fingerprint:\n%s", res.stdout)
	}
	storePath := filepath.Join(home, "trust.json")
	if _, err := os.Stat(storePath); err != nil {
		t.Fatalf("default store was not written at %s: %v", storePath, err)
	}

	// The key is accepted as bare hex too, and re-adding must not duplicate.
	res = runCLIEnv(t, env, "trust", "add", "--key", attest.PublicKeyHex(kp.Public), "--label", "Renamed")
	if res.code != 0 {
		t.Fatalf("trust add (hex) exit = %d\nstderr:\n%s", res.code, res.stderr)
	}

	res = runCLIEnv(t, env, "trust", "list", "--json")
	if res.code != 0 {
		t.Fatalf("trust list --json exit = %d\nstderr:\n%s", res.code, res.stderr)
	}
	var listed struct {
		Format  string `json:"format"`
		Store   string `json:"store"`
		Count   int    `json:"count"`
		Issuers []struct {
			Key         string `json:"key"`
			Fingerprint string `json:"fingerprint"`
			Label       string `json:"label"`
		} `json:"issuers"`
	}
	if err := json.Unmarshal([]byte(res.stdout), &listed); err != nil {
		t.Fatalf("trust list --json is not JSON: %v\n%s", err, res.stdout)
	}
	if listed.Format != attest.TrustStoreFormat {
		t.Fatalf("format = %q", listed.Format)
	}
	if listed.Count != 1 || len(listed.Issuers) != 1 {
		t.Fatalf("two spellings of one key produced %d issuers:\n%s", listed.Count, res.stdout)
	}
	if listed.Issuers[0].Key != attest.PublicKeyHex(kp.Public) {
		t.Fatalf("stored key = %q", listed.Issuers[0].Key)
	}
	if listed.Issuers[0].Fingerprint != fp {
		t.Fatalf("fingerprint = %q, want %q", listed.Issuers[0].Fingerprint, fp)
	}

	if res := runCLIEnv(t, env, "trust", "check", "--key", attest.PublicKeyHex(kp.Public)); res.code != 0 {
		t.Fatalf("trust check on a pinned key exit = %d, want 0\n%s%s", res.code, res.stdout, res.stderr)
	}

	res = runCLIEnv(t, env, "trust", "remove", "--key", attest.PublicKeyHex(kp.Public))
	if res.code != 0 {
		t.Fatalf("trust remove exit = %d\nstderr:\n%s", res.code, res.stderr)
	}
	if res := runCLIEnv(t, env, "trust", "check", "--key", attest.PublicKeyHex(kp.Public)); res.code != 1 {
		t.Fatalf("trust check after removal exit = %d, want 1\n%s", res.code, res.stdout)
	}
	if res := runCLIEnv(t, env, "trust", "remove", "--key", attest.PublicKeyHex(kp.Public)); res.code != 1 {
		t.Fatalf("removing an absent key exit = %d, want 1", res.code)
	}
}

func TestCLITrustRejectsMalformedKey(t *testing.T) {
	env := []string{"SIFT_HOME=" + t.TempDir()}
	res := runCLIEnv(t, env, "trust", "add", "--key", "not-a-key")
	if res.code == 0 {
		t.Fatalf("a malformed key was accepted:\n%s", res.stdout)
	}
	if !strings.Contains(res.stderr, "64-character hex") && !strings.Contains(res.stderr, "neither an existing PEM") {
		t.Fatalf("error does not explain what a key looks like:\n%s", res.stderr)
	}
	if _, err := os.Stat(filepath.Join(env[0][len("SIFT_HOME="):], "trust.json")); err == nil {
		t.Fatal("a failed add left a store behind")
	}
}

func TestCLITrustAddFromCertRejectsNonCertificate(t *testing.T) {
	env := []string{"SIFT_HOME=" + t.TempDir()}
	bundle := filepath.Join(t.TempDir(), "bundle.json")
	if err := os.WriteFile(bundle, []byte(`{"format":"vpmp/v1"}`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	res := runCLIEnv(t, env, "trust", "add", "--from-cert", bundle, "--label", "x")
	if res.code == 0 {
		t.Fatalf("a non-certificate was accepted as a pinning source:\n%s", res.stdout)
	}
}

// TestCLIVerifyPinnedBundlePasses is the positive half: the same bundle that is
// rejected below passes once its issuer is in the store.
func TestCLIVerifyPinnedBundlePasses(t *testing.T) {
	coord, worker := vbFreshKeys(t)
	bundlePath, samplesPath, _ := vbWritePack(t, coord, worker, "w1", vbRecords("w1", 5))

	storePath := filepath.Join(t.TempDir(), "trust.json")
	store := attest.NewTrustStore()
	if err := store.Add(coord.Public, "TechCorp"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := store.Save(storePath); err != nil {
		t.Fatalf("Save: %v", err)
	}

	res := runCLI(t, "verify", "--bundle", bundlePath, "--samples", samplesPath,
		"--trust-store", storePath, "--require-anchor", "--json")
	if res.code != 0 {
		t.Fatalf("pinned bundle exit = %d, want 0\nstdout:\n%s\nstderr:\n%s", res.code, res.stdout, res.stderr)
	}
	var got verifyJSON
	if err := json.Unmarshal([]byte(res.stdout), &got); err != nil {
		t.Fatalf("--json is not JSON: %v\n%s", err, res.stdout)
	}
	if !got.Valid || got.IssuerTrust != string(attest.IssuerPinned) {
		t.Fatalf("report = %+v, want valid with issuer_trust=pinned", got)
	}
	if got.IssuerLabel != "TechCorp" {
		t.Fatalf("issuer_label = %q, want TechCorp", got.IssuerLabel)
	}
	if got.IssuerKey != attest.PublicKeyHex(coord.Public) {
		t.Fatalf("issuer_key = %q", got.IssuerKey)
	}
}

// TestCLIVerifyRejectsForgedBundle is the claim in executable form: a bundle
// that is internally perfect but signed by a key the verifier has not accepted
// must exit 1 and say why.
func TestCLIVerifyRejectsForgedBundle(t *testing.T) {
	coord, worker := vbFreshKeys(t)
	bundlePath, samplesPath, _ := vbWritePack(t, coord, worker, "w1", vbRecords("w1", 5))

	school, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	storePath := filepath.Join(t.TempDir(), "trust.json")
	store := attest.NewTrustStore()
	if err := store.Add(school.Public, "School #12"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := store.Save(storePath); err != nil {
		t.Fatalf("Save: %v", err)
	}

	res := runCLI(t, "verify", "--bundle", bundlePath, "--samples", samplesPath, "--trust-store", storePath)
	if res.code != 1 {
		t.Fatalf("forged bundle exit = %d, want 1\nstdout:\n%s", res.code, res.stdout)
	}
	if !strings.Contains(res.stdout, "issuer-trust") {
		t.Fatalf("failure does not name the issuer-trust check:\n%s", res.stdout)
	}
	if !strings.Contains(res.stdout, "UNTRUSTED") {
		t.Fatalf("failure does not mark the issuer untrusted:\n%s", res.stdout)
	}

	// The same run in JSON must be machine-readable and equally decisive.
	res = runCLI(t, "verify", "--bundle", bundlePath, "--samples", samplesPath,
		"--trust-store", storePath, "--json")
	if res.code != 1 {
		t.Fatalf("forged bundle (json) exit = %d, want 1", res.code)
	}
	var got verifyJSON
	if err := json.Unmarshal([]byte(res.stdout), &got); err != nil {
		t.Fatalf("--json is not JSON: %v\n%s", err, res.stdout)
	}
	if got.Valid {
		t.Fatal("forged bundle reported valid")
	}
	if got.IssuerTrust != string(attest.IssuerUntrusted) {
		t.Fatalf("issuer_trust = %q, want untrusted", got.IssuerTrust)
	}
}

// TestCLIVerifyRequireAnchorUsesDefaultStore checks the flagless workflow:
// enrol an issuer once in $SIFT_HOME, then gate on --require-anchor alone.
func TestCLIVerifyRequireAnchorUsesDefaultStore(t *testing.T) {
	coord, worker := vbFreshKeys(t)
	bundlePath, samplesPath, _ := vbWritePack(t, coord, worker, "w1", vbRecords("w1", 5))

	home := t.TempDir()
	env := []string{"SIFT_HOME=" + home}

	// Nothing enrolled yet: --require-anchor must fail closed with guidance.
	res := runCLIEnv(t, env, "verify", "--bundle", bundlePath, "--samples", samplesPath, "--require-anchor")
	if res.code != 1 {
		t.Fatalf("--require-anchor without a store exit = %d, want 1\nstdout:\n%s", res.code, res.stdout)
	}
	if !strings.Contains(res.stderr, "Sift trust add") {
		t.Fatalf("failure does not tell the operator how to fix it:\n%s", res.stderr)
	}

	keyPath := writeKeypair(t, coord, "coord.pem")
	if res := runCLIEnv(t, env, "trust", "add", "--key", keyPath, "--label", "TechCorp"); res.code != 0 {
		t.Fatalf("trust add exit = %d\n%s", res.code, res.stderr)
	}

	res = runCLIEnv(t, env, "verify", "--bundle", bundlePath, "--samples", samplesPath, "--require-anchor")
	if res.code != 0 {
		t.Fatalf("pinned bundle with default store exit = %d, want 0\nstdout:\n%s\nstderr:\n%s", res.code, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, "(pinned)") {
		t.Fatalf("human output does not report the pinned issuer:\n%s", res.stdout)
	}
}

// TestCLIVerifyTrustStoreErrorsFailClosed checks that a bad --trust-store path
// cannot be mistaken for "no anchor required".
func TestCLIVerifyTrustStoreErrorsFailClosed(t *testing.T) {
	coord, worker := vbFreshKeys(t)
	bundlePath, samplesPath, _ := vbWritePack(t, coord, worker, "w1", vbRecords("w1", 5))

	res := runCLI(t, "verify", "--bundle", bundlePath, "--samples", samplesPath,
		"--trust-store", filepath.Join(t.TempDir(), "missing.json"))
	if res.code != 1 {
		t.Fatalf("missing trust store exit = %d, want 1\nstdout:\n%s", res.code, res.stdout)
	}
}

// writeCertificate issues a valid ss-cert/v1 certificate with kp and writes it
// as JSON, returning the path.
func writeCertificate(t *testing.T, kp *attest.Keypair, name string) string {
	t.Helper()
	a := certificate.NewFromPentest("https://example.test", "full", "TechCorp", "test",
		12, "B", "PASS", certificate.Counts{High: 1, Low: 1}, 9,
		"2026-11-07T08:00:00Z", "2026-11-07T08:05:00Z", "5m0s")
	a.Findings = []certificate.Finding{
		{ID: "H-1", Severity: "high", Title: "High"},
		{ID: "L-1", Severity: "low", Title: "Low"},
	}
	cert, err := certificate.Issue(kp, a, "", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	raw, err := cert.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write certificate: %v", err)
	}
	return path
}

// TestCLICertificateRequireAnchor is the certificate half of the trust anchor:
// the same file is VALID on its own, refused under --require-anchor without a
// store, accepted once its signer is enrolled, and refused when a different
// signer is the only one pinned.
func TestCLICertificateRequireAnchor(t *testing.T) {
	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	certPath := writeCertificate(t, kp, "cert.json")
	home := t.TempDir()
	env := []string{"SIFT_HOME=" + home}

	// Historical behaviour: a certificate verifies without any trust setup.
	res := runCLIEnv(t, env, "certificate", certPath)
	if res.code != 0 {
		t.Fatalf("plain verify exit = %d, want 0\nstderr:\n%s", res.code, res.stderr)
	}
	if !strings.Contains(res.stdout, "VALID") {
		t.Fatalf("plain verify did not report VALID:\n%s", res.stdout)
	}
	if !strings.Contains(res.stdout, "unpinned") {
		t.Fatalf("plain verify did not disclose that the issuer is unpinned:\n%s", res.stdout)
	}

	// --require-anchor with nothing enrolled fails closed.
	res = runCLIEnv(t, env, "certificate", certPath, "--require-anchor")
	if res.code != 1 {
		t.Fatalf("--require-anchor without a store exit = %d, want 1\nstdout:\n%s", res.code, res.stdout)
	}

	// Enrol the real signer: it must pass and be named.
	keyPath := writeKeypair(t, kp, "issuer.pem")
	if res := runCLIEnv(t, env, "trust", "add", "--key", keyPath, "--label", "TechCorp"); res.code != 0 {
		t.Fatalf("trust add exit = %d\n%s", res.code, res.stderr)
	}
	res = runCLIEnv(t, env, "certificate", certPath, "--require-anchor")
	if res.code != 0 {
		t.Fatalf("pinned certificate exit = %d, want 0\nstdout:\n%s\nstderr:\n%s", res.code, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, "TechCorp (pinned)") {
		t.Fatalf("pinned certificate did not name the issuer:\n%s", res.stdout)
	}

	// JSON is machine-readable and carries the identity fields separately.
	res = runCLIEnv(t, env, "certificate", certPath, "--json")
	if res.code != 0 {
		t.Fatalf("--json exit = %d, want 0\nstderr:\n%s", res.code, res.stderr)
	}
	var got certificateVerifyJSON
	if err := json.Unmarshal([]byte(res.stdout), &got); err != nil {
		t.Fatalf("--json is not JSON: %v\n%s", err, res.stdout)
	}
	if !got.Valid || got.IssuerTrust != string(attest.IssuerPinned) {
		t.Fatalf("report = %+v, want valid with issuer_trust=pinned", got)
	}
	if got.IssuerLabel != "TechCorp" || got.SignerKey != attest.PublicKeyHex(kp.Public) {
		t.Fatalf("identity fields are wrong: %+v", got)
	}

	// A store that pins only someone else must refuse this certificate.
	other, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	otherStore := filepath.Join(t.TempDir(), "other.json")
	store := attest.NewTrustStore()
	if err := store.Add(other.Public, "Other"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := store.Save(otherStore); err != nil {
		t.Fatalf("Save: %v", err)
	}
	res = runCLI(t, "certificate", certPath, "--trust-store", otherStore)
	if res.code != 1 {
		t.Fatalf("certificate from an unpinned signer exit = %d, want 1\nstdout:\n%s", res.code, res.stdout)
	}
	if !strings.Contains(res.stderr, "not in the trust store") {
		t.Fatalf("rejection does not explain the trust failure:\n%s", res.stderr)
	}
}
