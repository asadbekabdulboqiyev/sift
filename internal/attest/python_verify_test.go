package attest

// python_verify_test.go — the cross-implementation contract, enforced.
//
// The Go verifier and the standalone Python verifier (verify/standalone/
// sift_verify.py) share no code. That is the entire point of the Python script:
// "trust our verifier" is not a security claim, so a second implementation must
// reach the same verdict from the same bytes.
//
// Two implementations that are only compared by hand drift apart. This file
// makes the comparison part of the test suite: a real signed bundle produced by
// this package is handed to the Python verifier, and the test fails if the two
// disagree — on a clean pack, on a tampered pack, or on the issuer-trust check.
//
// The tests skip (never pass silently) when python3 is unavailable, because a
// missing interpreter is not evidence about the format.

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const pythonVerifierPath = "../../verify/standalone/sift_verify.py"

// pythonReport mirrors the --json output of the standalone verifier.
type pythonReport struct {
	Valid  bool `json:"valid"`
	Format string
	Checks []struct {
		Check  string `json:"check"`
		Status string `json:"status"`
		Detail string `json:"detail"`
	} `json:"checks"`
}

func (r pythonReport) failures() []string {
	var out []string
	for _, c := range r.Checks {
		if c.Status == "FAIL" {
			out = append(out, c.Check+": "+c.Detail)
		}
	}
	return out
}

// requirePython skips the test when no interpreter is available. It returns the
// interpreter path and the verifier script path.
func requirePython(t *testing.T) (string, string) {
	t.Helper()
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not installed: cannot cross-check the standalone verifier")
	}
	script := filepath.Clean(pythonVerifierPath)
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("standalone verifier is missing at %s: %v", script, err)
	}
	return py, script
}

// writePack saves the fixture as bundle.json plus one sidecar file holding every
// worker's records. It returns both paths.
func writePack(t *testing.T, b Bundle, samples map[string][]Record) (string, string) {
	t.Helper()
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := SaveBundle(b, bundlePath); err != nil {
		t.Fatalf("SaveBundle: %v", err)
	}

	// One sidecar for the whole run: the Python verifier groups records by
	// worker id, which is exactly how a real pack is shipped.
	ids := make([]string, 0, len(samples))
	for id := range samples {
		ids = append(ids, id)
	}
	sortStrings(ids)
	var all []Record
	for _, id := range ids {
		all = append(all, samples[id]...)
	}

	samplesPath := filepath.Join(dir, "bundle.samples.jsonl")
	f, err := os.Create(samplesPath)
	if err != nil {
		t.Fatalf("create sidecar: %v", err)
	}
	if err := WriteSamples(f, all); err != nil {
		_ = f.Close()
		t.Fatalf("WriteSamples: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close sidecar: %v", err)
	}
	return bundlePath, samplesPath
}

// runPython executes the standalone verifier and decodes its JSON report. A
// non-zero exit is expected for invalid packs, so only a report that cannot be
// parsed is fatal.
func runPython(t *testing.T, py, script string, args ...string) (pythonReport, int) {
	t.Helper()
	full := append([]string{script, "--json"}, args...)
	cmd := exec.Command(py, full...)
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()

	code := 0
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("run %s: %v", script, err)
		}
		code = ee.ExitCode()
	}

	var rep pythonReport
	if e := json.Unmarshal([]byte(out.String()), &rep); e != nil {
		t.Fatalf("standalone verifier did not emit a JSON report (exit %d): %v\nstdout: %s\nstderr: %s",
			code, e, out.String(), errb.String())
	}
	return rep, code
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// TestStandalonePythonVerifierAgreesOnCleanPack is the core contract: a bundle
// this package produced must be VALID to an implementation that has never seen
// this code, and every check the script performs must pass.
func TestStandalonePythonVerifierAgreesOnCleanPack(t *testing.T) {
	py, script := requirePython(t)

	b, samples, coord := newFixture(t, false)
	bundlePath, samplesPath := writePack(t, b, samples)
	issuer := hex.EncodeToString(coord.Public)

	rep, code := runPython(t, py, script,
		"--bundle", bundlePath,
		"--samples", samplesPath,
		"--trust-key", issuer,
		"--require-anchor",
	)
	if code != 0 {
		t.Fatalf("standalone verifier rejected a valid pack (exit %d): %v", code, rep.failures())
	}
	if !rep.Valid {
		t.Fatalf("standalone verifier reported invalid: %v", rep.failures())
	}
	if fails := rep.failures(); len(fails) != 0 {
		t.Fatalf("unexpected failures: %v", fails)
	}

	// The check names are a published contract too: if the Go side gains a
	// check the script does not know about, this list is where it shows up.
	want := []string{
		"bundle-digest",
		"bundle-signature",
		"issuer-trust",
		"aggregate",
		"aggregate-rate",
		"integrity",
	}
	seen := map[string]bool{}
	for _, c := range rep.Checks {
		seen[c.Check] = true
	}
	for _, name := range want {
		if !seen[name] {
			t.Errorf("standalone verifier never ran %q; checks: %v", name, seen)
		}
	}
}

// TestStandalonePythonVerifierDetectsTamper proves the cross-check has teeth: a
// single altered latency in the sidecar must flip the verdict, exactly as the Go
// verifier does, and the failure must name the Merkle root.
func TestStandalonePythonVerifierDetectsTamper(t *testing.T) {
	py, script := requirePython(t)

	b, samples, coord := newFixture(t, false)
	bundlePath, samplesPath := writePack(t, b, samples)
	issuer := hex.EncodeToString(coord.Public)

	raw, err := os.ReadFile(samplesPath)
	if err != nil {
		t.Fatalf("read sidecar: %v", err)
	}
	// Bump the first record's latency by one nanosecond. The line stays valid
	// JSON and the record stays valid on its own; only the committed Merkle
	// root can notice.
	tampered := strings.Replace(string(raw), `"latency_ns":1000000`, `"latency_ns":1000001`, 1)
	if tampered == string(raw) {
		t.Fatalf("fixture did not contain the expected latency to tamper with:\n%s", raw)
	}
	if err := os.WriteFile(samplesPath, []byte(tampered), 0o600); err != nil {
		t.Fatalf("write tampered sidecar: %v", err)
	}

	rep, code := runPython(t, py, script,
		"--bundle", bundlePath,
		"--samples", samplesPath,
		"--trust-key", issuer,
		"--require-anchor",
	)
	if code != 1 {
		t.Fatalf("standalone verifier exit %d, want 1 for a tampered pack", code)
	}
	if rep.Valid {
		t.Fatal("standalone verifier called a tampered pack valid")
	}
	joined := strings.Join(rep.failures(), "\n")
	if !strings.Contains(joined, "commit-root") {
		t.Fatalf("tamper was not attributed to the Merkle root:\n%s", joined)
	}

	// The Go verifier must reach the same conclusion from the same files.
	loaded, err := LoadBundle(bundlePath)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	recs, _, err := LoadSamples(samplesPath, DefaultSampleLoadOptions())
	if err != nil {
		t.Fatalf("LoadSamples: %v", err)
	}
	res := VerifyWith(loaded, recs, VerifyOptions{SkipCICheck: true})
	if res.Valid {
		t.Fatal("Go verifier called the same tampered pack valid: the two implementations disagree")
	}
}

// TestStandalonePythonVerifierEnforcesAnchor checks the trust half of the claim
// on the Python side: a valid signature by an unpinned key is refused when the
// caller asked for an anchor, and refused by default when the store pins someone
// else.
func TestStandalonePythonVerifierEnforcesAnchor(t *testing.T) {
	py, script := requirePython(t)

	b, samples, _ := newFixture(t, false)
	bundlePath, samplesPath := writePack(t, b, samples)
	foreign := hex.EncodeToString(fixedKeypair(0x99).Public)

	rep, code := runPython(t, py, script,
		"--bundle", bundlePath,
		"--samples", samplesPath,
		"--trust-key", foreign,
	)
	if code != 1 || rep.Valid {
		t.Fatalf("a bundle from a foreign signer was accepted (exit %d): %v", code, rep.failures())
	}
	if joined := strings.Join(rep.failures(), "\n"); !strings.Contains(joined, "UNTRUSTED") {
		t.Fatalf("failure did not name the untrusted issuer:\n%s", joined)
	}

	// And with no pin at all plus --require-anchor, the script must fail rather
	// than report a passing signature as identity.
	rep, code = runPython(t, py, script,
		"--bundle", bundlePath,
		"--samples", samplesPath,
		"--require-anchor",
	)
	if code != 1 || rep.Valid {
		t.Fatalf("--require-anchor without a pin was accepted (exit %d): %v", code, rep.failures())
	}
}
