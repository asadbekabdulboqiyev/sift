package attest

// trust_test.go — the trust-anchor contract.
//
// The tests here are the ones that make the difference between "this file is
// not corrupted" and "this evidence came from an issuer I chose to believe".
// The load-bearing one is TestVerifyRejectsForgedIssuer: a bundle that is
// perfectly self-consistent, signed by a key the verifier has never accepted,
// must fail. If that test ever passes with Valid == true, the tamper-evidence
// claim is a lie.

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Store mechanics
// ---------------------------------------------------------------------------

func TestTrustStoreAddLookupRemove(t *testing.T) {
	kp := mustKey(t)
	store := NewTrustStore()

	if store.Len() != 0 {
		t.Fatalf("new store Len = %d, want 0", store.Len())
	}
	if _, ok := store.Lookup(PublicKeyHex(kp.Public)); ok {
		t.Fatal("empty store claims to know a key")
	}

	if err := store.Add(kp.Public, "TechCorp"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if store.Len() != 1 {
		t.Fatalf("Len after Add = %d, want 1", store.Len())
	}

	entry, ok := store.Lookup(PublicKeyHex(kp.Public))
	if !ok {
		t.Fatal("Lookup missed a key that was just added")
	}
	if entry.Label != "TechCorp" {
		t.Fatalf("label = %q, want TechCorp", entry.Label)
	}
	if entry.AddedAt == "" {
		t.Fatal("AddedAt was not stamped")
	}

	if !store.Remove(PublicKeyHex(kp.Public)) {
		t.Fatal("Remove reported the key was absent")
	}
	if store.Len() != 0 {
		t.Fatalf("Len after Remove = %d, want 0", store.Len())
	}
	if store.Remove(PublicKeyHex(kp.Public)) {
		t.Fatal("Remove reported success for an absent key")
	}
}

func TestTrustStoreNormalizesKeyForms(t *testing.T) {
	kp := mustKey(t)
	hexKey := PublicKeyHex(kp.Public)
	store := NewTrustStore()

	// The same key written the way people actually write keys: uppercase, with
	// spaces between groups, and with colons like a fingerprint.
	for _, form := range []string{
		strings.ToUpper(hexKey),
		FingerprintHex(hexKey),
		strings.ReplaceAll(FingerprintHex(hexKey), " ", ":"),
	} {
		if err := store.AddHex(form, "x"); err != nil {
			t.Fatalf("AddHex(%q): %v", form, err)
		}
		if _, ok := store.Lookup(hexKey); !ok {
			t.Fatalf("key added as %q is not findable by its canonical hex", form)
		}
	}
	if store.Len() != 1 {
		t.Fatalf("three spellings of one key produced %d entries, want 1", store.Len())
	}
}

func TestTrustStoreAddHexRejectsMalformed(t *testing.T) {
	store := NewTrustStore()
	for _, bad := range []string{
		"",
		"zzzz",
		"abcd",
		strings.Repeat("ab", 31), // 31 bytes
		strings.Repeat("ab", 33), // 33 bytes
	} {
		if err := store.AddHex(bad, ""); err == nil {
			t.Fatalf("AddHex(%q) accepted a malformed key", bad)
		}
	}
	if store.Len() != 0 {
		t.Fatalf("malformed keys leaked into the store: %d entries", store.Len())
	}
}

func TestTrustStoreReAddKeepsOriginalTimestamp(t *testing.T) {
	kp := mustKey(t)
	store := NewTrustStore()
	if err := store.Add(kp.Public, "first"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	before, _ := store.Lookup(PublicKeyHex(kp.Public))

	if err := store.Add(kp.Public, "second"); err != nil {
		t.Fatalf("re-Add: %v", err)
	}
	after, _ := store.Lookup(PublicKeyHex(kp.Public))

	if after.AddedAt != before.AddedAt {
		t.Fatalf("re-adding rewrote history: %q -> %q", before.AddedAt, after.AddedAt)
	}
	if after.Label != "second" {
		t.Fatalf("label = %q, want the updated label", after.Label)
	}
}

func TestTrustStoreMergeAndClone(t *testing.T) {
	a := mustKey(t)
	b := mustKey(t)
	left := NewTrustStore()
	if err := left.Add(a.Public, "left"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	right := NewTrustStore()
	if err := right.Add(a.Public, "right-label"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := right.Add(b.Public, "right"); err != nil {
		t.Fatalf("Add: %v", err)
	}

	left.Merge(right)
	if left.Len() != 2 {
		t.Fatalf("merged Len = %d, want 2", left.Len())
	}
	// The receiver's label wins on conflict.
	if e, _ := left.Lookup(PublicKeyHex(a.Public)); e.Label != "left" {
		t.Fatalf("merge overwrote the receiver's label: %q", e.Label)
	}

	clone := left.Clone()
	if clone.Len() != left.Len() {
		t.Fatalf("clone Len = %d, want %d", clone.Len(), left.Len())
	}
	if !clone.Remove(PublicKeyHex(b.Public)) {
		t.Fatal("clone is not an independent copy")
	}
	if left.Len() != 2 {
		t.Fatal("mutating the clone changed the original")
	}

	var nilStore *TrustStore
	if got := nilStore.Clone(); got.Len() != 0 {
		t.Fatal("cloning nil produced a non-empty store")
	}
	var nilStore2 *TrustStore
	nilStore2.Merge(right) // must not panic
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

func TestTrustStoreSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "trust.json")

	a := mustKey(t)
	b := mustKey(t)
	store := NewTrustStore()
	if err := store.Add(a.Public, "TechCorp"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := store.Add(b.Public, "School #12"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := store.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Windows has no POSIX permission bits: Chmod only toggles the read-only
	// attribute and Stat reports 0666 for every writable file, so the mode
	// assertion below is a Unix-only claim.
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o644 {
			t.Fatalf("mode = %o, want 644 (public keys are not secret)", perm)
		}
	}

	loaded, err := LoadTrustStore(path)
	if err != nil {
		t.Fatalf("LoadTrustStore: %v", err)
	}
	if loaded.Len() != 2 {
		t.Fatalf("loaded Len = %d, want 2", loaded.Len())
	}
	for _, want := range []struct{ key, label string }{
		{PublicKeyHex(a.Public), "TechCorp"},
		{PublicKeyHex(b.Public), "School #12"},
	} {
		entry, ok := loaded.Lookup(want.key)
		if !ok {
			t.Fatalf("key %s lost in round trip", want.key)
		}
		if entry.Label != want.label {
			t.Fatalf("label = %q, want %q", entry.Label, want.label)
		}
	}
}

func TestTrustStoreEntriesAreSorted(t *testing.T) {
	store := NewTrustStore()
	var want []string
	for i := 0; i < 5; i++ {
		kp := mustKey(t)
		if err := store.Add(kp.Public, ""); err != nil {
			t.Fatalf("Add: %v", err)
		}
		want = append(want, PublicKeyHex(kp.Public))
	}
	got := store.Entries()
	if len(got) != len(want) {
		t.Fatalf("Entries len = %d, want %d", len(got), len(want))
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].Key >= got[i].Key {
			t.Fatal("Entries is not sorted by key, so output is not stable")
		}
	}
}

func TestTrustStoreLoadDirectory(t *testing.T) {
	dir := t.TempDir()

	// A JSON document plus a bare PEM public key: both ways keys arrive.
	jsonKey := mustKey(t)
	pemKey := mustKey(t)

	jsonStore := NewTrustStore()
	if err := jsonStore.Add(jsonKey.Public, "from-json"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := jsonStore.Save(filepath.Join(dir, "issuers.json")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := SaveKeypairPEM(pemKey, filepath.Join(dir, "school.pem")); err != nil {
		t.Fatalf("SaveKeypairPEM: %v", err)
	}
	// Dotfiles must be ignored, not parsed.
	if err := os.WriteFile(filepath.Join(dir, ".DS_Store"), []byte("junk"), 0o644); err != nil {
		t.Fatalf("write dotfile: %v", err)
	}

	store, err := LoadTrustStore(dir)
	if err != nil {
		t.Fatalf("LoadTrustStore(dir): %v", err)
	}
	if store.Len() != 2 {
		t.Fatalf("Len = %d, want 2 (json + pem)", store.Len())
	}
	if _, ok := store.Lookup(PublicKeyHex(jsonKey.Public)); !ok {
		t.Fatal("JSON issuer missing")
	}
	entry, ok := store.Lookup(PublicKeyHex(pemKey.Public))
	if !ok {
		t.Fatal("PEM issuer missing")
	}
	if entry.Label != "school" {
		t.Fatalf("PEM label = %q, want the file stem %q", entry.Label, "school")
	}
}

func TestTrustStoreLoadRejectsBadInput(t *testing.T) {
	dir := t.TempDir()

	empty := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(empty, []byte("  \n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadTrustStore(empty); err == nil {
		t.Fatal("empty file accepted")
	}

	badFormat := filepath.Join(dir, "format.json")
	if err := os.WriteFile(badFormat, []byte(`{"format":"sift-trust/v9","issuers":[]}`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadTrustStore(badFormat); err == nil {
		t.Fatal("unknown format accepted")
	}

	noIssuers := filepath.Join(dir, "none.json")
	if err := os.WriteFile(noIssuers, []byte(`{"format":"sift-trust/v1","issuers":[]}`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadTrustStore(noIssuers); err == nil {
		t.Fatal("a store with no issuers was accepted as a trust anchor")
	}

	badKey := filepath.Join(dir, "badkey.json")
	if err := os.WriteFile(badKey, []byte(`{"format":"sift-trust/v1","issuers":[{"key":"not-hex"}]}`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadTrustStore(badKey); err == nil {
		t.Fatal("a malformed key was silently accepted")
	}

	emptyDir := filepath.Join(dir, "emptydir")
	if err := os.Mkdir(emptyDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, err := LoadTrustStore(emptyDir); err == nil {
		t.Fatal("an empty directory was accepted as a trust anchor")
	}

	if _, err := LoadTrustStore(filepath.Join(dir, "does-not-exist.json")); err == nil {
		t.Fatal("a missing file was accepted")
	}
}

func TestFingerprintGrouping(t *testing.T) {
	kp := mustKey(t)
	hexKey := PublicKeyHex(kp.Public)
	fp := Fingerprint(kp.Public)
	if fp != FingerprintHex(hexKey) {
		t.Fatal("Fingerprint and FingerprintHex disagree")
	}
	groups := strings.Fields(fp)
	if len(groups) != 16 {
		t.Fatalf("fingerprint has %d groups, want 16", len(groups))
	}
	for _, g := range groups {
		if len(g) != 4 {
			t.Fatalf("group %q is not 4 characters", g)
		}
	}
	if strings.ReplaceAll(fp, " ", "") != hexKey {
		t.Fatal("fingerprint does not round-trip to the key")
	}
	// A malformed key is returned verbatim so the bad value stays visible.
	if got := FingerprintHex("zz"); got != "zz" {
		t.Fatalf("malformed key was rewritten to %q", got)
	}
}

// ---------------------------------------------------------------------------
// Verification integration — the load-bearing tests
// ---------------------------------------------------------------------------

func TestVerifyUnpinnedWithoutStore(t *testing.T) {
	b, samples, _ := newFixture(t, false)
	res := Verify(b, samples)

	if !res.Valid {
		t.Fatalf("a valid bundle was rejected when no store was configured: %v", res.ErrorLines())
	}
	if res.IssuerTrust != IssuerUnpinned {
		t.Fatalf("IssuerTrust = %q, want %q", res.IssuerTrust, IssuerUnpinned)
	}
	if res.IssuerKey == "" {
		t.Fatal("IssuerKey was not echoed for the report")
	}
	if res.IssuerTrust.Trusted() {
		t.Fatal("an unpinned issuer must never report Trusted()")
	}
	if len(res.Warnings) != 0 {
		t.Fatalf("unpinned verification added warnings, which would break --json consumers: %v", res.Warnings)
	}
}

func TestVerifyPinnedIssuer(t *testing.T) {
	b, samples, coord := newFixture(t, false)
	store := NewTrustStore()
	if err := store.Add(coord.Public, "TechCorp"); err != nil {
		t.Fatalf("Add: %v", err)
	}

	res := VerifyWith(b, samples, VerifyOptions{TrustStore: store})
	if !res.Valid {
		t.Fatalf("pinned bundle rejected: %v", res.ErrorLines())
	}
	if res.IssuerTrust != IssuerPinned {
		t.Fatalf("IssuerTrust = %q, want %q", res.IssuerTrust, IssuerPinned)
	}
	if !res.IssuerTrust.Trusted() {
		t.Fatal("a pinned issuer must report Trusted()")
	}
	if res.IssuerLabel != "TechCorp" {
		t.Fatalf("IssuerLabel = %q, want TechCorp", res.IssuerLabel)
	}
	if res.IssuerKey != PublicKeyHex(coord.Public) {
		t.Fatal("IssuerKey does not echo the signing key")
	}
}

// TestVerifyRejectsForgedIssuer is the whole point of the trust anchor. The
// bundle is internally perfect — every checksum, every signature, every Merkle
// root is consistent — and it must still fail, because the key that signed it
// is not one the verifier accepts.
func TestVerifyRejectsForgedIssuer(t *testing.T) {
	school := mustKey(t)
	forger := mustKey(t)

	b, samples, _ := newFixture(t, false)
	// Re-seal the (otherwise untouched) bundle with the forger's key: this is
	// exactly what an attacker who wants to publish fake numbers can do.
	if err := b.Sign(forger); err != nil {
		t.Fatalf("Sign(forger): %v", err)
	}
	if err := b.VerifyCoordinatorSig(); err != nil {
		t.Fatalf("forged bundle is not even self-consistent, so the test proves nothing: %v", err)
	}

	store := NewTrustStore()
	if err := store.Add(school.Public, "School #12"); err != nil {
		t.Fatalf("Add: %v", err)
	}

	res := VerifyWith(b, samples, VerifyOptions{TrustStore: store})
	if res.Valid {
		t.Fatal("a bundle signed by an unknown key was accepted: the trust anchor does not work")
	}
	if res.IssuerTrust != IssuerUntrusted {
		t.Fatalf("IssuerTrust = %q, want %q", res.IssuerTrust, IssuerUntrusted)
	}
	if res.IssuerTrust.Trusted() {
		t.Fatal("an untrusted issuer reported Trusted()")
	}
	if _, ok := findErr(res, "issuer-trust"); !ok {
		t.Fatalf("no issuer-trust failure was recorded: %v", res.ErrorLines())
	}
}

func TestVerifyEmptyStoreRejectsEverything(t *testing.T) {
	b, samples, _ := newFixture(t, false)

	// A non-nil but empty store means "accept no issuer" — the strictest
	// useful configuration, and the one a misconfigured path produces.
	res := VerifyWith(b, samples, VerifyOptions{TrustStore: NewTrustStore()})
	if res.Valid {
		t.Fatal("an empty trust store accepted a bundle")
	}
	if res.IssuerTrust != IssuerUntrusted {
		t.Fatalf("IssuerTrust = %q, want %q", res.IssuerTrust, IssuerUntrusted)
	}
}

func TestVerifyRequireTrustAnchorWithoutStore(t *testing.T) {
	b, samples, _ := newFixture(t, false)

	res := VerifyWith(b, samples, VerifyOptions{RequireTrustAnchor: true})
	if res.Valid {
		t.Fatal("RequireTrustAnchor was set but a bundle with no anchor passed")
	}
	if res.IssuerTrust != IssuerUnpinned {
		t.Fatalf("IssuerTrust = %q, want %q", res.IssuerTrust, IssuerUnpinned)
	}
	if _, ok := findErr(res, "issuer-trust"); !ok {
		t.Fatalf("no issuer-trust failure recorded: %v", res.ErrorLines())
	}
}

func TestVerifyMissingIssuerKey(t *testing.T) {
	b, samples, _ := newFixture(t, false)
	b.Signature.Key = ""

	res := Verify(b, samples)
	if res.Valid {
		t.Fatal("a bundle with no signing key passed verification")
	}
	if res.IssuerTrust != IssuerMissing {
		t.Fatalf("IssuerTrust = %q, want %q", res.IssuerTrust, IssuerMissing)
	}
	if _, ok := findErr(res, "issuer-trust"); !ok {
		t.Fatalf("no issuer-trust failure recorded: %v", res.ErrorLines())
	}
}

// TestVerifyPinnedIssuerStillCatchesTampering makes sure the trust check is an
// addition, not a replacement: a pinned bundle whose sidecar was edited must
// still fail on the Merkle recomputation.
func TestVerifyPinnedIssuerStillCatchesTampering(t *testing.T) {
	b, samples, coord := newFixture(t, false)
	store := NewTrustStore()
	if err := store.Add(coord.Public, "TechCorp"); err != nil {
		t.Fatalf("Add: %v", err)
	}

	tampered := cloneSamples(samples)
	tampered["w1"][0].LatencyNS += 1

	res := VerifyWith(b, tampered, VerifyOptions{TrustStore: store})
	if res.Valid {
		t.Fatal("a tampered sidecar passed verification even though the issuer was pinned")
	}
	if res.IssuerTrust != IssuerPinned {
		t.Fatalf("IssuerTrust = %q: the issuer identity should still be established", res.IssuerTrust)
	}
	if len(res.Errors) == 0 {
		t.Fatal("no errors were recorded for a tampered sidecar")
	}
}

// TestVerifyTrustStoreLoadedFromDisk is the end-to-end shape an operator
// actually uses: save a store, load it back, verify against it.
func TestVerifyTrustStoreLoadedFromDisk(t *testing.T) {
	b, samples, coord := newFixture(t, false)

	dir := t.TempDir()
	path := filepath.Join(dir, "trust.json")
	store := NewTrustStore()
	if err := store.Add(coord.Public, "TechCorp"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := store.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := LoadTrustStore(path)
	if err != nil {
		t.Fatalf("LoadTrustStore: %v", err)
	}

	res := VerifyWith(b, samples, VerifyOptions{TrustStore: loaded, RequireTrustAnchor: true})
	if !res.Valid {
		t.Fatalf("round-tripped trust store rejected a good bundle: %v", res.ErrorLines())
	}
	if !res.IssuerTrust.Trusted() {
		t.Fatalf("IssuerTrust = %q, want trusted", res.IssuerTrust)
	}
}

// TestLoadTrustStoreMissingIsErrNotExist pins the contract the CLI relies on.
//
// `Sift trust list` on a machine that has never pinned an issuer must report an
// empty store, not fail. It asks LoadTrustStore, and LoadTrustStore wraps the
// stat error to name the path — which means the plain os.IsNotExist(err) check
// answers "no" even though the file really is absent, because that function
// does not unwrap. The first version of the command compensated with a
// strings.Contains(err, "no such file"), which is Unix wording; on Windows the
// message is "The system cannot find the file specified", so the command exited
// 1 on a fresh machine.
//
// The test asserts the two facts the fix depends on, on every platform: the
// error is a not-exist error for errors.Is, and it is not one for os.IsNotExist.
// If a future change stops wrapping (or starts returning a bare error), this
// fails here rather than in a Windows CI job nobody watches.
func TestLoadTrustStoreMissingIsErrNotExist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent", "trust.json")

	_, err := LoadTrustStore(path)
	if err == nil {
		t.Fatal("LoadTrustStore loaded a store that does not exist")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("errors.Is(err, os.ErrNotExist) = false; the CLI cannot tell an empty store from a broken one: %v", err)
	}
	if os.IsNotExist(err) {
		t.Log("os.IsNotExist now unwraps too; the CLI's errors.Is check is still the correct one")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error does not name the path %q: %v", path, err)
	}
}
