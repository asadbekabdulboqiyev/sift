package attest

// golden_test.go — the format is frozen here.
//
// Everything else in this package proves that the producer and the verifier
// agree with each other. This file proves something different: that the bytes
// they agree on are stable across machines, Go versions and, crucially,
// independent implementations.
//
// The canonical encoding is the protocol. A verifier written in Python, Rust or
// a shell script has to reproduce exactly these bytes from the same logical
// bundle, or its signature check will disagree with ours for no security
// reason. A golden digest is the only way to notice a silent encoding change:
// without it, tweaking a separator or an escaping rule would still pass every
// round-trip test in the package while breaking every other implementation.
//
// The fixture is built from fixed key seeds and fixed records, so the golden
// values are reproducible by anyone reading this file.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
)

// fixedKeypair derives a deterministic identity from a single byte. Tests that
// need reproducible bytes use this instead of GenerateKeypair.
func fixedKeypair(seed byte) *Keypair {
	s := bytes.Repeat([]byte{seed}, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(s)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		panic("attest: Ed25519 public key has an unexpected type")
	}
	return &Keypair{Private: priv, Public: pub}
}

// goldenBundle is a complete, signed two-worker bundle built only from fixed
// inputs: fixed keys, fixed records, fixed run metadata.
func goldenBundle(t *testing.T) Bundle {
	t.Helper()
	coord := fixedKeypair(0x11)
	w1 := fixedKeypair(0x22)
	w2 := fixedKeypair(0x33)

	run := Run{
		Target:     "https://example.test/api",
		Profile:    "constant-rps",
		DurationNS: 10_000_000_000,
		PlannedRPS: Decimal("6.500"),
	}
	specs := []workerSpec{
		{id: "w1", kp: w1, recs: synthRecords("w1", 1_000_000_000, 3, 1_000_000, 1_000_000, 10_000)},
		{id: "w2", kp: w2, recs: synthRecords("w2", 2_000_000_000, 2, 1_000_000, 2_000_000, 20_000)},
	}
	b, _ := produceBundle(t, coord, run, specs, false)
	return b
}

// goldenCanonical is the exact byte string the coordinator signature covers for
// goldenBundle. It is deliberately written out in full: a port can diff its own
// encoder against this text and see precisely which rule differs.
const goldenCanonical = `{"aggregate":{"co_ci95_ns":{"high_ns":0,"low_ns":0},"co_corrected":false,"count":5,"p50_ns":1020000,"p95_ns":2020000,"p99_ns":2020000,"rps":"0.500","sum_latency_ns":7050000},"created_at":"2026-10-13T18:00:00Z","format":"vpmp/v1","integrity":{"achieved_rps":"0.500","dropped_samples":60,"planned_rps":"6.500","schedule_accuracy_ppm":76923},"run":{"duration_ns":10000000000,"planned_rps":"6.500","profile":"constant-rps","target":"https://example.test/api"},"tool":{"name":"Sift","version":"test"},"workers":[{"aggregate":{"count":3,"hist":{"1048575":3},"max_ns":1020000,"min_ns":1000000,"sum_latency_ns":3030000},"commit":{"merkle_root":"0a5af9f0444ba57e30faa55ad5ad566d988d0b7ad7464e231ca71014001d4c96","sample_count":3,"signature":"3aa0bb76b2df89452bc5712ca860ccf5bfbff318c5332766385104a188ba146ca1f2af662e32e400bce018121e8f7f4f98bfdd522f9c7192bec4152f173e7906","window_end_ns":1003020000,"window_start_ns":1000000000},"id":"w1","public_key":"a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0"},{"aggregate":{"count":2,"hist":{"2097151":2},"max_ns":2020000,"min_ns":2000000,"sum_latency_ns":4020000},"commit":{"merkle_root":"68fbc95de42844ed86cdeb35356b6d63cccb60143a6281bbb218fb0faa6d77c0","sample_count":2,"signature":"dc3b0f1b62bf98d920edc778867c63179fa8a9e1504495774678922ec37f2aa602b3ba3467d8287cc610b232863a5ee11d63b56d218ce962faaf5dfa4dbeae0d","window_end_ns":2003020000,"window_start_ns":2000000000},"id":"w2","public_key":"17cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce"}]}`

// goldenDigest is the lowercase hex SHA-256 of goldenCanonical.
const goldenDigest = "9f074a4e5fbd9355718c566712331f6a609dc204e7af0e243346b049cf5e4a43"

func TestCanonicalEncodingIsFrozen(t *testing.T) {
	b := goldenBundle(t)

	got, err := b.CanonicalUnsigned()
	if err != nil {
		t.Fatalf("CanonicalUnsigned: %v", err)
	}
	if string(got) != goldenCanonical {
		t.Fatalf("canonical encoding changed.\n got: %s\nwant: %s", got, goldenCanonical)
	}

	digest, err := b.DigestHex()
	if err != nil {
		t.Fatalf("DigestHex: %v", err)
	}
	if digest != goldenDigest {
		t.Fatalf("bundle digest changed: got %s, want %s", digest, goldenDigest)
	}
	if err := b.VerifyCoordinatorSig(); err != nil {
		t.Fatalf("the golden bundle does not verify against its own encoding: %v", err)
	}
}

// TestCanonicalEncodingIsReproducible rebuilds the fixture and re-derives the
// digest from a JSON round trip. If either differs, the golden value above is
// describing something the code no longer produces.
func TestCanonicalEncodingIsReproducible(t *testing.T) {
	a := goldenBundle(t)
	b := goldenBundle(t)

	da, err := a.DigestHex()
	if err != nil {
		t.Fatalf("DigestHex: %v", err)
	}
	db, err := b.DigestHex()
	if err != nil {
		t.Fatalf("DigestHex: %v", err)
	}
	if da != db {
		t.Fatalf("two builds of the same fixture disagree: %s vs %s", da, db)
	}

	raw, err := a.Canonical()
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	loaded, err := ParseBundle(raw)
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	dl, err := loaded.DigestHex()
	if err != nil {
		t.Fatalf("DigestHex after load: %v", err)
	}
	if dl != goldenDigest {
		t.Fatalf("digest changed after a JSON round trip: %s", dl)
	}
}

// TestCanonicalNumbersAreIntegers enforces the rule that makes the encoding
// portable: no floats anywhere. Every number in the canonical form must be an
// integer literal, and rates must travel as fixed-scale strings.
func TestCanonicalNumbersAreIntegers(t *testing.T) {
	b := goldenBundle(t)
	raw, err := b.CanonicalUnsigned()
	if err != nil {
		t.Fatalf("CanonicalUnsigned: %v", err)
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var tree any
	if err := dec.Decode(&tree); err != nil {
		t.Fatalf("canonical output is not valid JSON: %v", err)
	}

	var walk func(path string, v any)
	walk = func(path string, v any) {
		switch val := v.(type) {
		case json.Number:
			s := val.String()
			if strings.ContainsAny(s, ".eE") {
				t.Fatalf("%s is a non-integer number (%q); the canonical form allows integers only", path, s)
			}
		case map[string]any:
			for k, child := range val {
				walk(path+"."+k, child)
			}
		case []any:
			for _, child := range val {
				walk(path+"[]", child)
			}
		}
	}
	walk("$", tree)
}

// TestCanonicalKeysAreSorted checks the ordering rule directly rather than
// trusting the encoder to have applied it.
func TestCanonicalKeysAreSorted(t *testing.T) {
	b := goldenBundle(t)
	raw, err := b.CanonicalUnsigned()
	if err != nil {
		t.Fatalf("CanonicalUnsigned: %v", err)
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var tree any
	if err := dec.Decode(&tree); err != nil {
		t.Fatalf("canonical output is not valid JSON: %v", err)
	}

	// Re-encoding the parsed tree with a sorted-key encoder must reproduce the
	// same bytes. encoding/json emits map keys in sorted order, so a match
	// proves the canonical encoder did the same. HTML escaping is disabled to
	// match the canonical encoder's minimal escaping.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(tree); err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	got := strings.TrimRight(buf.String(), "\n")
	if got != string(raw) {
		t.Fatalf("canonical output is not sorted-key JSON.\n got: %s\nwant: %s", got, raw)
	}
}
