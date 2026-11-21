package attest

// trust.go — the verifier's trust anchor.
//
// # Why this file exists
//
// A vpmp/v1 bundle carries the coordinator public key that signed it
// (bundle.signature.key). Verifying that signature proves the bundle is
// internally consistent. It does not prove *who* issued it, because anyone can
// mint a fresh keypair and sign any numbers they like.
//
// That distinction is the whole difference between "this file is not corrupted"
// and "this evidence came from an issuer I chose to believe". Without it a
// verifier that reports PASS is answering the wrong question, and a forged
// certificate is indistinguishable from a real one.
//
// A TrustStore is the missing half: an out-of-band set of issuer keys the
// verifier has decided to accept. VerifyWith consults it, and a bundle signed
// by a key that is not in it fails the "issuer-trust" check. When no store is
// configured the signature is still verified, but the verdict reports the
// issuer as unpinned, so a caller can never mistake internal consistency for an
// established identity.
//
// # Format
//
// A store is one JSON document, so it can be reviewed in a pull request:
//
//	{
//	  "format": "sift-trust/v1",
//	  "issuers": [
//	    {"key": "<64 hex chars>", "label": "TechCorp", "added_at": "2026-11-18T09:00:00Z"}
//	  ]
//	}
//
// Keys are stored as lowercase hex, the same form the bundle carries, so a
// store can be filled by copy-pasting a fingerprint out of a certificate. A
// path that is a directory is loaded as every public key file inside it, which
// is what an operations team ends up with when keys arrive as .pub files.
//
// Loading is deliberately permissive about *which* files it accepts (JSON
// documents and PKIX PEM public keys) and strict about their *content*: a
// malformed key is an error, never silently skipped, because a trust store that
// quietly drops an entry is worse than one that refuses to load.

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/shared"
)

// TrustStoreFormat is the frozen format identifier of a trust store document.
const TrustStoreFormat = "sift-trust/v1"

// maxTrustFileBytes bounds one trust store file read. A store is a list of
// 32-byte keys; a megabyte holds tens of thousands of them.
const maxTrustFileBytes = 1 << 20

// TrustEntry is one accepted issuer.
type TrustEntry struct {
	// Key is the issuer's Ed25519 public key as lowercase hex.
	Key string `json:"key"`
	// Label is a human-readable name for the issuer ("TechCorp", "School #12").
	// It is display only: it never takes part in any decision.
	Label string `json:"label,omitempty"`
	// AddedAt is when the entry was first recorded, as RFC 3339. Informational.
	AddedAt string `json:"added_at,omitempty"`
}

// trustDocument is the on-disk shape of a store.
type trustDocument struct {
	Format  string       `json:"format"`
	Issuers []TrustEntry `json:"issuers"`
}

// TrustStore is a set of issuer public keys a verifier accepts.
//
// The zero value is an empty store and is safe to use, so a caller that wants
// "accept nothing" can pass &TrustStore{} and every bundle will fail the
// issuer-trust check. That is the strictest useful configuration and needs no
// extra flag.
type TrustStore struct {
	entries map[string]TrustEntry
}

// NewTrustStore returns an empty store.
func NewTrustStore() *TrustStore { return &TrustStore{entries: map[string]TrustEntry{}} }

func (t *TrustStore) ensure() {
	if t.entries == nil {
		t.entries = make(map[string]TrustEntry)
	}
}

// isNil reports whether the receiver is nil. Every exported method consults it
// so a nil *TrustStore behaves like an empty store instead of panicking: the
// type is passed around as a pointer and "no store configured" is a normal
// state, not an error.
func (t *TrustStore) isNil() bool { return t == nil }

// normalizeHexKey validates and lowercases a hex public key.
func normalizeHexKey(s string) (string, error) {
	key := strings.ToLower(strings.TrimSpace(s))
	key = strings.ReplaceAll(key, " ", "")
	key = strings.ReplaceAll(key, ":", "")
	raw, err := hex.DecodeString(key)
	if err != nil {
		return "", fmt.Errorf("attest: issuer key is not hex: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return "", fmt.Errorf("attest: issuer key is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	return key, nil
}

// Add records an issuer key under a label. Re-adding an existing key updates
// its label and keeps the original added_at timestamp, so a re-run of an
// enrolment script does not rewrite history.
func (t *TrustStore) Add(key ed25519.PublicKey, label string) error {
	if t.isNil() {
		return errors.New("attest: cannot add to a nil trust store")
	}
	if len(key) != ed25519.PublicKeySize {
		return errors.New("attest: trust store requires a 32-byte Ed25519 public key")
	}
	return t.AddHex(PublicKeyHex(key), label)
}

// AddHex records an issuer key given as hex.
func (t *TrustStore) AddHex(hexKey, label string) error {
	if t.isNil() {
		return errors.New("attest: cannot add to a nil trust store")
	}
	key, err := normalizeHexKey(hexKey)
	if err != nil {
		return err
	}
	t.ensure()
	prev, exists := t.entries[key]
	entry := TrustEntry{Key: key, Label: strings.TrimSpace(label), AddedAt: time.Now().UTC().Format(time.RFC3339)}
	if exists {
		entry.AddedAt = prev.AddedAt
		if entry.AddedAt == "" {
			entry.AddedAt = time.Now().UTC().Format(time.RFC3339)
		}
		if entry.Label == "" {
			entry.Label = prev.Label
		}
	}
	t.entries[key] = entry
	return nil
}

// Remove drops an issuer key. It reports whether the key was present.
func (t *TrustStore) Remove(hexKey string) bool {
	key, err := normalizeHexKey(hexKey)
	if err != nil {
		return false
	}
	if t.isNil() || t.entries == nil {
		return false
	}
	if _, ok := t.entries[key]; !ok {
		return false
	}
	delete(t.entries, key)
	return true
}

// Lookup reports whether the key is accepted, and its entry.
func (t *TrustStore) Lookup(hexKey string) (TrustEntry, bool) {
	key, err := normalizeHexKey(hexKey)
	if err != nil {
		return TrustEntry{}, false
	}
	if t.isNil() || t.entries == nil {
		return TrustEntry{}, false
	}
	e, ok := t.entries[key]
	return e, ok
}

// Len is the number of accepted issuers.
func (t *TrustStore) Len() int {
	if t.isNil() || t.entries == nil {
		return 0
	}
	return len(t.entries)
}

// Entries returns the accepted issuers sorted by key, so output is stable.
func (t *TrustStore) Entries() []TrustEntry {
	out := make([]TrustEntry, 0, t.Len())
	if t.isNil() {
		return out
	}
	for _, e := range t.entries {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// Merge copies every entry from other into t, keeping t's labels on conflict.
func (t *TrustStore) Merge(other *TrustStore) {
	if t.isNil() || other == nil {
		return
	}
	t.ensure()
	for key, e := range other.entries {
		if _, exists := t.entries[key]; exists {
			continue
		}
		t.entries[key] = e
	}
}

// Clone returns an independent copy.
func (t *TrustStore) Clone() *TrustStore {
	out := NewTrustStore()
	if t == nil {
		return out
	}
	for k, v := range t.entries {
		out.entries[k] = v
	}
	return out
}

// LoadTrustStore reads a trust store from a file or a directory.
//
// A directory is read as every regular file inside it: a JSON document is
// merged, and anything else is parsed as a PKIX PEM public key labelled with
// its file name. That covers both ways keys actually arrive in practice — a
// reviewed JSON list and a pile of .pub files.
func LoadTrustStore(path string) (*TrustStore, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("attest: trust store %s: %w", path, err)
	}
	store := NewTrustStore()
	if !info.IsDir() {
		if err := store.loadFile(path); err != nil {
			return nil, err
		}
		return store, nil
	}

	dirEntries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("attest: read trust store directory %s: %w", path, err)
	}
	loaded := 0
	for _, de := range dirEntries {
		name := de.Name()
		if de.IsDir() || strings.HasPrefix(name, ".") {
			continue
		}
		if err := store.loadFile(filepath.Join(path, name)); err != nil {
			return nil, err
		}
		loaded++
	}
	if loaded == 0 {
		return nil, fmt.Errorf("attest: trust store directory %s contains no key files", path)
	}
	return store, nil
}

// loadFile merges one file into the store.
func (t *TrustStore) loadFile(path string) error {
	doc, err := readLimited(path, maxTrustFileBytes)
	if err != nil {
		return fmt.Errorf("attest: trust store %s: %w", path, err)
	}
	trimmed := strings.TrimSpace(string(doc))
	if trimmed == "" {
		return fmt.Errorf("attest: trust store %s is empty", path)
	}

	if strings.HasPrefix(trimmed, "{") {
		var parsed trustDocument
		if err := json.Unmarshal(doc, &parsed); err != nil {
			return fmt.Errorf("attest: parse trust store %s: %w", path, err)
		}
		if parsed.Format != "" && parsed.Format != TrustStoreFormat {
			return fmt.Errorf("attest: trust store %s has format %q, want %q", path, parsed.Format, TrustStoreFormat)
		}
		if len(parsed.Issuers) == 0 {
			return fmt.Errorf("attest: trust store %s contains no issuers", path)
		}
		for _, e := range parsed.Issuers {
			key, err := normalizeHexKey(e.Key)
			if err != nil {
				return fmt.Errorf("attest: trust store %s: %w", path, err)
			}
			t.ensure()
			if _, exists := t.entries[key]; !exists {
				t.entries[key] = TrustEntry{Key: key, Label: e.Label, AddedAt: e.AddedAt}
			}
		}
		return nil
	}

	pub, err := LoadPublicKeyPEM(path)
	if err != nil {
		return fmt.Errorf("attest: trust store %s is neither a %s document nor a PEM public key: %w", path, TrustStoreFormat, err)
	}
	label := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	if err := t.Add(pub, label); err != nil {
		return fmt.Errorf("attest: trust store %s: %w", path, err)
	}
	return nil
}

// Save writes the store as a JSON document, atomically and world-readable
// (a trust store holds public keys only).
func (t *TrustStore) Save(path string) error {
	doc := trustDocument{Format: TrustStoreFormat, Issuers: t.Entries()}
	if doc.Issuers == nil {
		doc.Issuers = []TrustEntry{}
	}
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("attest: encode trust store: %w", err)
	}
	body = append(body, '\n')

	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("attest: create trust store directory: %w", err)
		}
	}
	// Strict directory sync: a lost rename here would silently drop a trusted
	// issuer, so a genuine sync failure must fail the save. Trust stores are
	// public by design (0644).
	if err := shared.Write(path, body, 0o644, shared.WithDirSync(true)); err != nil {
		return fmt.Errorf("attest: install trust store: %w", err)
	}
	return nil
}

// Fingerprint renders a public key as sixteen space-separated groups of four
// lowercase hex characters. It is the form printed on certificates and in CLI
// output: short enough to read aloud, long enough that comparing two of them by
// eye is meaningful.
func Fingerprint(pub ed25519.PublicKey) string { return FingerprintHex(PublicKeyHex(pub)) }

// FingerprintHex is Fingerprint for a hex key. A key that does not decode is
// returned unchanged so a malformed value is still visible in the output.
func FingerprintHex(hexKey string) string {
	key, err := normalizeHexKey(hexKey)
	if err != nil {
		return hexKey
	}
	var b strings.Builder
	b.Grow(len(key) + len(key)/4)
	for i := 0; i < len(key); i += 4 {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(key[i : i+4])
	}
	return b.String()
}
