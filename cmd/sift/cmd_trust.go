package main

// cmd_trust.go — the issuer trust store on the command line.
//
// `Sift verify` and `Sift certificate` both answer "is this file internally
// consistent?". Neither can answer "did this come from an issuer I accept?",
// because both formats carry the public key that signed them. A signature that
// verifies against its own embedded key proves nothing about identity: anyone
// can mint a keypair and sign any numbers they like.
//
// This command is the other half. It maintains the out-of-band set of issuer
// keys a verifier has decided to believe, and the two verification commands
// consult it. The workflow is deliberately boring:
//
//	Sift trust add --key school.pub --label "School #12"   # enrol once
//	Sift trust list                                        # review it
//	Sift verify --bundle b.json                            # anchor required by default
//
// Since F-02 (2026-11-20) --require-anchor is the default; --allow-unpinned is
// the explicit opt-out for a self-consistency-only check.
//
// A trust store holds public keys only, so it is world-readable and safe to
// commit to a repository where a reviewer can see every change.
//
// Exit status
//
//	0   the command succeeded (for `check`: the key is pinned)
//	1   the command failed, or the key is not pinned (fail closed)

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/asadbekabdulboqiyev/sift/internal/attest"
	"github.com/asadbekabdulboqiyev/sift/internal/authz"
	"github.com/asadbekabdulboqiyev/sift/internal/certificate"
)

// defaultTrustStorePath is where the trust store lives when --store is omitted,
// next to the other local identity material. Keeping one default means an
// operator enrols an issuer once and every later verification picks it up
// without extra flags.
func defaultTrustStorePath() string {
	return filepath.Join(authz.ConfigHome(), "trust.json")
}

func cmdTrust() {
	if len(os.Args) < 3 {
		trustUsage()
		exitProcess(1)
	}
	sub := os.Args[2]
	args := os.Args[3:]

	switch sub {
	case "add":
		trustAdd(args)
	case "list", "ls":
		trustList(args)
	case "remove", "rm":
		trustRemove(args)
	case "check":
		trustCheck(args)
	case "help", "--help", "-h":
		trustUsage()
	case "path":
		fmt.Println(defaultTrustStorePath())
	default:
		fmt.Fprintf(os.Stderr, "error: unknown trust subcommand %q\n\n", sub)
		trustUsage()
		exitProcess(1)
	}
}

// trustAdd implements: Sift trust add --key <hex|pem> [--label <name>]
func trustAdd(args []string) {
	fs := flag.NewFlagSet("trust add", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	storePath := fs.String("store", defaultTrustStorePath(), "trust store file to update")
	keyArg := fs.String("key", "", "issuer public key: 64 hex chars, a PEM file, or a keypair PEM (required)")
	label := fs.String("label", "", "human-readable issuer name (display only)")
	fromCert := fs.String("from-cert", "", "pin the signer of a certificate that verifies (alternative to --key)")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			trustUsage()
			return
		}
		fatal(fmt.Errorf("trust add: %w", err))
	}
	if fs.NArg() > 0 {
		fatal(fmt.Errorf("trust add: unexpected argument %q", fs.Arg(0)))
	}
	if strings.TrimSpace(*keyArg) == "" && strings.TrimSpace(*fromCert) == "" {
		fatal(fmt.Errorf("trust add: --key (or --from-cert) is required"))
	}

	pub, err := resolveIssuerKey(*keyArg, *fromCert)
	if err != nil {
		fatal(err)
	}

	store, err := loadOrInitTrustStore(*storePath)
	if err != nil {
		fatal(err)
	}
	if err := store.Add(pub, *label); err != nil {
		fatal(err)
	}
	if err := store.Save(*storePath); err != nil {
		fatal(err)
	}

	fmt.Printf("pinned %s\n", attest.Fingerprint(pub))
	if strings.TrimSpace(*label) != "" {
		fmt.Printf("  label:  %s\n", strings.TrimSpace(*label))
	} else {
		fmt.Fprintln(os.Stderr, "note: no --label given; the issuer will show as a bare fingerprint")
	}
	fmt.Printf("  store:  %s (%d issuers)\n", *storePath, store.Len())
	fmt.Println()
	fmt.Println("Verify (anchor now required by default):")
	fmt.Printf("  Sift verify --bundle <bundle.json>\n")
	fmt.Printf("  Sift certificate <cert.json>\n")
	fmt.Println("For a self-consistency-only check: add --allow-unpinned")
}

// trustList implements: Sift trust list [--json]
func trustList(args []string) {
	fs := flag.NewFlagSet("trust list", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	storePath := fs.String("store", defaultTrustStorePath(), "trust store file to read")
	asJSON := fs.Bool("json", false, "emit a machine-readable JSON object")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			trustUsage()
			return
		}
		fatal(fmt.Errorf("trust list: %w", err))
	}

	store, err := attest.LoadTrustStore(*storePath)
	if err != nil {
		// errors.Is walks the wrap chain and matches the platform's own
		// "not found" error (os.ErrNotExist is fs.ErrNotExist). os.IsNotExist does not unwrap, so it saw the
		// fmt.Errorf wrapper and said no; the string fallback then only worked
		// on Unix, where the message happens to be "no such file". On Windows
		// it is "The system cannot find the file specified", so `trust list`
		// on a fresh machine exited 1 instead of reporting an empty store.
		if errors.Is(err, os.ErrNotExist) {
			if *asJSON {
				emitTrustListJSON(*storePath, attest.NewTrustStore())
				return
			}
			fmt.Printf("trust store %s does not exist yet (0 issuers)\n", *storePath)
			fmt.Println("Pin an issuer with:")
			fmt.Println("  Sift trust add --key <issuer.pub> --label \"<name>\"")
			return
		}
		fatal(err)
	}

	if *asJSON {
		emitTrustListJSON(*storePath, store)
		return
	}

	entries := store.Entries()
	fmt.Printf("trust store %s (%s, %d issuers)\n", *storePath, attest.TrustStoreFormat, len(entries))
	for _, e := range entries {
		label := e.Label
		if label == "" {
			label = "(no label)"
		}
		line := fmt.Sprintf("  %-24s %s", label, attest.FingerprintHex(e.Key))
		if e.AddedAt != "" {
			line += "  added " + e.AddedAt
		}
		fmt.Println(line)
	}
	if len(entries) == 0 {
		fmt.Println("  (empty: every verification with this store fails the issuer check)")
	}
}

func emitTrustListJSON(storePath string, store *attest.TrustStore) {
	type issuerJSON struct {
		Key         string `json:"key"`
		Fingerprint string `json:"fingerprint"`
		Label       string `json:"label,omitempty"`
		AddedAt     string `json:"added_at,omitempty"`
	}
	out := struct {
		Format  string       `json:"format"`
		Store   string       `json:"store"`
		Count   int          `json:"count"`
		Issuers []issuerJSON `json:"issuers"`
	}{Format: attest.TrustStoreFormat, Store: storePath, Count: store.Len(), Issuers: []issuerJSON{}}
	for _, e := range store.Entries() {
		out.Issuers = append(out.Issuers, issuerJSON{
			Key:         e.Key,
			Fingerprint: attest.FingerprintHex(e.Key),
			Label:       e.Label,
			AddedAt:     e.AddedAt,
		})
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fatal(err)
	}
}

// trustRemove implements: Sift trust remove --key <hex|pem>
func trustRemove(args []string) {
	fs := flag.NewFlagSet("trust remove", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	storePath := fs.String("store", defaultTrustStorePath(), "trust store file to update")
	keyArg := fs.String("key", "", "issuer public key to drop: 64 hex chars or a PEM file (required)")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			trustUsage()
			return
		}
		fatal(fmt.Errorf("trust remove: %w", err))
	}
	if strings.TrimSpace(*keyArg) == "" {
		fatal(fmt.Errorf("trust remove: --key is required"))
	}

	pub, err := resolveIssuerKey(*keyArg, "")
	if err != nil {
		fatal(err)
	}

	store, err := attest.LoadTrustStore(*storePath)
	if err != nil {
		fatal(err)
	}
	hexKey := attest.PublicKeyHex(pub)
	if !store.Remove(hexKey) {
		fmt.Fprintf(os.Stderr, "error: %s is not in %s\n", attest.Fingerprint(pub), *storePath)
		exitProcess(1)
	}
	if err := store.Save(*storePath); err != nil {
		fatal(err)
	}
	fmt.Printf("removed %s\n", attest.Fingerprint(pub))
	fmt.Printf("  store: %s (%d issuers)\n", *storePath, store.Len())
}

// trustCheck implements: Sift trust check --key <hex|pem>
//
// It is the scriptable form of the question: exit 0 when the key is pinned,
// 1 when it is not, so a CI job can gate on it.
func trustCheck(args []string) {
	fs := flag.NewFlagSet("trust check", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	storePath := fs.String("store", defaultTrustStorePath(), "trust store file to consult")
	keyArg := fs.String("key", "", "issuer public key to look for (required)")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			trustUsage()
			return
		}
		fatal(fmt.Errorf("trust check: %w", err))
	}
	if strings.TrimSpace(*keyArg) == "" {
		fatal(fmt.Errorf("trust check: --key is required"))
	}

	pub, err := resolveIssuerKey(*keyArg, "")
	if err != nil {
		fatal(err)
	}
	store, err := attest.LoadTrustStore(*storePath)
	if err != nil {
		fatal(err)
	}
	entry, ok := store.Lookup(attest.PublicKeyHex(pub))
	if !ok {
		fmt.Printf("NOT PINNED — %s is not in %s (%d issuers)\n", attest.Fingerprint(pub), *storePath, store.Len())
		exitProcess(1)
	}
	label := entry.Label
	if label == "" {
		label = "(no label)"
	}
	fmt.Printf("PINNED — %s (%s)\n", label, attest.Fingerprint(pub))
}

// resolveIssuerKey turns whatever the operator typed into a public key. It
// accepts the three forms a key actually arrives in: bare hex (as printed by
// `keygen` and carried by a bundle), a PEM public key file, and a keypair PEM
// file whose public half is what gets pinned. --from-cert pins the signer of a
// certificate that already verifies, so a key can never be enrolled from a
// document that fails its own signature check.
func resolveIssuerKey(keyArg, fromCert string) (ed25519.PublicKey, error) {
	if certPath := strings.TrimSpace(fromCert); certPath != "" {
		data, err := os.ReadFile(filepath.Clean(certPath)) // #nosec G304 -- operator-selected certificate file
		if err != nil {
			return nil, fmt.Errorf("trust: read certificate %s: %w", certPath, err)
		}
		c, err := certificate.VerifyBytes(data)
		if err != nil {
			return nil, fmt.Errorf("trust: refusing to pin the issuer of an invalid certificate: %w", err)
		}
		return attest.ParsePublicKeyHex(c.PublicKey)
	}

	arg := strings.TrimSpace(keyArg)
	if arg == "" {
		return nil, fmt.Errorf("trust: no key given")
	}
	// A path that exists is read as PEM; anything else must be hex. Stat before
	// parsing so a typo'd filename produces "file not found", not "not hex".
	if info, err := os.Stat(arg); err == nil && !info.IsDir() {
		pub, err := attest.LoadPublicKeyPEM(arg)
		if err != nil {
			return nil, fmt.Errorf("trust: read key file %s: %w", arg, err)
		}
		return pub, nil
	}
	normalized := strings.ReplaceAll(arg, " ", "")
	normalized = strings.ReplaceAll(normalized, ":", "")
	pub, err := attest.ParsePublicKeyHex(normalized)
	if err != nil {
		return nil, fmt.Errorf("trust: %q is neither an existing PEM file nor a 64-character hex public key", arg)
	}
	return pub, nil
}

// loadOrInitTrustStore loads an existing store, or returns an empty one when the
// file does not exist yet. It deliberately does not create the file: `add` saves
// it, so a failed add leaves no half-configured store behind.
func loadOrInitTrustStore(path string) (*attest.TrustStore, error) {
	store, err := attest.LoadTrustStore(path)
	if err == nil {
		return store, nil
	}
	if _, statErr := os.Stat(path); os.IsNotExist(statErr) {
		return attest.NewTrustStore(), nil
	}
	return nil, err
}

func trustUsage() {
	fmt.Fprint(os.Stderr, `Usage: Sift trust <add|list|remove|check|path> [flags]

Manages the issuer trust store: the out-of-band set of Ed25519 public keys a
verifier accepts. Without it, "the signature verifies" only means the file is
self-consistent — anyone can mint a keypair and sign any numbers. With it, a
bundle or certificate signed by any other key is rejected.

Default store: `+defaultTrustStorePath()+`

Subcommands:
  add      Pin an issuer key (--key <hex|pem> or --from-cert <cert.json>)
  list     Show the pinned issuers (--json for machine output)
  remove   Drop an issuer key
  check    Exit 0 if the key is pinned, 1 if not (for CI gates)
  path     Print the default store path

Examples:
  Sift keygen --out school.pem
  Sift trust add --key school.pem --label "School #12"
  Sift trust list
  Sift verify --bundle bundle.json                    # trust anchor required by default
  Sift certificate cert.json --trust-store ./trust.json
  Sift verify --bundle bundle.json --allow-unpinned   # explicit self-consistency-only check
`)
}
