package main

// cmd_audit360.go — verify a sealed Sift 360° audit report.
//
// 360° audits are produced by the dashboard (POST /api/audit-360). The report
// JSON carries an Ed25519 seal over a canonical digest of its own payload, so a
// shared report can be checked without the dashboard, without the signing key
// and without the network.
//
//	Sift audit360 verify report.json
//	Sift audit360 verify report.json --key <signer-pubkey-hex>
//
// The second form is the one that answers "who produced this?": the key is
// recorded inside the signed payload, so a verifier that only reads it proves
// internal consistency. Pinning a key you obtained out of band is what turns
// the check into an attribution.

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/asadbekabdulboqiyev/sift/internal/audit360"
)

// maxAudit360ReportBytes caps a report file so a malformed or hostile input
// cannot make the verifier allocate without bound.
const maxAudit360ReportBytes = 32 << 20

// audit360VerifyJSON is the machine-readable verdict.
type audit360VerifyJSON struct {
	Valid             bool   `json:"valid"`
	Format            string `json:"format"`
	Report            string `json:"report"`
	Target            string `json:"target,omitempty"`
	Timestamp         string `json:"timestamp,omitempty"`
	RiskLevel         string `json:"risk_level,omitempty"`
	ResilienceScore   int    `json:"resilience_score"`
	CertificateID     string `json:"certificate_id,omitempty"`
	SignerKey         string `json:"signer_key,omitempty"`
	SignerFingerprint string `json:"signer_fingerprint,omitempty"`
	KeyPinned         bool   `json:"key_pinned"`
	Error             string `json:"error,omitempty"`
}

func cmdAudit360() {
	args := os.Args[2:]
	if len(args) == 0 {
		printAudit360Guide()
		return
	}
	sub := args[0]
	switch sub {
	case "help", "-h", "--help":
		printAudit360Guide()
		return
	case "verify":
	default:
		fmt.Fprintf(os.Stderr, "error: unknown audit360 subcommand %q (use: verify)\n", sub)
		exitProcess(2)
	}

	fs := flag.NewFlagSet("audit360 verify", flag.ContinueOnError)
	var (
		key    string
		asJSON bool
		quiet  bool
	)
	fs.StringVar(&key, "key", "", "pin the signer public key (hex) the report must carry")
	fs.BoolVar(&asJSON, "json", false, "machine-readable verdict")
	fs.BoolVar(&quiet, "quiet", false, "print nothing on success")

	// Go's flag package stops at the first non-flag argument, so the natural
	// `verify report.json --key <hex>` would silently drop the flags. Keep
	// parsing after each positional so flag order does not change the verdict —
	// a verification command that ignores a flag is worse than one that rejects
	// it.
	var positional []string
	rest := args[1:]
	for {
		if err := fs.Parse(rest); err != nil {
			exitProcess(2)
		}
		if fs.NArg() == 0 {
			break
		}
		positional = append(positional, fs.Arg(0))
		rest = fs.Args()[1:]
	}
	if len(positional) > 1 {
		fmt.Fprintf(os.Stderr, "error: unexpected arguments: %s\n", strings.Join(positional[1:], " "))
		exitProcess(2)
	}
	path := ""
	if len(positional) == 1 {
		path = positional[0]
	}
	if path == "" {
		fmt.Fprintln(os.Stderr, "error: no report file\n\n  Sift audit360 verify report.json")
		exitProcess(2)
	}
	verifyAudit360File(path, key, asJSON, quiet)
}

func verifyAudit360File(path, pinnedKey string, asJSON, quiet bool) {
	out := audit360VerifyJSON{
		Format:    "sift.audit360/v2",
		Report:    path,
		KeyPinned: strings.TrimSpace(pinnedKey) != "",
	}

	raw, err := readAudit360Report(path)
	if err != nil {
		emitAudit360Verify(out, err, asJSON, quiet)
		exitProcess(1)
	}
	var report audit360.Audit360Report
	if err := json.Unmarshal(raw, &report); err != nil {
		emitAudit360Verify(out, fmt.Errorf("parse report: %w", err), asJSON, quiet)
		exitProcess(1)
	}
	out.Target = report.TargetURL
	out.Timestamp = report.Timestamp
	out.RiskLevel = report.RiskLevel
	out.ResilienceScore = report.ResilienceScore
	out.CertificateID = report.CertificateID

	check, err := audit360.VerifyReport(&report, pinnedKey)
	if check != nil {
		out.SignerKey = check.SignerKey
		out.SignerFingerprint = check.Fingerprint
		out.CertificateID = check.CertificateID
	}
	if err != nil {
		emitAudit360Verify(out, err, asJSON, quiet)
		exitProcess(1)
	}
	out.Valid = true
	emitAudit360Verify(out, nil, asJSON, quiet)
}

// readAudit360Report reads a report file with a hard size cap.
//
// The limit is applied to the read, not just to a stat before it, so a file
// that grows between the check and the read cannot slip past it.
func readAudit360Report(path string) ([]byte, error) {
	f, err := os.Open(filepath.Clean(path)) // #nosec G304 -- path is an operator-selected report file
	if err != nil {
		return nil, fmt.Errorf("read report: %w", err)
	}
	defer func() { _ = f.Close() }()

	data, err := io.ReadAll(io.LimitReader(f, maxAudit360ReportBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read report: %w", err)
	}
	if len(data) > maxAudit360ReportBytes {
		return nil, fmt.Errorf("read report: file is larger than %d bytes", maxAudit360ReportBytes)
	}
	return data, nil
}

func emitAudit360Verify(out audit360VerifyJSON, verifyErr error, asJSON, quiet bool) {
	if verifyErr != nil {
		out.Valid = false
		out.Error = verifyErr.Error()
	}
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			fatal(err)
		}
		return
	}
	if verifyErr != nil {
		fmt.Fprintln(os.Stderr, "INVALID —", verifyErr)
		if out.SignerKey != "" {
			fmt.Fprintf(os.Stderr, "  signer:  %s\n", out.SignerFingerprint)
		}
		return
	}
	if quiet {
		return
	}
	fmt.Println("VALID — sift.audit360/v2 Ed25519 sealed report")
	fmt.Printf("  target:    %s\n", audit360Display(out.Target))
	fmt.Printf("  audited:   %s\n", audit360Display(out.Timestamp))
	fmt.Printf("  risk:      %s (resilience %d/100)\n", audit360Display(out.RiskLevel), out.ResilienceScore)
	fmt.Printf("  report id: %s\n", audit360Display(out.CertificateID))
	fmt.Printf("  signer:    %s\n", audit360Display(out.SignerFingerprint))
	if !out.KeyPinned {
		fmt.Println()
		fmt.Println("The signer key is recorded inside the signed payload, so this proves the")
		fmt.Println("report is intact — not who produced it. Pin the key to check attribution:")
		fmt.Println("  Sift audit360 verify report.json --key <signer-pubkey-hex>")
	}
}

func audit360Display(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func printAudit360Guide() {
	fmt.Fprint(os.Stderr, `Sift audit360 — verify a sealed Sift 360° audit report

 USAGE
   Sift audit360 verify report.json [flags]

 FLAGS
   --key <hex>   pin the signer public key the report must carry
   --json        machine-readable verdict
   --quiet       print nothing on success

 WHAT IS CHECKED
   The report is sealed with Ed25519 over a SHA-256 digest of a canonical
   payload (sift.audit360/v2), and the certificate id is that digest's first
   16 bytes. Verification recomputes both from the report body, so any edit
   to a score, a finding or a note fails the check.

   The signer key travels inside the signed payload. Without --key the answer
   is "this file is intact". With --key the answer is also "and it came from
   the key I already trust".

 360° audits are run from the dashboard (POST /api/audit-360); download the
 report as signed JSON and verify it anywhere.
`)
}
