package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/asadbekabdulboqiyev/sift/internal/authz"
	"github.com/asadbekabdulboqiyev/sift/internal/cliux"
	"github.com/asadbekabdulboqiyev/sift/internal/scanner"
)

// cmd_sslscan.go implements `Sift sslscan`: the CLI face of the
// dashboard's POST /api/sslscan. It performs a TLS handshake and reports the
// certificate (issuer, subject, validity window, SANs) plus protocol/cipher
// weaknesses.
//
// The handshake dials TLS directly, so it cannot route through the Guard. The
// Guard is still built to validate the policy knobs, and --dry-run skips the
// handshake so it never opens a socket.
func cmdSSLScan() {
	var target string
	sf := &scanFlags{}

	fs := flag.NewFlagSet("sslscan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	fs.StringVar(&target, "target", "", "target host or URL (required), e.g. https://example.com")
	addScanGateFlags(fs, sf)

	cliux.Parse(fs, os.Args[2:], func() { printSSLScanHelp(fs) }, cliux.Options{
		Command: "sslscan",
		FlagSet: fs,
		Examples: []string{
			"Sift sslscan --target https://example.com",
		},
	})

	if strings.TrimSpace(target) == "" {
		scanUsageExit(sf, fmt.Errorf("--target is required\n\nExample: Sift sslscan --target https://example.com"))
	}
	parsed, err := validateScanTarget(target)
	if err != nil {
		scanUsageExit(sf, err)
	}

	// Authorization gate: a TLS inspection is an OpScan operation.
	authzOut := enforceAuthz(authz.OpScan, []string{parsed.String()}, os.Args, sf.gate)

	scanWarning("sslscan")
	announceScanScope("sslscan", parsed, sf)

	// The TLS dial does not go through the Guard's HTTP client, so the guard's
	// dial-time address check is handed to it instead of being dropped.
	gate, err := buildScanGuard(parsed, sf, false, scanner.DefaultTimeout, authzOut.ClassValue)
	if err != nil {
		scanUsageExit(sf, err)
	}

	// ScanSSL needs host:port; parsed.String() carries the scheme, which breaks
	// dialing. Use the explicit port when present, else 443 for https and 80 for
	// http — exactly like the dashboard.
	var scanTarget string
	if p := parsed.Port(); p != "" {
		scanTarget = net.JoinHostPort(parsed.Hostname(), p)
	} else if parsed.Scheme == "https" {
		scanTarget = net.JoinHostPort(parsed.Hostname(), "443")
	} else {
		scanTarget = net.JoinHostPort(parsed.Hostname(), "80")
	}
	scanDirectDialNote("sslscan", scanTarget)

	if skip, err := scanDryRunSkip("sslscan", scanTarget, sf); err != nil {
		scanRuntimeExit(sf, err)
	} else if skip {
		return
	}

	result := scanner.ScanSSLWithControl(context.Background(), scanTarget, gate.DialControl())

	if err := emitScanDirectDialJSON("sslscan", scanTarget, result, sf); err != nil {
		scanRuntimeExit(sf, err)
	}
	if sf.jsonOut {
		return
	}

	fmt.Printf("sslscan: %s\n", result.Target)
	fmt.Printf("  valid:     %v\n", result.Valid)
	fmt.Printf("  expired:   %v\n", result.Expired)
	if result.Version != "" {
		fmt.Printf("  version:   %s\n", result.Version)
	}
	if result.Cipher != "" {
		fmt.Printf("  cipher:    %s\n", result.Cipher)
	}
	if result.Issuer != "" {
		fmt.Printf("  issuer:    %s\n", result.Issuer)
	}
	if result.Subject != "" {
		fmt.Printf("  subject:   %s\n", result.Subject)
	}
	if result.NotBefore != "" {
		fmt.Printf("  notBefore: %s\n", result.NotBefore)
	}
	if result.NotAfter != "" {
		fmt.Printf("  notAfter:  %s\n", result.NotAfter)
	}
	if len(result.SANs) > 0 {
		fmt.Printf("  sans:      %s\n", strings.Join(result.SANs, ", "))
	}
	fmt.Printf("  scope:     %s\n", scanScopeLabel(parsed, sf))
	for _, issue := range result.Issues {
		fmt.Printf("  - %s\n", issue)
	}
}

// printSSLScanHelp renders `Sift sslscan --help`.
func printSSLScanHelp(fs *flag.FlagSet) {
	w := os.Stderr
	_, _ = fmt.Fprintf(w, "\n Sift sslscan — TLS certificate & configuration analyzer\n\n")
	_, _ = fmt.Fprintf(w, " USAGE\n")
	_, _ = fmt.Fprintf(w, "   Sift sslscan --target https://example.com [flags]\n\n")
	_, _ = fmt.Fprintf(w, " Performs a TLS handshake and reports the certificate (issuer, subject,\n")
	_, _ = fmt.Fprintf(w, " validity window, SANs) plus protocol and cipher weaknesses.\n\n")
	_, _ = fmt.Fprintf(w, " The handshake dials TLS directly, outside the probe gate: scope/\n")
	_, _ = fmt.Fprintf(w, " rate/budget are validated but not enforced on that connection. The\n")
	_, _ = fmt.Fprintf(w, " dial-time address check still applies, so the socket cannot reach an\n")
	_, _ = fmt.Fprintf(w, " address the authorization decision did not approve. Use --dry-run to\n")
	_, _ = fmt.Fprintf(w, " see the intent without connecting.\n\n")
	_, _ = fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════\n")
	_, _ = fmt.Fprintf(w, " FLAGS\n")
	_, _ = fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════\n")
	cliux.PrintFlagList(w, fs)
	_, _ = fmt.Fprintf(w, "\n═══════════════════════════════════════════════════════════════════\n")
	_, _ = fmt.Fprintf(w, " EXAMPLES\n")
	_, _ = fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════\n")
	for _, e := range []string{
		"# Inspect a TLS endpoint",
		"Sift sslscan --target https://example.com",
		"",
		"# Use an explicit port",
		"Sift sslscan --target https://example.com:8443",
		"",
		"# Machine-readable output",
		"Sift sslscan --target https://example.com --json --output-json tls.json",
	} {
		_, _ = fmt.Fprintf(w, "\n   %s\n", e)
	}
	_, _ = fmt.Fprintf(w, "\n")
}
