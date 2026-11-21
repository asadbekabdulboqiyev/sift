package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/asadbekabdulboqiyev/sift/internal/authz"
	"github.com/asadbekabdulboqiyev/sift/internal/cliux"
	"github.com/asadbekabdulboqiyev/sift/internal/scanner"
)

// cmd_portscan.go implements `Sift portscan`: the CLI face of the
// dashboard's POST /api/portscan. It performs a TCP connect scan (with light
// banner grabbing) of a curated common-port list, or of an explicit --ports set.
//
// The scanner dials TCP directly. The dashboard still wires the Guard into
// ScanPorts (which ignores it internally); the CLI does the same so the policy
// is validated and the result shape matches. --dry-run skips the scan so it
// never opens a socket.
func cmdPortScan() {
	var (
		target   string
		portsCSV string
	)
	sf := &scanFlags{}

	fs := flag.NewFlagSet("portscan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	fs.StringVar(&target, "target", "", "target host or URL (required), e.g. https://example.com")
	fs.StringVar(&portsCSV, "ports", "", "comma-separated ports to scan (default: built-in common list)")
	addScanGateFlags(fs, sf)

	cliux.Parse(fs, os.Args[2:], func() { printPortScanHelp(fs) }, cliux.Options{
		Command: "portscan",
		FlagSet: fs,
		Examples: []string{
			"Sift portscan --target https://example.com --ports 80,443,8080",
		},
	})

	if strings.TrimSpace(target) == "" {
		scanUsageExit(sf, fmt.Errorf("--target is required\n\nExample: Sift portscan --target https://example.com"))
	}
	parsed, err := validateScanTarget(target)
	if err != nil {
		scanUsageExit(sf, err)
	}
	ports, err := parsePortList(portsCSV)
	if err != nil {
		scanUsageExit(sf, err)
	}

	// Authorization gate: port scanning is an OpScan operation.
	authzOut := enforceAuthz(authz.OpScan, []string{parsed.String()}, os.Args, sf.gate)

	scanWarning("portscan")
	announceScanScope("portscan", parsed, sf)

	gate, err := buildScanGuard(parsed, sf, false, scanner.DefaultTimeout, authzOut.ClassValue)
	if err != nil {
		scanUsageExit(sf, err)
	}
	hostname := parsed.Hostname()
	scanDirectDialNote("portscan", hostname)

	if skip, err := scanDryRunSkip("portscan", hostname, sf); err != nil {
		scanRuntimeExit(sf, err)
	} else if skip {
		return
	}

	result := scanner.ScanPortsWithControl(context.Background(), hostname, ports, gate, gate.DialControl())

	if err := emitScanDirectDialJSON("portscan", hostname, result, sf); err != nil {
		scanRuntimeExit(sf, err)
	}
	if sf.jsonOut {
		return
	}

	fmt.Printf("portscan: %s\n", result.Target)
	fmt.Printf("  open:    %d\n", result.Opened)
	fmt.Printf("  closed:  %d\n", result.Closed)
	fmt.Printf("  scope:   %s\n", scanScopeLabel(parsed, sf))
	for _, p := range result.Ports {
		svc := ""
		if p.Service != "" {
			svc = " (" + p.Service + ")"
		}
		banner := ""
		if p.Banner != "" {
			banner = " — " + oneLine(p.Banner, 80)
		}
		fmt.Printf("  - %d/tcp %s%s%s\n", p.Port, p.State, svc, banner)
	}
	if result.Opened == 0 {
		fmt.Println("  no open ports found")
	}
}

// parsePortList parses a comma-separated port list, rejecting out-of-range and
// non-numeric values and dropping duplicates while preserving order. An empty
// string returns nil, which makes the scanner use its built-in common list.
func parsePortList(s string) ([]int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	seen := make(map[int]bool)
	var out []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: must be a number 1-65535", part)
		}
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("port %d out of range 1-65535", p)
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out, nil
}

// oneLine collapses a banner to a single truncated line so a multi-line server
// response cannot wreck the summary layout.
func oneLine(s string, max int) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if max > 0 && len(s) > max {
		s = s[:max] + "…"
	}
	return s
}

// printPortScanHelp renders `Sift portscan --help`.
func printPortScanHelp(fs *flag.FlagSet) {
	w := os.Stderr
	_, _ = fmt.Fprintf(w, "\n Sift portscan — TCP port & service scanner\n\n")
	_, _ = fmt.Fprintf(w, " USAGE\n")
	_, _ = fmt.Fprintf(w, "   Sift portscan --target https://example.com [--ports 80,443]\n\n")
	_, _ = fmt.Fprintf(w, " TCP connect scan with light banner grabbing over a curated common-port\n")
	_, _ = fmt.Fprintf(w, " list, or an explicit --ports set.\n\n")
	_, _ = fmt.Fprintf(w, " The scanner dials TCP directly, outside the probe gate: scope/rate/\n")
	_, _ = fmt.Fprintf(w, " budget are validated but not enforced on those sockets. The dial-time\n")
	_, _ = fmt.Fprintf(w, " address check still applies, so a socket cannot reach an address the\n")
	_, _ = fmt.Fprintf(w, " authorization decision did not approve. Use --dry-run to see the intent\n")
	_, _ = fmt.Fprintf(w, " without opening a connection.\n\n")
	_, _ = fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════\n")
	_, _ = fmt.Fprintf(w, " FLAGS\n")
	_, _ = fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════\n")
	cliux.PrintFlagList(w, fs)
	_, _ = fmt.Fprintf(w, "\n═══════════════════════════════════════════════════════════════════\n")
	_, _ = fmt.Fprintf(w, " EXAMPLES\n")
	_, _ = fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════\n")
	for _, e := range []string{
		"# Scan the built-in common ports",
		"Sift portscan --target https://example.com",
		"",
		"# Scan a specific set of ports",
		"Sift portscan --target example.com --ports 22,80,443,3306",
		"",
		"# Machine-readable output",
		"Sift portscan --target example.com --ports 80,443 --json",
	} {
		_, _ = fmt.Fprintf(w, "\n   %s\n", e)
	}
	_, _ = fmt.Fprintf(w, "\n")
}
