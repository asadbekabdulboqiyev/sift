package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/asadbekabdulboqiyev/sift/internal/authz"
	"github.com/asadbekabdulboqiyev/sift/internal/cliux"
	"github.com/asadbekabdulboqiyev/sift/internal/scanner"
)

// cmd_websocket.go implements `Sift websocket`: the CLI face of the
// dashboard's POST /api/websocket/scan. It connects to a WebSocket endpoint
// (ws:// or wss://) and reports structural weaknesses — missing origin
// validation, absent subprotocol negotiation, whether the server answers an
// unsolicited probe.
//
// Unlike the other scanners, the connect is performed by the gorilla/websocket
// dialer, which does its own TLS/TCP and cannot be routed through the probe
// gate. The guard's scope check also only accepts http/https and would refuse a
// ws:// upgrade, so a nil Requester is passed (mirroring the dashboard). The
// Guard is still constructed to validate the policy knobs, and --dry-run skips
// the dial entirely so a dry run never opens a socket.
func cmdWebSocket() {
	var wsURL string
	sf := &scanFlags{}

	fs := flag.NewFlagSet("websocket", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	fs.StringVar(&wsURL, "url", "", "WebSocket endpoint URL (required), e.g. wss://example.com/socket")
	addScanGateFlags(fs, sf)

	cliux.Parse(fs, os.Args[2:], func() { printWebSocketHelp(fs) }, cliux.Options{
		Command: "websocket",
		FlagSet: fs,
		Examples: []string{
			"Sift websocket --url wss://example.com/socket",
		},
	})

	raw := strings.TrimSpace(wsURL)
	if raw == "" {
		scanUsageExit(sf, fmt.Errorf("--url is required\n\nExample: Sift websocket --url wss://example.com/socket"))
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		scanUsageExit(sf, fmt.Errorf("invalid WebSocket URL %q (expected ws:// or wss://host/path)", raw))
	}
	if parsed.Scheme != "ws" && parsed.Scheme != "wss" {
		scanUsageExit(sf, fmt.Errorf("WebSocket URL must use ws:// or wss://, got %q", parsed.Scheme))
	}

	// Authorization gate: websocket is an OpScan operation, like the dashboard's
	// /api/websocket/scan. A ws:// URL classifies fine (authz parses the host).
	authzOut := enforceAuthz(authz.OpScan, []string{raw}, os.Args, sf.gate)

	scanWarning("websocket")
	announceScanScope("websocket", parsed, sf)

	// The WebSocket client dials on its own, so the guard's dial-time address
	// check is handed to it instead of being dropped.
	gate, err := buildScanGuard(parsed, sf, false, scanner.DefaultTimeout, authzOut.ClassValue)
	if err != nil {
		scanUsageExit(sf, err)
	}
	scanDirectDialNote("websocket", raw)

	if skip, err := scanDryRunSkip("websocket", raw, sf); err != nil {
		scanRuntimeExit(sf, err)
	} else if skip {
		return
	}

	result := scanner.TestWebSocketWithControl(context.Background(), raw, nil, gate.DialControl())

	if err := emitScanDirectDialJSON("websocket", raw, result, sf); err != nil {
		scanRuntimeExit(sf, err)
	}
	if sf.jsonOut {
		return
	}

	fmt.Printf("websocket: %s\n", result.URL)
	fmt.Printf("  connected:   %v\n", result.Connected)
	if result.Subprotocol != "" {
		fmt.Printf("  subprotocol: %s\n", result.Subprotocol)
	}
	fmt.Printf("  messages:    %d\n", result.Messages)
	fmt.Printf("  scope:       %s\n", scanScopeLabel(parsed, sf))
	for _, issue := range result.Issues {
		fmt.Printf("  - %s\n", issue)
	}
}

// printWebSocketHelp renders `Sift websocket --help`.
func printWebSocketHelp(fs *flag.FlagSet) {
	w := os.Stderr
	_, _ = fmt.Fprintf(w, "\n Sift websocket — WebSocket security tester\n\n")
	_, _ = fmt.Fprintf(w, " USAGE\n")
	_, _ = fmt.Fprintf(w, "   Sift websocket --url wss://example.com/socket [flags]\n\n")
	_, _ = fmt.Fprintf(w, " Connects without an Origin header and reports structural weaknesses:\n")
	_, _ = fmt.Fprintf(w, " missing origin validation, absent subprotocol negotiation, and whether\n")
	_, _ = fmt.Fprintf(w, " the server answers an unsolicited probe.\n\n")
	_, _ = fmt.Fprintf(w, " The dial is performed by the WebSocket client, outside the probe\n")
	_, _ = fmt.Fprintf(w, " gate: scope/rate/budget are validated but not enforced on the socket.\n")
	_, _ = fmt.Fprintf(w, " The dial-time address check still applies, so the socket cannot reach\n")
	_, _ = fmt.Fprintf(w, " an address the authorization decision did not approve. Use --dry-run\n")
	_, _ = fmt.Fprintf(w, " to see the intent without opening a connection.\n\n")
	_, _ = fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════\n")
	_, _ = fmt.Fprintf(w, " FLAGS\n")
	_, _ = fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════\n")
	cliux.PrintFlagList(w, fs)
	_, _ = fmt.Fprintf(w, "\n═══════════════════════════════════════════════════════════════════\n")
	_, _ = fmt.Fprintf(w, " EXAMPLES\n")
	_, _ = fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════\n")
	for _, e := range []string{
		"# Test a WebSocket endpoint",
		"Sift websocket --url wss://example.com/socket",
		"",
		"# Preview the policy without connecting",
		"Sift websocket --url wss://example.com/socket --dry-run",
		"",
		"# Machine-readable output",
		"Sift websocket --url wss://example.com/socket --json",
	} {
		_, _ = fmt.Fprintf(w, "\n   %s\n", e)
	}
	_, _ = fmt.Fprintf(w, "\n")
}
