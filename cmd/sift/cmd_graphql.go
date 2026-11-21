package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/asadbekabdulboqiyev/sift/internal/authz"
	"github.com/asadbekabdulboqiyev/sift/internal/cliux"
	"github.com/asadbekabdulboqiyev/sift/internal/scanner"
)

// cmd_graphql.go implements `Sift graphql`: the CLI face of the
// dashboard's POST /api/graphql/scan. It POSTs a GraphQL introspection query to
// the endpoint and reports whether introspection is enabled (a serious
// information-disclosure issue) plus any types that look like they expose
// sensitive data.
//
// Every request goes through the probe gate, exactly like the dashboard.
func cmdGraphQL() {
	var target string
	sf := &scanFlags{}

	fs := flag.NewFlagSet("graphql", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	fs.StringVar(&target, "target", "", "GraphQL endpoint URL (required), e.g. https://example.com/graphql")
	addScanGateFlags(fs, sf)

	cliux.Parse(fs, os.Args[2:], func() { printGraphQLHelp(fs) }, cliux.Options{
		Command: "graphql",
		FlagSet: fs,
		Examples: []string{
			"Sift graphql --target https://example.com/graphql",
		},
	})

	if strings.TrimSpace(target) == "" {
		scanUsageExit(sf, fmt.Errorf("--target is required\n\nExample: Sift graphql --target https://example.com/graphql"))
	}
	parsed, err := validateScanTarget(target)
	if err != nil {
		scanUsageExit(sf, err)
	}

	// Authorization gate: graphql is an OpScan operation, like the dashboard's
	// /api/graphql/scan. The decision is recorded before the query is sent.
	authzOut := enforceAuthz(authz.OpScan, []string{parsed.String()}, os.Args, sf.gate)

	scanWarning("graphql")
	announceScanScope("graphql", parsed, sf)

	gate, err := buildScanGuard(parsed, sf, false, scanner.DefaultTimeout, authzOut.ClassValue)
	if err != nil {
		scanUsageExit(sf, err)
	}

	result := scanner.ScanGraphQL(context.Background(), parsed.String(), gate)
	st := gate.Stats()
	printScanGateStats(st)

	if err := emitScanJSON(result, sf); err != nil {
		scanRuntimeExit(sf, err)
	}
	if sf.jsonOut {
		return
	}

	fmt.Printf("graphql: %s\n", result.Endpoint)
	fmt.Printf("  reachable:     %v\n", result.Reachable)
	fmt.Printf("  introspection: %v\n", result.Introspection)
	if result.Schema != "" {
		fmt.Printf("  schema:        %s\n", result.Schema)
	}
	if len(result.Types) > 0 {
		fmt.Printf("  types:         %d\n", len(result.Types))
	}
	fmt.Printf("  scope:         %s\n", scanScopeLabel(parsed, sf))
	if note := scanGateNote(st); note != "" {
		fmt.Printf("  note:          %s\n", note)
	}
	for _, issue := range result.Issues {
		fmt.Printf("  - %s\n", issue)
	}
}

// printGraphQLHelp renders `Sift graphql --help`.
func printGraphQLHelp(fs *flag.FlagSet) {
	w := os.Stderr
	_, _ = fmt.Fprintf(w, "\n Sift graphql — GraphQL introspection scanner\n\n")
	_, _ = fmt.Fprintf(w, " USAGE\n")
	_, _ = fmt.Fprintf(w, "   Sift graphql --target https://example.com/graphql [flags]\n\n")
	_, _ = fmt.Fprintf(w, " Sends a standard introspection query and reports whether the schema is\n")
	_, _ = fmt.Fprintf(w, " exposed, along with types whose names suggest sensitive data. Every\n")
	_, _ = fmt.Fprintf(w, " request passes through the probe gate (scope, rate, budget, dry-run).\n\n")
	_, _ = fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════\n")
	_, _ = fmt.Fprintf(w, " FLAGS\n")
	_, _ = fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════\n")
	cliux.PrintFlagList(w, fs)
	_, _ = fmt.Fprintf(w, "\n═══════════════════════════════════════════════════════════════════\n")
	_, _ = fmt.Fprintf(w, " EXAMPLES\n")
	_, _ = fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════\n")
	for _, e := range []string{
		"# Probe a GraphQL endpoint for introspection",
		"Sift graphql --target https://example.com/graphql",
		"",
		"# Preview the policy without sending anything",
		"Sift graphql --target example.com/graphql --dry-run",
		"",
		"# Machine-readable output",
		"Sift graphql --target https://example.com/graphql --json --output-json graphql.json",
	} {
		_, _ = fmt.Fprintf(w, "\n   %s\n", e)
	}
	_, _ = fmt.Fprintf(w, "\n")
}
