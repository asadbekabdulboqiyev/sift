package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/dashboard"
	"github.com/asadbekabdulboqiyev/sift/internal/engine"
	"github.com/asadbekabdulboqiyev/sift/internal/evidence"
	"github.com/asadbekabdulboqiyev/sift/internal/report"
)

// dashboardAuthOptions translates the CLI auth flags into the dashboard's
// auth options without changing any default or validation.
func dashboardAuthOptions(o *runOptions) dashboard.AuthOptions {
	// Mirror the standalone sift-dashboard flags: --dashboard-auth-oidc takes
	// issuer:client_id pairs (the last valid pair wins) and --dashboard-auth-rbac
	// takes subject:role1,role2 assignments. Split on the LAST colon so an
	// issuer that is a URL ("https://issuer.example.com:client-id") works too.
	// The role claim defaults to "role", matching sift-dashboard's hardcoded
	// value; it stays empty when OIDC is not configured so existing defaults
	// are untouched.
	var oidcIssuer, oidcClientID, roleClaim string
	for _, entry := range o.dashAuthOIDC {
		idx := strings.LastIndex(entry, ":")
		if idx <= 0 || idx == len(entry)-1 {
			continue
		}
		oidcIssuer = strings.TrimSpace(entry[:idx])
		oidcClientID = strings.TrimSpace(entry[idx+1:])
	}
	if oidcIssuer != "" && oidcClientID != "" {
		roleClaim = "role"
	}

	return dashboard.AuthOptions{
		Tokens:         o.dashAuthTokens,
		APIKeyHashes:   o.dashAuthAPIKeys,
		AllowedOrigins: o.dashAuthOrigins,
		RateLimitRPS:   o.dashAuthRateLimit,
		RateLimitBurst: o.dashAuthBurst,
		TrustProxy:     o.dashAuthProxy,
		AllowAnonymous: o.dashAuthInsecure,
		OIDCIssuer:     oidcIssuer,
		OIDCClientID:   oidcClientID,
		OIDCRoleClaim:  roleClaim,
		RBACEnabled:    o.dashAuthRBACEnabled,
		RBACRole:       o.dashAuthRBAC,
	}
}

func applyRunPreWarm(o *runOptions) {
	if o.preWarm {
		o.scenario.PreWarm = true
		if o.preWarmConns > 0 {
			o.scenario.PreWarmConnections = o.preWarmConns
		}
	}
}

func printRunWarnings(o *runOptions) {
	fmt.Fprintln(os.Stderr, "WARNING: Sift is a load testing tool. Only run it against systems you own or")
	fmt.Fprintln(os.Stderr, "have explicit written permission to test. Unauthorized load floods are illegal (DDoS).")
	if o.scenario.Profile.TLSFingerprint != "" {
		fmt.Fprintf(os.Stderr, "TLS fingerprint: masking ClientHello as %q (JA3-mitigation bypass)\n", o.scenario.Profile.TLSFingerprint)
	}
}

// applyRunTransportOptions maps --no-http2 onto the profile (nil = enabled,
// true by default). The transport wiring itself lives in internal/engine/client.go.
func applyRunTransportOptions(o *runOptions) {
	if o.noHTTP2 {
		off := false
		o.scenario.Profile.Http2 = &off
	}
}

// executeRun drives the engine and assembles the report. It does not write or
// print anything: gating and persistence are renderRunReport's job, so a run
// that trips a gate still leaves its evidence behind.
func executeRun(ctx context.Context, o *runOptions, eng *engine.Engine) (*report.Report, *evidence.Collector) {
	fmt.Fprintf(os.Stderr, "Sift v%s | target: %s | profile: %s | duration: %ds\n",
		buildVersion, targetDisplay(o.scenario), o.scenario.Profile.Type, o.scenario.Profile.TotalDuration())

	var progress *engine.ProgressTracker
	if !o.quiet {
		dur := time.Duration(o.scenario.Profile.TotalDuration()) * time.Second
		progress = engine.NewProgressTracker(dur, o.scenario.Profile.Users)
	}

	// Sift: when a bundle is requested, every measured request is fed to a
	// collector as well, so the evidence pack is built from the same
	// measurements the report is — not from a summary of them.
	var collector *evidence.Collector
	var err error
	runOpts := engine.RunOptions{Out: os.Stderr, Quiet: o.quiet, Progress: progress}
	if strings.TrimSpace(o.emitBundle) != "" {
		worker := strings.TrimSpace(o.bundleWorker)
		if worker == "" {
			worker = defaultWorkerID()
		}
		collector, err = evidence.NewCollector(worker)
		if err != nil {
			fatal(err)
		}
		runOpts.Samples = collector
	}

	telemetry, err := eng.Run(ctx, runOpts)
	if err != nil {
		fatal(err)
	}
	if progress != nil {
		progress.Finish()
	}

	r := report.Build(telemetry, o.scenario)
	if strings.TrimSpace(o.resourceEvidenceFile) != "" {
		b, readErr := os.ReadFile(o.resourceEvidenceFile)
		if readErr != nil {
			fatal(fmt.Errorf("resource evidence: read %s: %w", o.resourceEvidenceFile, readErr))
		}
		if !json.Valid(b) {
			fatal(fmt.Errorf("resource evidence: %s is not valid JSON", o.resourceEvidenceFile))
		}
		r.ResourceEvidence = json.RawMessage(b)
	}
	return &r, collector
}
