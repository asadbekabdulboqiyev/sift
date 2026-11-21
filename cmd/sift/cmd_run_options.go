package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/asadbekabdulboqiyev/sift/internal/cliux"
	"github.com/asadbekabdulboqiyev/sift/internal/config"
	"github.com/asadbekabdulboqiyev/sift/internal/fingerprint"
)

// runOptions is the parsed CLI surface of `Sift run`. It is built by
// parseRunOptions and then read-only for the rest of the command, so the
// authorization decision and the engine see exactly the same values.
type runOptions struct {
	fs *flag.FlagSet

	configPath           string
	url                  string
	method               string
	data                 string
	headers              headerFlags
	name                 string
	profile              string
	users                int
	duration             int
	rampUp               int
	spikeUsers           int
	spikeWarmup          int
	spikeHold            int
	wavePeriod           int
	rps                  int
	timeout              int
	keepAlive            bool
	quiet                bool
	reportDir            string
	showVersion          bool
	expectP99            float64
	expectAvg            float64
	expectErrRate        float64
	expectMinRPS         float64
	comparePath          string
	regressPct           float64
	timelineCSV          bool
	preWarm              bool
	preWarmConns         int
	targetRPS            int
	mode                 string
	dashListen           string
	tlsFP                string
	noHTTP2              bool
	coordOmission        bool
	emitBundle           string
	bundleKey            string
	bundleWorker         string
	resourceEvidenceFile string
	authzOpts            gateOptions

	dashAuthTokens      stringListFlags
	dashAuthAPIKeys     stringListFlags
	dashAuthOrigins     stringListFlags
	dashAuthOIDC        stringListFlags
	dashAuthRBAC        stringListFlags
	dashAuthOIDCRoleMap stringListFlags
	dashAuthRBACEnabled bool
	dashAuthRateLimit   float64
	dashAuthBurst       int
	dashAuthProxy       bool
	dashAuthInsecure    bool

	scenario *config.Scenario
}

// newRunFlagSet registers every `Sift run` flag. Help strings are unchanged:
// printRunHelp renders this same FlagSet.
func newRunFlagSet(o *runOptions) *flag.FlagSet {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // suppress raw Go flag noise; we render our own
	fs.Usage = func() {}     // usage dumps are handled explicitly below
	fs.StringVar(&o.configPath, "config", "", "YAML/JSON scenario file")
	fs.StringVar(&o.configPath, "c", "", "shorthand for --config")
	fs.StringVar(&o.url, "url", "", "target URL (quick mode)")
	fs.StringVar(&o.method, "method", "GET", "HTTP method (quick mode)")
	fs.StringVar(&o.data, "data", "", "request body (quick mode)")
	fs.Var(o.headers, "header", "request header in Key=Value form (repeatable)")
	fs.StringVar(&o.name, "name", "quick-test", "report/test name")
	fs.StringVar(&o.profile, "profile", "steady", "load profile: steady, soak, linear-ramp, spike, wave, constant-rps, burst")
	fs.IntVar(&o.users, "users", 10, "concurrent virtual users")
	fs.IntVar(&o.duration, "duration", 30, "test duration in seconds")
	fs.IntVar(&o.rampUp, "ramp-up", 0, "ramp-up duration in seconds")
	fs.IntVar(&o.spikeUsers, "spike-users", 0, "target users for spike burst")
	fs.IntVar(&o.spikeWarmup, "spike-warmup", 5, "baseline warmup seconds before spike")
	fs.IntVar(&o.spikeHold, "spike-hold", 10, "spike burst duration in seconds")
	fs.IntVar(&o.wavePeriod, "wave-period", 0, "oscillation period in seconds (wave)")
	fs.IntVar(&o.rps, "rps", 0, "global pacing cap (requests per second)")
	fs.IntVar(&o.targetRPS, "target-rps", 0, "target requests per second (constant-rps mode)")
	fs.IntVar(&o.timeout, "timeout", 5, "per-request timeout in seconds")
	fs.BoolVar(&o.keepAlive, "keep-alive", true, "reuse TCP connections")
	fs.StringVar(&o.tlsFP, "tls-fingerprint", "", "TLS ClientHello fingerprint (chrome, firefox, safari, edge, ios, android_okhttp, randomized, golang, ...)")
	fs.BoolVar(&o.noHTTP2, "no-http2", false, "disable HTTP/2 negotiation (force HTTP/1.1)")
	fs.BoolVar(&o.coordOmission, "coordinated-omission", false, "apply coordinated-omission correction to paced runs (constant-rps / --rps)")
	fs.StringVar(&o.emitBundle, "emit-bundle", "", "write a verifiable vpmp/v1 evidence bundle (plus its .samples.jsonl sidecar) to this path")
	fs.StringVar(&o.bundleKey, "bundle-key", "", "Ed25519 keypair PEM that seals the bundle (generated ephemerally when omitted)")
	fs.StringVar(&o.bundleWorker, "bundle-worker", "", "worker identity recorded in the bundle (default: hostname, sanitised)")
	fs.StringVar(&o.resourceEvidenceFile, "resource-evidence-file", "", "optional JSON file with resource monitoring evidence (e.g. from 'sift xray report --evidence-out'); attached to report as explicit, non-fabricated evidence")
	fs.StringVar(&o.authzOpts.authorized, "authorized", "", "authorization ticket id recorded by an approver")
	fs.BoolVar(&o.authzOpts.allowPrivate, "allow-private", false, "allow private/link-local targets explicitly")
	fs.StringVar(&o.authzOpts.policyPath, "policy", "", "authorization policy file (default ~/.Sift/authz.json)")
	fs.StringVar(&o.authzOpts.auditPath, "audit-log", "", "audit log file (default ~/.Sift/audit.jsonl)")
	fs.StringVar(&o.authzOpts.webhook, "notify-webhook", "", "webhook URL for audit notifications")
	fs.Float64Var(&o.expectP99, "expect-p99-ms", 0, "SLA: max p99 latency (ms)")
	fs.Float64Var(&o.expectAvg, "expect-avg-ms", 0, "SLA: max avg latency (ms)")
	fs.Float64Var(&o.expectErrRate, "expect-error-rate", 0, "SLA: max error rate (%%)")
	fs.Float64Var(&o.expectMinRPS, "expect-min-rps", 0, "SLA: min throughput")
	fs.StringVar(&o.comparePath, "compare", "", "baseline report for comparison")
	fs.Float64Var(&o.regressPct, "regress-pct", 20, "regression threshold %%")
	fs.BoolVar(&o.timelineCSV, "timeline", false, "write per-second CSV timeline")
	fs.BoolVar(&o.preWarm, "pre-warm", false, "pre-establish TCP connections before test start")
	fs.IntVar(&o.preWarmConns, "pre-warm-conns", 0, "number of pre-warmed connections (default: users count)")
	fs.BoolVar(&o.quiet, "quiet", false, "disable live progress")
	fs.StringVar(&o.reportDir, "report-dir", "./reports", "report output directory")
	fs.BoolVar(&o.showVersion, "version", false, "print version")
	fs.StringVar(&o.mode, "mode", "cli", "output mode: cli (terminal report) | dashboard (real-time web dashboard)")
	fs.StringVar(&o.dashListen, "listen", "127.0.0.1:8888", "dashboard listen address (with --mode dashboard)")
	addRunDashboardFlags(fs, o)
	return fs
}

// addRunDashboardFlags keeps the dashboard auth surface in one place; those
// flags feed dashboard.AuthOptions unchanged in cmdRun.
func addRunDashboardFlags(fs *flag.FlagSet, o *runOptions) {
	fs.Var(&o.dashAuthTokens, "dashboard-auth-token", "bearer token required for the dashboard control API (repeatable)")
	fs.Var(&o.dashAuthAPIKeys, "dashboard-auth-api-key", "SHA-256 hex of an accepted dashboard API key (repeatable)")
	fs.Var(&o.dashAuthOrigins, "dashboard-auth-origin", "allowed origin for state-changing requests (repeatable; CSRF)")
	fs.Var(&o.dashAuthOIDC, "dashboard-auth-oidc", "OIDC issuer:client_id pairs for ID token verification (repeatable; last valid pair wins)")
	fs.Var(&o.dashAuthRBAC, "dashboard-auth-rbac", "subject:role1,role2 role assignments (repeatable; requires --dashboard-auth-oidc)")
	fs.Var(&o.dashAuthOIDCRoleMap, "dashboard-auth-oidc-role-map", "OIDC claim value=local role mapping for claim-derived roles (repeatable; admin targets refused; empty map ignores all claim roles)")
	fs.Float64Var(&o.dashAuthRateLimit, "dashboard-auth-rate-limit", 0, "per-client-IP request rate limit (0 = disabled)")
	fs.IntVar(&o.dashAuthBurst, "dashboard-auth-rate-burst", 0, "rate limiter bucket capacity (default 1)")
	fs.BoolVar(&o.dashAuthProxy, "dashboard-auth-trust-proxy", false, "honor X-Forwarded-For / X-Real-IP for the limiter (only behind a trusted proxy)")
	fs.BoolVar(&o.dashAuthRBACEnabled, "dashboard-auth-rbac-enabled", false, "enable role-based access control for dashboard endpoints")
	fs.BoolVar(&o.dashAuthInsecure, "dashboard-insecure", false, "acknowledge running the unauthenticated dashboard control API on a non-loopback address (demo only)")
}

// parseRunOptions parses flags, resolves a scenario and applies the CLI
// overrides. It returns before scenario work when --version was requested.
func parseRunOptions() *runOptions {
	o := &runOptions{headers: headerFlags{}}
	fs := newRunFlagSet(o)
	o.fs = fs

	// Parse args: os.Args = ["run", "--url", ...] after slicing in main.go.
	// Friendly flag errors, consistent help, exit 2 on usage errors.
	cliux.Parse(fs, os.Args[1:], func() { printRunHelp(fs) }, cliux.Options{
		Command: "run",
		FlagSet: fs,
		Examples: []string{
			"Sift run --url https://api.example.com --users 10 --duration 10",
		},
	})

	if o.showVersion {
		fmt.Printf("Sift v%s\n", buildVersion)
		return o
	}

	o.scenario = buildRunScenario(o)
	o.normalizeMode()
	return o
}

// buildRunScenario loads or constructs the scenario and applies every CLI
// override that changes it (TLS fingerprint, coordinated omission, SLA).
func buildRunScenario(o *runOptions) *config.Scenario {
	nameSet, durationSet := o.explicitFlags()

	// burst: a short, maximum-speed volley — every user from t=0, no RPS cap.
	// Defaults to a 3-second window unless --duration is given explicitly.
	if o.profile == "burst" && !durationSet {
		o.duration = 3
	}

	var scenario *config.Scenario
	if o.configPath != "" {
		sc, err := config.Load(o.configPath)
		if err != nil {
			fatal(err)
		}
		if nameSet {
			sc.Name = o.name
		}
		scenario = sc
	} else {
		if o.url == "" {
			fatal(fmt.Errorf("either --config or --url is required\n\nExample: Sift run --url https://api.example.com --users 10 --duration 10"))
		}
		// When --target-rps is set, automatically use constant-rps profile.
		if o.targetRPS > 0 && o.profile == "steady" {
			o.profile = "constant-rps"
		}
		sc, err := quickScenario(o.name, o.url, o.method, o.data, o.headers, o.profile,
			o.users, o.duration, o.rampUp, o.spikeUsers, o.spikeWarmup, o.spikeHold,
			o.wavePeriod, o.rps, o.targetRPS, o.timeout, o.keepAlive)
		if err != nil {
			fatal(err)
		}
		scenario = sc
	}

	if o.tlsFP != "" {
		if !fingerprint.Profile(o.tlsFP).Valid() {
			fatal(fmt.Errorf("unknown -tls-fingerprint %q (valid values: %s)", o.tlsFP, strings.Join(fingerprint.Names(), ", ")))
		}
		scenario.Profile.TLSFingerprint = o.tlsFP
	}

	// Coordinated-omission correction is only meaningful for paced runs: with
	// no arrival schedule (no limiter) there is nothing to fall behind.
	if o.coordOmission {
		scenario.Profile.CoordinatedOmission = true
		if scenario.Profile.RPS <= 0 && !scenario.Profile.IsConstantRPS() {
			fmt.Fprintln(os.Stderr, "WARNING: --coordinated-omission has no effect without pacing; add --target-rps or --rps")
		}
	}

	applyRunSLA(scenario, o)
	return scenario
}

// explicitFlags reports which flags the operator actually set, so --name only
// overrides a scenario's name when it was given on the command line.
func (o *runOptions) explicitFlags() (nameSet, durationSet bool) {
	o.fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "name":
			nameSet = true
		case "duration":
			durationSet = true
		}
	})
	return nameSet, durationSet
}

// applyRunSLA overlays the --expect-* flags onto the scenario SLA.
func applyRunSLA(scenario *config.Scenario, o *runOptions) {
	sla := scenario.SLA
	if sla == nil {
		sla = &config.SLA{}
	}
	if o.expectP99 > 0 {
		sla.MaxP99Ms = o.expectP99
	}
	if o.expectAvg > 0 {
		sla.MaxAvgMs = o.expectAvg
	}
	if o.expectErrRate > 0 {
		sla.MaxErrorRatePct = o.expectErrRate
	}
	if o.expectMinRPS > 0 {
		sla.MinRPS = o.expectMinRPS
	}
	if !sla.Empty() {
		scenario.SLA = sla
	}
}

func (o *runOptions) normalizeMode() {
	o.mode = strings.ToLower(strings.TrimSpace(o.mode))
	if o.mode != "cli" && o.mode != "dashboard" {
		fatal(fmt.Errorf("invalid --mode %q: must be 'cli' or 'dashboard'", o.mode))
	}
}
