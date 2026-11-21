package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/attest"
	"github.com/asadbekabdulboqiyev/sift/internal/authz"
	"github.com/asadbekabdulboqiyev/sift/internal/cliux"
	"github.com/asadbekabdulboqiyev/sift/internal/config"
	"github.com/asadbekabdulboqiyev/sift/internal/engine"
	"github.com/asadbekabdulboqiyev/sift/internal/evidence"
	"github.com/asadbekabdulboqiyev/sift/internal/report"
)

type headerFlags map[string]string

func (h headerFlags) String() string { return "" }
func (h headerFlags) Set(value string) error {
	parts := strings.SplitN(value, "=", 2)
	if len(parts) != 2 || parts[0] == "" {
		return fmt.Errorf("header must be in Key=Value form, got %q", value)
	}
	h[parts[0]] = parts[1]
	return nil
}

// stringListFlags collects a repeatable string flag (e.g. -auth-token a -auth-token b).
type stringListFlags []string

func (s *stringListFlags) String() string { return strings.Join(*s, ",") }
func (s *stringListFlags) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// cmdRun is the orchestrator: parse, authorize, build, execute, render. Each
// stage owns one concern and keeps the authorization decision visible until
// the dial-time control is installed in buildRunGate.
func cmdRun() {
	opts := parseRunOptions()
	if opts.showVersion {
		return
	}

	decision := authorizeRun(opts.scenario, opts)
	baseline := loadRunBaseline(opts)

	// Dashboard mode: open the real-time WebSocket dashboard and drive the
	// real load engine from the browser. No terminal report is printed.
	if opts.mode == "dashboard" {
		runWithDashboard(opts.scenario, opts.dashListen, opts.reportDir, dashboardAuthOptions(opts))
		return
	}

	applyRunPreWarm(opts)
	printRunWarnings(opts)
	applyRunTransportOptions(opts)
	eng := buildRunGate(opts.scenario, decision)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		second := make(chan os.Signal, 1)
		signal.Notify(second, os.Interrupt, syscall.SIGTERM)
		<-second
		exitProcess(130)
	}()

	r, collector := executeRun(ctx, opts, eng)
	renderRunReport(opts, r, collector, baseline)
}

// authorizeRun is the admission gate for a load test. The decision is kept by
// cmdRun and re-applied at dial time in buildRunGate: a DNS answer that changes
// after classification must not send traffic to a more restrictive network.
func authorizeRun(scenario *config.Scenario, o *runOptions) authzOutcome {
	authDecision := enforceAuthz(authz.OpLoadTest, scenarioTargets(scenario), os.Args, o.authzOpts)
	return authDecision
}

// buildRunGate creates the engine with the socket-level hook. Without it the
// gate is only an admission check: a name approved as public could rebind to
// link-local/metadata before the engine connects. The approved class from the
// authorization decision is installed as the dial control.
func buildRunGate(scenario *config.Scenario, authDecision authzOutcome) *engine.Engine {
	eng, err := engine.NewWithControl(scenario, authz.DialControl(authDecision.ClassValue))
	if err != nil {
		fatal(err)
	}
	return eng
}

func quickScenario(name, url, method, data string, headers headerFlags, profile string, users, duration, rampUp, spikeUsers, spikeWarmup, spikeHold, wavePeriod, rps, targetRPS, timeout int, keepAlive bool) (*config.Scenario, error) {
	sc := &config.Scenario{
		Name: name,
		Profile: config.Profile{
			Type:        profile,
			Users:       users,
			Duration:    duration,
			RampUp:      rampUp,
			SpikeUsers:  spikeUsers,
			SpikeWarmup: spikeWarmup,
			SpikeHold:   spikeHold,
			WavePeriod:  wavePeriod,
			RPS:         rps,
			TargetRPS:   targetRPS,
			Timeout:     timeout,
			KeepAlive:   &keepAlive,
		},
		Steps: []config.Step{
			{
				Name:    "request",
				Method:  method,
				URL:     url,
				Headers: headers,
				Body:    data,
			},
		},
	}
	if err := sc.Normalize(); err != nil {
		return nil, err
	}
	return sc, nil
}

func targetDisplay(scenario *config.Scenario) string {
	if scenario.BaseURL != "" {
		return scenario.BaseURL
	}
	if len(scenario.Steps) > 0 {
		return scenario.Steps[0].URL
	}
	return "n/a"
}

// printRunHelp renders `Sift run --help` in the same sectioned,
// two-dash style as the top-level help, with real examples.
func printRunHelp(fs *flag.FlagSet) {
	w := os.Stderr
	_, _ = fmt.Fprintf(w, "\n Sift run — HTTP/gRPC/WebSocket load test\n\n")
	_, _ = fmt.Fprintf(w, " USAGE\n")
	_, _ = fmt.Fprintf(w, "   Sift run --url https://api.example.com --users 100 --duration 60\n")
	_, _ = fmt.Fprintf(w, "   Sift run --url https://api.example.com --target-rps 1000 --duration 30\n")
	_, _ = fmt.Fprintf(w, "   Sift run --url https://api.example.com --profile burst --users 500\n")
	_, _ = fmt.Fprintf(w, "   Sift run --config scenario.yaml\n\n")
	_, _ = fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════\n")
	_, _ = fmt.Fprintf(w, " FLAGS\n")
	_, _ = fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════\n")
	cliux.PrintFlagList(w, fs)
	_, _ = fmt.Fprintf(w, "\n═══════════════════════════════════════════════════════════════════\n")
	_, _ = fmt.Fprintf(w, " EXAMPLES\n")
	_, _ = fmt.Fprintf(w, "═══════════════════════════════════════════════════════════════════\n")
	for _, e := range []string{
		"# Simple load test",
		"Sift run --url https://api.example.com --users 100 --duration 60",
		"",
		"# Constant RPS mode (1000 requests/sec)",
		"Sift run --url https://api.example.com --target-rps 1000 --duration 30",
		"",
		"# Constant RPS with coordinated-omission correction (trustworthy p99 under saturation)",
		"Sift run --url https://api.example.com --target-rps 1000 --duration 30 --coordinated-omission",
		"",
		"# SEAL THE RESULT: emit verifiable evidence a third party can check offline",
		"Sift keygen --out operator.key",
		"Sift run --url https://api.example.com --target-rps 1000 --duration 30 --coordinated-omission \\",
		"    --emit-bundle bundle.json --bundle-key operator.key",
		"Sift verify --bundle bundle.json --samples bundle.samples.jsonl   # 0 = valid, 1 = tampered",
		"",
		"# Burst: 3s maximum-speed volley, all users at once, no RPS cap",
		"Sift run --url https://api.example.com --profile burst --users 500",
		"",
		"# Advanced scenario: branching, retries, think time",
		"Sift run --config examples/branching-flow.yaml",
		"",
		"# Client-streaming gRPC load test",
		"Sift run --config examples/streaming.yaml",
		"",
		"# Compare with a baseline report (exit 2 on regression)",
		"Sift run --url https://api.example.com --users 50 --duration 30 --compare reports/baseline.json",
		"",
		"# SLA gate for CI/CD (exit code 2 on failure)",
		"Sift run --url https://api.example.com --users 50 --duration 30 --expect-p99-ms 200 --expect-error-rate 1",
		"",
		"# YAML scenario file",
		"Sift run --config examples/login-flow.yaml",
		"",
		"# Real-time web dashboard output",
		"Sift run --url https://api.example.com --users 100 --duration 60 --mode dashboard",
	} {
		_, _ = fmt.Fprintf(w, "\n   %s\n", e)
	}
	_, _ = fmt.Fprintf(w, "\n")
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	exitProcess(1)
}

// defaultWorkerID names this process as a worker in an evidence bundle. A
// bundle records who measured what, so the identity has to be stable enough for
// an auditor to pin it later: hostname plus pid does that without any
// configuration.
func defaultWorkerID() string {
	host, err := os.Hostname()
	if err != nil || strings.TrimSpace(host) == "" {
		host = "local"
	}
	return fmt.Sprintf("%s-%d", host, os.Getpid())
}

// coCorrectionGate reports why the coordinated-omission correction may not be
// claimed for a run, or "" when it may.
//
// The correction answers one question: a request was served late after waiting
// for its slot; how long did the user actually wait? That question only has an
// answer when the client kept a *fixed arrival schedule*. A steady (or soak)
// profile with a fixed --rps cap is the one shape where that holds: the profile
// maps to a fixed number of workers for the whole run, and the rate cap applies
// from the first millisecond. Every other shape moves its own target —
// constant-rps ramps over half the run by default, and linear-ramp, spike and
// wave vary it by construction — so arrivals are late *by design* and the same
// arithmetic would manufacture queue time nobody waited for. Observed on a
// ramped run: a raw p99 of 0.8 ms became a "corrected" p99 of 1.35 s, entirely
// generator lag.
//
// Note what the gate deliberately does NOT require: that the client kept up.
// Falling behind is the very situation the correction exists to measure, so a
// saturated run still gets a corrected tail. The shortfall stays visible instead
// of being hidden: the integrity block seals the planned and achieved rates and
// the dropped-sample count either way.
//
// The check keys off the profile, not off Profile.RampUp: Normalize fills
// RampUp with Duration/2 for *every* scenario, including steady ones, and the
// steady profile never reads it (it holds a fixed worker count for the whole
// run). Testing the ramp field would therefore reject exactly the runs whose
// schedule is provably constant.
func coCorrectionGate(scenario *config.Scenario, plannedMilli int64) string {
	switch {
	case plannedMilli <= 0:
		return "the run had no pacing rate (no --rps / --target-rps)"
	case scenario.Profile.Type != config.ProfileSteady && scenario.Profile.Type != config.ProfileSoak:
		return fmt.Sprintf("the %q profile moves its own arrival target over the run, so its schedule is not constant", scenario.Profile.Type)
	}
	return ""
}

// bundleKeypair loads the operator's signing keypair, or mints a throwaway one
// so that even a one-off run can produce a sealed bundle. The second return
// value reports whether the key is ephemeral: an ephemeral seal still proves
// the evidence was fixed before it was published, but nobody can attribute it
// to a key they already trust, so a real workflow uses --bundle-key with a key
// from `Sift keygen`.
func bundleKeypair(path string) (*attest.Keypair, bool, error) {
	if p := strings.TrimSpace(path); p != "" {
		kp, err := attest.LoadKeypairPEM(p)
		if err != nil {
			return nil, false, fmt.Errorf("emit-bundle: %w", err)
		}
		return kp, false, nil
	}
	kp, err := attest.GenerateKeypair()
	if err != nil {
		return nil, false, fmt.Errorf("emit-bundle: %w", err)
	}
	return kp, true, nil
}

// emitEvidenceBundle seals the collected measurements into a signed vpmp/v1
// bundle and writes it beside its sample sidecar.
//
// Nothing here is copied out of the terminal report. Every sealed number is
// recomputed from the raw records, so the bundle is an independent statement
// about the same run: if the report and the bundle ever disagree, the report is
// wrong — not the bundle. When a completed run report is available, its actual
// (monotonic, elapsed) duration is used; otherwise the planned profile duration
// is used as a fallback.
func emitEvidenceBundle(path, keyPath string, collector *evidence.Collector, scenario *config.Scenario, runReport *report.Report) error {
	plannedMilli := evidence.PlannedRPSMilli(scenario)
	planned, err := attest.DecimalFromMilli(plannedMilli)
	if err != nil {
		return fmt.Errorf("emit-bundle: planned rate %d: %w", plannedMilli, err)
	}

	kp, ephemeral, err := bundleKeypair(keyPath)
	if err != nil {
		return err
	}

	// The coordinated-omission correction is defined against a pacing schedule,
	// so it may only be claimed when the run actually had one and kept it (see
	// coCorrectionGate). Otherwise the bundle says plainly that it carries raw
	// percentiles instead of inventing a schedule to correct against.
	co := scenario.Profile.CoordinatedOmission
	durationNS := int64(scenario.Profile.TotalDuration()) * int64(time.Second)
	if runReport != nil && runReport.Duration > 0 {
		// Prefer actual measured (monotonic) run duration for integrity metadata.
		durationNS = runReport.Duration.Nanoseconds()
	}
	// The correction may only be claimed when the run had a pacing schedule and
	// kept it. When it did not — no pacing rate, a ramped run, or a client that
	// fell behind — the same arithmetic adds queue time nobody waited for, so the
	// claim is withheld with the reason stated. The gate reads the same raw count
	// and rate the integrity block seals, so the claim and the sealed numbers
	// always agree.
	if co {
		if reason := coCorrectionGate(scenario, plannedMilli); reason != "" {
			fmt.Fprintln(os.Stderr, "emit-bundle: coordinated-omission correction withheld —", reason)
			fmt.Fprintln(os.Stderr, "  The bundle records raw percentiles, co_corrected=false: honest, but uncorrected.")
			co = false
		}
	}

	bundle, err := evidence.BuildBundle(evidence.BundleInput{
		Collector:      collector,
		WorkerKey:      kp,
		CoordinatorKey: kp,
		Tool:           attest.Tool{Name: "Sift", Version: buildVersion},
		Run: attest.Run{
			Target:     targetDisplay(scenario),
			Profile:    scenario.Profile.Type,
			DurationNS: durationNS,
			PlannedRPS: planned,
		},
		// In a local run one operator both measures and claims, so the worker
		// commitment and the coordinator seal share an identity. Distributed
		// runs give each worker its own key (internal/dist/coordinator).
		COCorrected: co,
	})
	if err != nil {
		return err
	}

	sidecar, err := evidence.WriteBundle(bundle, collector.Records(), path)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "\nVerifiable evidence written:\n  %s\n  %s\n", path, sidecar)
	fmt.Fprintf(os.Stderr, "  format:        %s — %d samples, worker %q\n", bundle.Format, bundle.Aggregate.Count, bundle.Workers[0].ID)
	fmt.Fprintf(os.Stderr, "  coordinator:   %s\n", bundle.Signature.Key)
	if ephemeral {
		fmt.Fprintln(os.Stderr, "  note:          the seal key was generated for this run; pin it with --bundle-key to make the claim attributable")
	}
	if bundle.Aggregate.COCorrected {
		fmt.Fprintf(os.Stderr, "  p99:           %s (coordinated-omission corrected, 95%% CI %s)\n",
			asMillis(bundle.Aggregate.P99NS), millisInterval(bundle.Aggregate.COCI95NS.LowNS, bundle.Aggregate.COCI95NS.HighNS))
	} else {
		fmt.Fprintf(os.Stderr, "  p99:           %s (raw, uncorrected)\n", asMillis(bundle.Aggregate.P99NS))
	}
	fmt.Fprintf(os.Stderr, "  verify it yourself (exit 0 = valid, 1 = tampered):\n    Sift verify --bundle %s --samples %s\n", path, sidecar)
	return nil
}

// asMillis renders a nanosecond duration for humans only. The bundle itself is
// integer nanoseconds throughout; this is display formatting, not a
// measurement.
func asMillis(ns int64) string { return fmt.Sprintf("%.3fms", float64(ns)/1e6) }

func millisInterval(lowNS, highNS int64) string {
	return fmt.Sprintf("[%s, %s]", asMillis(lowNS), asMillis(highNS))
}
