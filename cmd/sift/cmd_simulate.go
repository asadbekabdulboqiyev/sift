package main

// cmd_simulate.go — digital twin / capacity simulation.
//
// `simulate fit` turns a completed Sift report into a versioned capacity model
// (twin-model.json). `simulate run` answers one what-if question against that
// model. `simulate compare` runs the three built-in scenarios (best, likely,
// worst) and prints a comparison table. Every command writes JSON artifacts plus
// a Markdown report that restates the estimate-not-guarantee caveat.
//
//	exit status
//	  0   the command succeeded
//	  1   invalid input, an unreadable artifact, or the simulation failed
//	  3   the estimated SLA breach probability exceeded --fail-on-breach-prob
//	      (the gate is disabled when the flag is 0)
//
// The exit-3 gate writes the artifacts before exiting, so CI keeps the evidence
// that justified the failure.

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/report"
	"github.com/asadbekabdulboqiyev/sift/internal/twin"
)

const defaultTwinOutDir = "reports/twin"

// cmdSimulate dispatches: Sift simulate <fit|run|compare|validate|backtest> [flags].
func cmdSimulate() {
	if len(os.Args) < 3 {
		simulateUsage()
		exitProcess(1)
	}
	switch os.Args[2] {
	case "fit":
		simulateFit(os.Args[3:])
	case "run":
		simulateRun(os.Args[3:])
	case "compare":
		simulateCompare(os.Args[3:])
	case "validate":
		simulateValidate(os.Args[3:])
	case "backtest":
		simulateBacktest(os.Args[3:])
	default:
		simulateUsage()
		exitProcess(1)
	}
}

// simulateFit implements: Sift simulate fit --report <path> --out <dir>.
func simulateFit(args []string) {
	fs := flag.NewFlagSet("simulate fit", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	reportPath := fs.String("report", "", "path to a Sift report JSON (required)")
	outDir := fs.String("out", defaultTwinOutDir, "directory for twin-model.json")
	targetP99 := fs.Float64("target-p99-ms", 0, "latency objective used for capacity headroom (0 = documented default)")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			simulateUsage()
			return
		}
		simulateUsage()
		exitProcess(1)
	}
	if strings.TrimSpace(*reportPath) == "" || fs.NArg() > 0 {
		simulateUsage()
		exitProcess(1)
	}
	if *targetP99 < 0 {
		fatal(fmt.Errorf("simulate fit: --target-p99-ms must not be negative, got %v", *targetP99))
	}

	rep, err := report.LoadReport(*reportPath)
	if err != nil {
		fatal(fmt.Errorf("simulate fit: load report: %w", err))
	}
	model, err := twin.Fit(*rep, twin.FitOptions{TargetP99MS: *targetP99})
	if err != nil {
		fatal(fmt.Errorf("simulate fit: %w", err))
	}
	path, err := twin.WriteModel(*outDir, model)
	if err != nil {
		fatal(fmt.Errorf("simulate fit: %w", err))
	}

	fmt.Printf("model written: %s\n", path)
	fmt.Printf("  source report:     %s (%s, %s)\n",
		fallback(model.Source.ReportName, "unnamed"),
		fallback(model.Source.LoadProfile, "profile n/a"),
		formatSeconds(model.Source.DurationSeconds))
	fmt.Printf("  observed workload: %.2f rps, %.2f concurrent, %.3f%% errors\n",
		model.Workload.RPS, model.Workload.Concurrency, model.Workload.ErrorRatePct)
	fmt.Printf("  baseline latency:  p50 %.2f ms, p95 %.2f ms, p99 %.2f ms\n",
		model.Curve.Baseline.P50MS, model.Curve.Baseline.P95MS, model.Curve.Baseline.P99MS)
	if model.ConfidenceV2 != nil {
		fmt.Printf("  confidence:        %s (%.1f/100, evidence=%t, data_quality=%s)\n",
			model.ConfidenceV2.Level, model.ConfidenceV2.Score, model.ConfidenceV2.Sufficient, model.ConfidenceV2.DataQuality)
		fmt.Printf("  confidence reason: %s\n", model.ConfidenceV2.Summary)
		if len(model.ConfidenceV2.MissingData) > 0 {
			fmt.Printf("  missing data:      %s\n", strings.Join(model.ConfidenceV2.MissingData, ", "))
		}
	} else {
		fmt.Printf("  confidence:        %s\n", model.Confidence)
	}
	if model.Capacity != nil {
		fmt.Printf("  observed capacity: %.2f rps (observed_is_max=false)\n", model.Capacity.ObservedRPS)
		switch model.Capacity.Status {
		case twin.CapacityInsufficient:
			fmt.Printf("  sustainable cap.:  INSUFFICIENT_DATA (%s)\n", model.Capacity.Uncertainty)
		default:
			if model.Capacity.SustainableRPS != nil {
				fmt.Printf("  sustainable cap.:  %.2f rps", *model.Capacity.SustainableRPS)
				if model.Capacity.SustainableInterval != nil {
					fmt.Printf(" [%.2f, %.2f] (%.0f%% %s)", model.Capacity.SustainableInterval.Low, model.Capacity.SustainableInterval.High, model.Capacity.SustainableInterval.Level*100, model.Capacity.SustainableInterval.Method)
				}
				fmt.Printf(" status=%s\n", model.Capacity.Status)
			} else {
				fmt.Printf("  sustainable cap.:  INSUFFICIENT_DATA\n")
			}
		}
		if len(model.Capacity.DegradationSignals) > 0 {
			fmt.Printf("  degradation:       %s\n", strings.Join(model.Capacity.DegradationSignals, "; "))
		}
	} else {
		fmt.Printf("  capacity estimate: %.2f rps (range %.2f - %.2f, +/-%.1f%%)\n",
			model.Curve.CapacityRPS, model.Curve.CapacityLowRPS, model.Curve.CapacityHighRPS,
			model.Curve.CapacityRelativeUncertainty*100)
	}
	for _, note := range model.Calibration.Notes {
		fmt.Printf("  note: %s\n", note)
	}
}

// simulateRun implements: Sift simulate run --model <path> --scenario
// best|likely|worst [--rps N | --users N] [flags].
func simulateRun(args []string) {
	fs := flag.NewFlagSet("simulate run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	modelPath := fs.String("model", "", "path to twin-model.json (required)")
	preset := fs.String("scenario", "", "scenario preset: best|likely|worst (required)")
	rps := fs.Float64("rps", 0, "open-loop target rps (overrides the preset)")
	users := fs.Float64("users", 0, "closed-loop target users (overrides the preset)")
	duration := fs.Float64("duration", 0, "scenario duration in seconds (0 = preset)")
	slaP99 := fs.Float64("sla-p99-ms", 0, "p99 latency objective in ms (0 = preset)")
	maxErr := fs.Float64("max-error-rate", 0, "error-rate objective in percent (0 = disabled)")
	iterations := fs.Int("iterations", 0, "Monte Carlo iterations (0 = preset)")
	seed := fs.Int64("seed", 42, "PRNG seed; the same seed reproduces the result exactly")
	ramp := fs.Float64("ramp", -1, "ramp to target in seconds (-1 = preset, 0 = immediate step)")
	outDir := fs.String("out", defaultTwinOutDir, "directory for artifacts")
	failOn := fs.Float64("fail-on-breach-prob", 0, "exit 3 when the breach probability exceeds this fraction (0 = disabled)")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			simulateUsage()
			return
		}
		simulateUsage()
		exitProcess(1)
	}
	if strings.TrimSpace(*modelPath) == "" || strings.TrimSpace(*preset) == "" || fs.NArg() > 0 {
		simulateUsage()
		exitProcess(1)
	}
	if *rps > 0 && *users > 0 {
		fatal(fmt.Errorf("simulate run: --rps and --users are mutually exclusive"))
	}
	if *rps < 0 || *users < 0 || *duration < 0 || *slaP99 < 0 || *maxErr < 0 || *iterations < 0 {
		fatal(fmt.Errorf("simulate run: numeric flags must not be negative"))
	}
	if *failOn < 0 || *failOn > 1 {
		fatal(fmt.Errorf("simulate run: --fail-on-breach-prob must be in [0,1], got %v", *failOn))
	}

	model, err := twin.LoadModel(*modelPath)
	if err != nil {
		fatal(fmt.Errorf("simulate run: %w", err))
	}
	sc, err := twin.Preset(*preset, model)
	if err != nil {
		fatal(fmt.Errorf("simulate run: %w", err))
	}
	switch {
	case *rps > 0:
		sc.Mode = twin.LoopOpen
		sc.TargetRPS = *rps
		sc.TargetUsers = 0
	case *users > 0:
		sc.Mode = twin.LoopClosed
		sc.TargetUsers = *users
		sc.TargetRPS = 0
	}
	if *duration > 0 {
		sc.DurationSeconds = *duration
	}
	if *slaP99 > 0 {
		sc.SLAP99MS = *slaP99
	}
	if *maxErr > 0 {
		sc.MaxErrorRatePct = *maxErr
	}
	if *iterations > 0 {
		sc.Iterations = *iterations
	}
	applyRamp(&sc, *ramp)

	res, err := twin.Simulate(model, sc, *seed)
	if err != nil {
		fatal(fmt.Errorf("simulate run: %w", err))
	}
	results := map[string]twin.Result{res.Scenario.Name: res}
	paths, err := twin.WriteArtifacts(*outDir, model, results)
	if err != nil {
		fatal(fmt.Errorf("simulate run: %w", err))
	}

	printSimulation(res)
	fmt.Printf("  model:             %s\n", paths.ModelPath)
	for _, art := range paths.SimulationPaths {
		fmt.Printf("  result:            %s\n", art.Path)
	}
	fmt.Printf("  report:            %s\n", paths.ReportPath)
	fmt.Printf("\nNote: these are model-based estimates, not guarantees.\n")

	if *failOn > 0 && res.Summary.SLAProbabilityBreach > *failOn {
		fmt.Fprintf(os.Stderr, "simulate run: breach probability %.1f%% exceeds --fail-on-breach-prob %.1f%%\n",
			res.Summary.SLAProbabilityBreach*100, *failOn*100)
		exitProcess(3)
	}
}

// simulateCompare implements: Sift simulate compare --model <path> --out <dir>.
func simulateCompare(args []string) {
	fs := flag.NewFlagSet("simulate compare", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	modelPath := fs.String("model", "", "path to twin-model.json (required)")
	duration := fs.Float64("duration", 0, "scenario duration in seconds (0 = preset)")
	slaP99 := fs.Float64("sla-p99-ms", 0, "p99 latency objective in ms (0 = preset)")
	maxErr := fs.Float64("max-error-rate", 0, "error-rate objective in percent (0 = disabled)")
	iterations := fs.Int("iterations", 0, "Monte Carlo iterations (0 = preset)")
	seed := fs.Int64("seed", 42, "PRNG seed shared by all three scenarios")
	ramp := fs.Float64("ramp", -1, "ramp to target in seconds (-1 = preset, 0 = immediate step)")
	outDir := fs.String("out", defaultTwinOutDir, "directory for artifacts")
	failOn := fs.Float64("fail-on-breach-prob", 0, "exit 3 when any breach probability exceeds this fraction (0 = disabled)")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			simulateUsage()
			return
		}
		simulateUsage()
		exitProcess(1)
	}
	if strings.TrimSpace(*modelPath) == "" || fs.NArg() > 0 {
		simulateUsage()
		exitProcess(1)
	}
	if *duration < 0 || *slaP99 < 0 || *maxErr < 0 || *iterations < 0 {
		fatal(fmt.Errorf("simulate compare: numeric flags must not be negative"))
	}
	if *failOn < 0 || *failOn > 1 {
		fatal(fmt.Errorf("simulate compare: --fail-on-breach-prob must be in [0,1], got %v", *failOn))
	}

	model, err := twin.LoadModel(*modelPath)
	if err != nil {
		fatal(fmt.Errorf("simulate compare: %w", err))
	}

	results := make(map[string]twin.Result, len(twin.PresetNames()))
	// Every scenario shares one seed: common random numbers keep capacity and
	// noise draws aligned, so the comparison isolates the load change.
	for _, name := range twin.PresetNames() {
		sc, presetErr := twin.Preset(name, model)
		if presetErr != nil {
			fatal(fmt.Errorf("simulate compare: %w", presetErr))
		}
		if *duration > 0 {
			sc.DurationSeconds = *duration
		}
		if *slaP99 > 0 {
			sc.SLAP99MS = *slaP99
		}
		if *maxErr > 0 {
			sc.MaxErrorRatePct = *maxErr
		}
		if *iterations > 0 {
			sc.Iterations = *iterations
		}
		applyRamp(&sc, *ramp)
		res, simErr := twin.Simulate(model, sc, *seed)
		if simErr != nil {
			fatal(fmt.Errorf("simulate compare (%s): %w", name, simErr))
		}
		results[name] = res
	}

	paths, err := twin.WriteArtifacts(*outDir, model, results)
	if err != nil {
		fatal(fmt.Errorf("simulate compare: %w", err))
	}

	if model.ConfidenceV2 != nil && model.Capacity != nil {
		capStr := "INSUFFICIENT_DATA"
		if model.Capacity.SustainableRPS != nil {
			capStr = fmt.Sprintf("%.2f rps", *model.Capacity.SustainableRPS)
		}
		fmt.Printf("capacity model: observed %.2f rps, sustainable %s (confidence %s %.1f/100)\n\n",
			model.Capacity.ObservedRPS, capStr, model.ConfidenceV2.Level, model.ConfidenceV2.Score)
	} else {
		fmt.Printf("capacity model: %.2f rps (%.2f - %.2f, confidence %s)\n\n",
			model.Curve.CapacityRPS, model.Curve.CapacityLowRPS, model.Curve.CapacityHighRPS, model.Confidence)
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SCENARIO\tLOOP\tTARGET\tP99 P50\tP99 P95\tBREACH\tSATURATION\tRISK")
	for _, name := range twin.PresetNames() {
		res := results[name]
		fmt.Fprintf(tw, "%s\t%s\t%s\t%.2f ms\t%.2f ms\t%.1f%%\t%s\t%s\n",
			name, res.Scenario.Mode, scenarioTarget(res.Scenario),
			res.Summary.P99MS.P50, res.Summary.P99MS.P95,
			res.Summary.SLAProbabilityBreach*100,
			formatSaturation(res.Summary), res.Summary.RiskLevel)
	}
	if err := tw.Flush(); err != nil {
		fatal(fmt.Errorf("simulate compare: write table: %w", err))
	}

	fmt.Printf("\nmodel:  %s\nreport: %s\n", paths.ModelPath, paths.ReportPath)
	for _, art := range paths.SimulationPaths {
		fmt.Printf("result: %s\n", art.Path)
	}
	fmt.Printf("\nNote: these are model-based estimates, not guarantees.\n")

	if *failOn > 0 {
		worst := 0.0
		worstName := ""
		for _, name := range twin.PresetNames() {
			if res := results[name]; res.Summary.SLAProbabilityBreach > worst {
				worst = res.Summary.SLAProbabilityBreach
				worstName = name
			}
		}
		if worst > *failOn {
			fmt.Fprintf(os.Stderr, "simulate compare: scenario %q breach probability %.1f%% exceeds --fail-on-breach-prob %.1f%%\n",
				worstName, worst*100, *failOn*100)
			exitProcess(3)
		}
	}
}

// applyRamp resolves the --ramp flag. A negative value keeps the preset ramp,
// but a preset ramp longer than a shortened horizon is clamped instead of
// failing: shortening --duration should not require re-specifying the ramp.
func applyRamp(sc *twin.Scenario, ramp float64) {
	switch {
	case ramp >= 0:
		sc.RampSeconds = ramp
	case sc.RampSeconds > sc.DurationSeconds:
		sc.RampSeconds = sc.DurationSeconds
	}
}

// printSimulation renders a single scenario result.
func printSimulation(res twin.Result) {
	fmt.Printf("scenario %s (%s loop)\n", res.Scenario.Name, res.Scenario.Mode)
	fmt.Printf("  target load:       %s\n", scenarioTarget(res.Scenario))
	fmt.Printf("  horizon:           %s, %d iterations, seed %d\n",
		formatSeconds(res.Scenario.DurationSeconds), res.Scenario.Iterations, res.Scenario.Seed)
	if res.Scenario.SLAP99MS > 0 {
		fmt.Printf("  SLA p99:           <= %.2f ms\n", res.Scenario.SLAP99MS)
	}
	if res.Scenario.MaxErrorRatePct > 0 {
		fmt.Printf("  SLA error rate:    <= %.2f%%\n", res.Scenario.MaxErrorRatePct)
	}
	fmt.Printf("  achieved rps:      median %.2f (p95 %.2f)\n", res.Summary.AchievedRPS.P50, res.Summary.AchievedRPS.P95)
	fmt.Printf("  utilisation:       median %.3f (p95 %.3f)\n", res.Summary.Utilization.P50, res.Summary.Utilization.P95)
	fmt.Printf("  predicted p99:     median %.2f ms, p95 %.2f ms\n", res.Summary.P99MS.P50, res.Summary.P99MS.P95)
	fmt.Printf("  predicted errors:  median %.3f%%, p95 %.3f%%\n", res.Summary.ErrorRatePct.P50, res.Summary.ErrorRatePct.P95)
	fmt.Printf("  breach probability: %.1f%% (latency %.1f%%, errors %.1f%%), risk %s\n",
		res.Summary.SLAProbabilityBreach*100, res.Summary.P99BreachProbability*100,
		res.Summary.ErrorBreachProbability*100, res.Summary.RiskLevel)
	if res.Summary.PredictedSaturationSeconds != nil {
		fmt.Printf("  saturation:        %s into the ramp (in %.1f%% of draws)\n",
			formatSeconds(*res.Summary.PredictedSaturationSeconds), res.Summary.SaturationProbability*100)
	}
	for _, note := range res.Notes {
		fmt.Printf("  note: %s\n", note)
	}
}

// scenarioTarget and formatSeconds are shared with the Markdown renderer's
// vocabulary so the CLI and the artifact never disagree.
func scenarioTarget(sc twin.Scenario) string {
	if sc.Mode == twin.LoopClosed {
		return fmt.Sprintf("%.2f users", sc.TargetUsers)
	}
	return fmt.Sprintf("%.2f rps", sc.TargetRPS)
}

func formatSaturation(s twin.Summary) string {
	if s.PredictedSaturationSeconds == nil {
		return "-"
	}
	return formatSeconds(*s.PredictedSaturationSeconds)
}

func formatSeconds(v float64) string {
	if v <= 0 {
		return "0 s"
	}
	if v < 1 {
		return fmt.Sprintf("%.0f ms", v*1000)
	}
	if v < 60 {
		return fmt.Sprintf("%.1f s", v)
	}
	return fmt.Sprintf("%.1f min", v/60)
}

func fallback(v, alt string) string {
	if strings.TrimSpace(v) == "" {
		return alt
	}
	return v
}

func simulateUsage() {
	fmt.Fprint(os.Stderr, `Usage: Sift simulate <command> [flags]

Builds a capacity digital twin from a Sift report and answers what-if load
questions without touching the service. All output is a model-based estimate,
not a guarantee.

Commands:
  fit       Fit a capacity model from a report JSON
  run       Simulate one scenario against a fitted model
  compare   Simulate the best, likely and worst presets and compare them
  validate  Compare prediction vs actual measured report and write validation artifact
  backtest  Compute MAE/RMSE/MAPE/drift/OOD from paired samples and write backtest artifact

Fit flags:
  --report string          path to a Sift report JSON (required)
  --out string             output directory (default "reports/twin")
  --target-p99-ms float    latency objective for capacity headroom (0 = default)

Run flags:
  --model string           path to twin-model.json (required)
  --scenario string        preset: best|likely|worst (required)
  --rps float              open-loop target rps (overrides the preset)
  --users float            closed-loop target users (overrides the preset)
  --duration float         scenario duration in seconds (0 = preset)
  --sla-p99-ms float       p99 objective in ms (0 = preset)
  --max-error-rate float   error-rate objective in percent (0 = disabled)
  --iterations int         Monte Carlo iterations (0 = preset, max 10000)
  --seed int               PRNG seed (default 42)
  --ramp float             ramp seconds (-1 = preset, 0 = immediate step)
  --out string             output directory (default "reports/twin")
  --fail-on-breach-prob float
                           exit 3 when the breach probability exceeds this
                           fraction of 1 (0 = disabled)

Compare flags: --model, --duration, --sla-p99-ms, --max-error-rate,
  --iterations, --seed, --ramp, --out, --fail-on-breach-prob.

Validate flags:
  --model string           path to twin-model.json (optional if --result provided; required with --update-model)
  --actual string          path to measured actual report JSON (required)
  --result string          path to simulation result JSON (optional)
  --scenario string        scenario when simulating from model (default "normal")
  --seed int               PRNG seed when simulating from model (default 42)
  --update-model           persist derived validation record into --model (optional)
  --manifest string        path to canonical dataset manifest JSON for provenance-based verification (recommended)
  --split-json string      JSON object for split/provenance metadata (optional, caller-provided)
  --leakage-json string    JSON object for leakage guard metadata (optional, caller-provided)
  --dataset-json string    JSON object for dataset/provenance metadata (optional, caller-provided)
  --require-no-leakage     fail if leakage metadata is not explicitly enforced and proven (legacy metadata gate)
  --strict-validation      fail if manifest/provenance is missing, verification unverified, overlap detected, or leakage not proven absent
  --strict-no-leakage      alias of --strict-validation for leakage enforcement
  --out string             output directory (default "reports/twin")

Backtest flags:
  --input string           JSON with predicted/actual arrays (required)
  --model string           path to twin-model.json to update (optional)
  --update-model           persist derived validation record into --model (optional)
  --out string             output directory (default "reports/twin")
  --model-version string   model version label to record (optional)
  --manifest string        path to canonical dataset manifest JSON for provenance-based verification (recommended)
  --require-no-leakage     fail if split/leakage metadata is missing or not explicitly enforced+proven (legacy metadata gate)
  --strict-validation      fail if manifest/provenance is missing, verification unverified, overlap detected, or leakage not proven absent
  --strict-no-leakage      alias of --strict-validation for leakage enforcement

Exit status: 0 success, 1 invalid input, 3 SLA breach gate tripped.

Examples:
  Sift simulate fit --report reports/api.json --out reports/twin
  Sift simulate run --model reports/twin/twin-model.json --scenario likely --rps 500
  Sift simulate compare --model reports/twin/twin-model.json --out reports/twin
  Sift simulate validate --model reports/twin/twin-model.json --actual reports/measured.json --scenario normal --manifest reports/twin/validate-manifest.json --strict-validation --update-model --out reports/twin
  Sift simulate backtest --input pairs.json --model reports/twin/twin-model.json --manifest reports/twin/backtest-manifest.json --strict-validation --update-model --out reports/twin
`)
}

// simulateValidate implements: Sift simulate validate --model <path> --actual <report.json> [--scenario <name>|--result <sim.json>] [--manifest <path>] [--update-model] [--split-json ... --leakage-json ... --dataset-json ...] [--require-no-leakage] [--strict-validation|--strict-no-leakage] --out <dir>
func simulateValidate(args []string) {
	fs := flag.NewFlagSet("simulate validate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	modelPath := fs.String("model", "", "path to twin-model.json (optional if --result provided; required with --update-model)")
	actualPath := fs.String("actual", "", "path to measured actual report JSON (required)")
	resultPath := fs.String("result", "", "path to simulation result JSON (optional; if omitted, simulate from model+scenario)")
	scenario := fs.String("scenario", "normal", "scenario preset/name when simulating from model")
	seed := fs.Int64("seed", 42, "PRNG seed when simulating from model")
	outDir := fs.String("out", defaultTwinOutDir, "directory for validation artifacts")
	updateModel := fs.Bool("update-model", false, "persist derived validation record into the model artifact at --model")
	manifestPath := fs.String("manifest", "", "path to canonical dataset manifest JSON for provenance-based leakage verification")
	splitJSON := fs.String("split-json", "", "JSON object describing split/provenance metadata (caller-provided)")
	leakageJSON := fs.String("leakage-json", "", "JSON object describing leakage guard/proof metadata (caller-provided)")
	datasetJSON := fs.String("dataset-json", "", "JSON object describing dataset/provenance metadata (caller-provided)")
	requireNoLeakage := fs.Bool("require-no-leakage", false, "fail if leakage metadata is not explicitly enforced and proven (legacy metadata gate)")
	strictValidation := fs.Bool("strict-validation", false, "fail if manifest/provenance is missing, verification unverified, overlap detected, or leakage not proven absent")
	strictNoLeakage := fs.Bool("strict-no-leakage", false, "alias of --strict-validation for leakage enforcement")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			simulateUsage()
			return
		}
		simulateUsage()
		exitProcess(1)
	}
	if strings.TrimSpace(*actualPath) == "" || fs.NArg() > 0 {
		simulateUsage()
		exitProcess(1)
	}
	if *updateModel && strings.TrimSpace(*modelPath) == "" {
		fatal(fmt.Errorf("simulate validate: --update-model requires --model"))
	}
	strict := *strictValidation || *strictNoLeakage
	splitMeta, err := parseSplitMetaFlag(*splitJSON)
	if err != nil {
		fatal(fmt.Errorf("simulate validate: --split-json: %w", err))
	}
	datasetMeta, err := parseDatasetMetaFlag(*datasetJSON)
	if err != nil {
		fatal(fmt.Errorf("simulate validate: --dataset-json: %w", err))
	}
	metadataLeakage, err := parseLeakageMetaFlag(*leakageJSON)
	if err != nil {
		fatal(fmt.Errorf("simulate validate: --leakage-json: %w", err))
	}
	manifest, ver, manifestResolvedPath, verr := resolveValidateManifest(*manifestPath, *actualPath, *resultPath, *modelPath, splitMeta, datasetMeta)
	if verr != nil {
		fatal(fmt.Errorf("simulate validate: %w", verr))
	}
	leakageMeta := buildEffectiveLeakageGuard(metadataLeakage, manifest, ver, manifestResolvedPath)
	if strict {
		if err := enforceStrictLeakageVerification(leakageMeta, ver, manifest != nil); err != nil {
			fatal(fmt.Errorf("simulate validate: %w", err))
		}
	} else if *requireNoLeakage {
		// Legacy metadata gate: require explicit enforced+proven flags in caller metadata,
		// but never treat metadata-only claims as verified without manifest/provenance.
		if metadataLeakage == nil || !metadataLeakage.Enforced || !metadataLeakage.Proven {
			reason := "no leakage proof provided"
			if metadataLeakage != nil && strings.TrimSpace(metadataLeakage.Reason) != "" {
				reason = metadataLeakage.Reason
			} else if metadataLeakage != nil {
				reason = "leakage not explicitly enforced+proven by provided metadata"
			}
			fatal(fmt.Errorf("simulate validate: no-leakage requirement not satisfied (%s)", reason))
		}
	}

	actual, err := report.LoadReport(*actualPath)
	if err != nil {
		fatal(fmt.Errorf("simulate validate: load actual report: %w", err))
	}
	var res twin.Result
	var model twin.Model
	haveModel := false
	if strings.TrimSpace(*resultPath) != "" {
		b, rerr := os.ReadFile(*resultPath)
		if rerr != nil {
			fatal(fmt.Errorf("simulate validate: read result: %w", rerr))
		}
		if rerr := json.Unmarshal(b, &res); rerr != nil {
			fatal(fmt.Errorf("simulate validate: decode result: %w", rerr))
		}
	}
	if strings.TrimSpace(*modelPath) != "" {
		m, merr := twin.LoadModel(*modelPath)
		if merr != nil {
			fatal(fmt.Errorf("simulate validate: %w", merr))
		}
		model = m
		haveModel = true
	}
	if strings.TrimSpace(*resultPath) == "" {
		if !haveModel {
			fatal(fmt.Errorf("simulate validate: --model is required when --result is not provided"))
		}
		sc, serr := twin.Preset(strings.ToLower(strings.TrimSpace(*scenario)), model)
		if serr != nil {
			fatal(fmt.Errorf("simulate validate: %w", serr))
		}
		sim, simErr := twin.Simulate(model, sc, *seed)
		if simErr != nil {
			fatal(fmt.Errorf("simulate validate: %w", simErr))
		}
		res = sim
	}
	cmp := twin.ComparePredictionToActual(res, *actual)
	status, driftStatus, statusNote := twin.ComparisonValidationStatus(cmp)
	assumptions := []string{
		"Prediction-vs-actual compares model-based simulated estimates to the provided actual report as validation evidence (actual metrics are not fabricated).",
		"Comparable scenario/metric context is required for meaningful validation; caller must ensure alignment.",
		"Metadata-only leakage claims are not trusted as verified; verification requires manifest/provenance/ID checks when available.",
	}
	modelVersion := ""
	var modelParams map[string]any
	var modelAssumptions []string
	if haveModel && model.ModelInfo != nil {
		modelVersion = model.ModelInfo.Version
		if model.ModelInfo.Parameters != nil {
			modelParams = make(map[string]any, len(model.ModelInfo.Parameters))
			for k, v := range model.ModelInfo.Parameters {
				modelParams[k] = v
			}
		}
		modelAssumptions = model.ModelInfo.Assumptions
	}
	seedVal := res.SimulationSeed
	if seedVal == 0 {
		seedVal = res.Scenario.Seed
	}
	// Populate dataset provenance from actual file when missing.
	if datasetMeta == nil {
		datasetMeta = &twin.DatasetRef{}
	}
	if strings.TrimSpace(datasetMeta.Kind) == "" {
		datasetMeta.Kind = "report"
	}
	if strings.TrimSpace(datasetMeta.Path) == "" {
		if abs, aerr := filepath.Abs(*actualPath); aerr == nil {
			datasetMeta.Path = abs
		} else {
			datasetMeta.Path = *actualPath
		}
	}
	if strings.TrimSpace(datasetMeta.Hash) == "" {
		if h, herr := hashFileSHA256Hex(datasetMeta.Path); herr == nil {
			datasetMeta.Hash = h
		}
	}
	if datasetMeta.Records == 0 {
		datasetMeta.Records = int(actual.TotalRequests)
	}
	if strings.TrimSpace(datasetMeta.ID) == "" {
		datasetMeta.ID = filepath.Base(datasetMeta.Path)
	}
	cmpCopy := cmp
	validationRecord := twin.ValidationRecord{
		SchemaVersion:      "sift.twin-validation/v1",
		Kind:               "compare",
		GeneratedAt:        time.Now().UTC().Format(time.RFC3339Nano),
		ModelVersion:       modelVersion,
		Parameters:         modelParams,
		Assumptions:        append(assumptions, modelAssumptions...),
		Dataset:            datasetMeta,
		Split:              splitMeta,
		Leakage:            leakageMeta,
		Manifest:           manifest,
		ManifestPath:       manifestResolvedPath,
		VerificationStatus: leakageMeta.Status,
		Verification:       &ver,
		Comparison:         &cmpCopy,
		BacktestStatus:     status,
		DriftStatus:        driftStatus,
		ValidationNotes: []string{
			statusNote,
			"Comparison uses provided actual report as validation evidence.",
			"Leakage verification is provenance-based when manifest/data IDs/hashes are available; metadata-only claims are recorded as unverified.",
		},
	}
	record := map[string]any{
		"schema_version":            "sift.twin-validation/v1",
		"generated_at":              validationRecord.GeneratedAt,
		"model_version":             modelVersion,
		"simulation_seed":           seedVal,
		"scenario":                  res.Scenario.Name,
		"parameters":                modelParams,
		"assumptions":               validationRecord.Assumptions,
		"dataset":                   datasetMeta,
		"split":                     splitMeta,
		"leakage":                   leakageMeta,
		"manifest_path":             manifestResolvedPath,
		"verification_status":       leakageMeta.Status,
		"verification":              ver,
		"simulated_not_measured":    true,
		"derived_validation_status": status,
		"derived_drift_status":      driftStatus,
		"comparison":                cmp,
		"validation_record":         validationRecord,
		"actual_report": map[string]any{
			"name": actual.Name, "duration": actual.Duration.String(), "rps": actual.RPS,
			"p95_ms": durationMS(actual.Overall.P95), "p99_ms": durationMS(actual.Overall.P99), "error_rate_pct": actual.ErrorRatePct,
		},
	}
	if manifest != nil {
		record["manifest"] = manifest
	}
	if *updateModel && haveModel {
		model.ApplyValidationRecord(validationRecord)
		saved, serr := twin.SaveModel(*modelPath, model)
		if serr != nil {
			fatal(fmt.Errorf("simulate validate: update model: %w", serr))
		}
		record["updated_model_path"] = saved
		record["updated_model_info"] = model.ModelInfo
	}
	if err := os.MkdirAll(*outDir, 0o750); err != nil {
		fatal(fmt.Errorf("simulate validate: create output dir: %w", err))
	}
	outPath := filepath.Join(*outDir, "validation-compare.json")
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		fatal(fmt.Errorf("simulate validate: encode validation artifact: %w", err))
	}
	if err := os.WriteFile(outPath, append(data, '\n'), 0o600); err != nil {
		fatal(fmt.Errorf("simulate validate: write %s: %w", outPath, err))
	}
	fmt.Printf("validation artifact: %s\n", outPath)
	fmt.Printf("  scenario: %s (seed %d, model %s)\n", res.Scenario.Name, seedVal, fallback(modelVersion, "unknown"))
	fmt.Printf("  RPS:   actual %.2f vs predicted %.2f (error %.2f%%)\n", cmp.ActualRPS, cmp.PredictedRPS, cmp.RPSErrorPct)
	fmt.Printf("  p95:   actual %.2f ms vs predicted %.2f ms (MAE %.2f, error %.2f%%)\n", cmp.ActualP95, cmp.PredictedP95, cmp.P95MAE, cmp.P95ErrorPct)
	fmt.Printf("  p99:   actual %.2f ms vs predicted %.2f ms (MAE %.2f, error %.2f%%)\n", cmp.ActualP99, cmp.PredictedP99, cmp.P99MAE, cmp.P99ErrorPct)
	fmt.Printf("  derived status: %s (drift=%s)\n", status, driftStatus)
	if leakageMeta != nil {
		fmt.Printf("  leakage: enforced=%t proven=%t status=%s verified=%t\n", leakageMeta.Enforced, leakageMeta.Proven, fallback(leakageMeta.Status, "unverified"), leakageMeta.Verified)
		if strings.TrimSpace(leakageMeta.Reason) != "" {
			fmt.Printf("  leakage reason: %s\n", leakageMeta.Reason)
		}
	}
	if *updateModel && haveModel {
		fmt.Printf("  model updated:  %s\n", *modelPath)
	}
	for _, n := range cmp.Notes {
		fmt.Printf("  note: %s\n", n)
	}
	fmt.Printf("  note: estimates are model-based; actual values come from measured report evidence. metadata-only leakage claims are recorded as unverified.\n")
}

// simulateBacktest implements: Sift simulate backtest --input <pairs.json> [--model <twin-model.json> --update-model] [--manifest <path>] [--strict-validation|--strict-no-leakage] [--require-no-leakage] --out <dir>
func simulateBacktest(args []string) {
	fs := flag.NewFlagSet("simulate backtest", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	inputPath := fs.String("input", "", "path to JSON with predicted/actual arrays (required)")
	outDir := fs.String("out", defaultTwinOutDir, "directory for validation artifacts")
	modelPath := fs.String("model", "", "path to twin-model.json to update (optional; requires --update-model)")
	updateModel := fs.Bool("update-model", false, "persist derived backtest/drift status into the model artifact at --model")
	modelVersion := fs.String("model-version", "", "model version label to record")
	manifestPath := fs.String("manifest", "", "path to canonical dataset manifest JSON for provenance-based leakage verification")
	requireNoLeakage := fs.Bool("require-no-leakage", false, "fail if split/leakage metadata is missing or not explicitly enforced+proven (legacy metadata gate)")
	strictValidation := fs.Bool("strict-validation", false, "fail if manifest/provenance is missing, verification unverified, overlap detected, or leakage not proven absent")
	strictNoLeakage := fs.Bool("strict-no-leakage", false, "alias of --strict-validation for leakage enforcement")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			simulateUsage()
			return
		}
		simulateUsage()
		exitProcess(1)
	}
	if strings.TrimSpace(*inputPath) == "" || fs.NArg() > 0 {
		simulateUsage()
		exitProcess(1)
	}
	if *updateModel && strings.TrimSpace(*modelPath) == "" {
		fatal(fmt.Errorf("simulate backtest: --update-model requires --model"))
	}
	strict := *strictValidation || *strictNoLeakage
	b, err := os.ReadFile(*inputPath)
	if err != nil {
		fatal(fmt.Errorf("simulate backtest: read input: %w", err))
	}
	var req struct {
		Predicted      []float64          `json:"predicted"`
		Actual         []float64          `json:"actual"`
		ModelRangeLow  float64            `json:"model_range_low"`
		ModelRangeHigh float64            `json:"model_range_high"`
		ModelVersion   string             `json:"model_version"`
		Parameters     map[string]any     `json:"parameters"`
		Assumptions    []string           `json:"assumptions"`
		Dataset        *twin.DatasetRef   `json:"dataset,omitempty"`
		Split          *twin.SplitSpec    `json:"split,omitempty"`
		Leakage        *twin.LeakageGuard `json:"leakage,omitempty"`
		Manifest       string             `json:"manifest,omitempty"`
	}
	if err := json.Unmarshal(b, &req); err != nil {
		fatal(fmt.Errorf("simulate backtest: decode input: %w", err))
	}
	if strings.TrimSpace(*manifestPath) == "" && strings.TrimSpace(req.Manifest) != "" {
		*manifestPath = strings.TrimSpace(req.Manifest)
	}
	manifest, ver, manifestResolvedPath, verr := resolveBacktestManifest(*manifestPath, *inputPath, req.Predicted, req.Actual, req.Split, req.Dataset)
	if verr != nil {
		fatal(fmt.Errorf("simulate backtest: %w", verr))
	}
	leakage := buildEffectiveLeakageGuard(req.Leakage, manifest, ver, manifestResolvedPath)
	if strict {
		if err := enforceStrictLeakageVerification(leakage, ver, manifest != nil); err != nil {
			fatal(fmt.Errorf("simulate backtest: %w", err))
		}
	} else if *requireNoLeakage {
		if req.Leakage == nil || !req.Leakage.Enforced || !req.Leakage.Proven {
			reason := "no leakage proof provided"
			if req.Leakage != nil && strings.TrimSpace(req.Leakage.Reason) != "" {
				reason = req.Leakage.Reason
			} else if req.Leakage != nil {
				reason = "leakage not explicitly enforced+proven by provided metadata"
			}
			fatal(fmt.Errorf("simulate backtest: no-leakage requirement not satisfied (%s)", reason))
		}
	}
	bt := twin.BacktestErrors(req.Predicted, req.Actual, req.ModelRangeLow, req.ModelRangeHigh)
	backtestStatus, driftStatus := bt.ValidationStatus()
	mv := strings.TrimSpace(*modelVersion)
	if mv == "" {
		mv = strings.TrimSpace(req.ModelVersion)
	}
	if req.Dataset == nil {
		req.Dataset = &twin.DatasetRef{}
	}
	if strings.TrimSpace(req.Dataset.Kind) == "" {
		req.Dataset.Kind = "pairs"
	}
	if strings.TrimSpace(req.Dataset.Path) == "" {
		if abs, aerr := filepath.Abs(*inputPath); aerr == nil {
			req.Dataset.Path = abs
		} else {
			req.Dataset.Path = *inputPath
		}
	}
	if strings.TrimSpace(req.Dataset.Hash) == "" {
		if h, herr := hashFileSHA256Hex(req.Dataset.Path); herr == nil {
			req.Dataset.Hash = h
		}
	}
	if req.Dataset.Records == 0 {
		n := len(req.Predicted)
		if len(req.Actual) < n {
			n = len(req.Actual)
		}
		req.Dataset.Records = n
	}
	if strings.TrimSpace(req.Dataset.ID) == "" {
		req.Dataset.ID = filepath.Base(req.Dataset.Path)
	}
	assumptions := append([]string{
		"Train/validation separation must be verifiable from manifest/provenance (IDs/hashes/paths/boundaries); metadata-only claims are not trusted as verified.",
		"Predicted and actual samples must represent comparable scenarios/metrics.",
	}, req.Assumptions...)
	btCopy := bt
	validationRecord := twin.ValidationRecord{
		SchemaVersion:      "sift.twin-validation/v1",
		Kind:               "backtest",
		GeneratedAt:        time.Now().UTC().Format(time.RFC3339Nano),
		ModelVersion:       mv,
		Parameters:         req.Parameters,
		Assumptions:        assumptions,
		Dataset:            req.Dataset,
		Split:              req.Split,
		Leakage:            leakage,
		Manifest:           manifest,
		ManifestPath:       manifestResolvedPath,
		VerificationStatus: leakage.Status,
		Verification:       &ver,
		Backtest:           &btCopy,
		BacktestStatus:     backtestStatus,
		DriftStatus:        driftStatus,
	}
	record := map[string]any{
		"schema_version":          "sift.twin-validation/v1",
		"generated_at":            validationRecord.GeneratedAt,
		"model_version":           mv,
		"parameters":              req.Parameters,
		"assumptions":             assumptions,
		"dataset":                 req.Dataset,
		"split":                   req.Split,
		"leakage":                 leakage,
		"manifest_path":           manifestResolvedPath,
		"verification_status":     leakage.Status,
		"verification":            ver,
		"backtest":                bt,
		"validation_status":       backtestStatus,
		"derived_backtest_status": backtestStatus,
		"derived_drift_status":    driftStatus,
		"validation_record":       validationRecord,
	}
	if manifest != nil {
		record["manifest"] = manifest
	}
	if *updateModel {
		model, merr := twin.LoadModel(*modelPath)
		if merr != nil {
			fatal(fmt.Errorf("simulate backtest: load model: %w", merr))
		}
		if mv == "" && model.ModelInfo != nil {
			mv = model.ModelInfo.Version
			record["model_version"] = mv
			validationRecord.ModelVersion = mv
		}
		note := fmt.Sprintf("backtest: status=%s drift=%s samples=%d mae=%.4f rmse=%.4f mape=%.2f%% leakage_status=%s leakage_verified=%t leakage_proven=%t",
			backtestStatus, driftStatus, bt.Samples, bt.MAE, bt.RMSE, bt.MAPE, fallback(leakage.Status, twin.LeakageStatusUnverified), leakage.Verified, leakage.Proven)
		validationRecord.ValidationNotes = append(validationRecord.ValidationNotes, note)
		model.ApplyValidationRecord(validationRecord)
		saved, serr := twin.SaveModel(*modelPath, model)
		if serr != nil {
			fatal(fmt.Errorf("simulate backtest: update model: %w", serr))
		}
		record["updated_model_path"] = saved
		record["updated_model_info"] = model.ModelInfo
	}
	if err := os.MkdirAll(*outDir, 0o750); err != nil {
		fatal(fmt.Errorf("simulate backtest: create output dir: %w", err))
	}
	outPath := filepath.Join(*outDir, "validation-backtest.json")
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		fatal(fmt.Errorf("simulate backtest: encode artifact: %w", err))
	}
	if err := os.WriteFile(outPath, append(data, '\n'), 0o600); err != nil {
		fatal(fmt.Errorf("simulate backtest: write %s: %w", outPath, err))
	}
	fmt.Printf("backtest artifact: %s\n", outPath)
	fmt.Printf("  samples=%d MAE=%.4f RMSE=%.4f MAPE=%.2f%% drift=%s ood=%t status=%s\n", bt.Samples, bt.MAE, bt.RMSE, bt.MAPE, bt.Drift, bt.OutOfDomain, backtestStatus)
	fmt.Printf("  leakage: status=%s verified=%t proven=%t\n", fallback(leakage.Status, twin.LeakageStatusUnverified), leakage.Verified, leakage.Proven)
	if strings.TrimSpace(leakage.Reason) != "" {
		fmt.Printf("  leakage reason: %s\n", leakage.Reason)
	}
	if *updateModel {
		fmt.Printf("  model updated:  %s\n", *modelPath)
	}
	for _, n := range bt.Notes {
		fmt.Printf("  note: %s\n", n)
	}
}

func resolveValidateManifest(manifestPath, actualPath, resultPath, modelPath string, split *twin.SplitSpec, dataset *twin.DatasetRef) (*twin.DatasetManifest, twin.LeakageVerification, string, error) {
	if strings.TrimSpace(manifestPath) != "" {
		abs := manifestPath
		if a, err := filepath.Abs(manifestPath); err == nil {
			abs = a
		}
		m, err := twin.LoadManifest(abs)
		if err != nil {
			return nil, twin.LeakageVerification{Status: twin.LeakageStatusUnverified, Summary: "unverified: failed to load manifest"}, "", err
		}
		ver := twin.VerifyManifestSeparation(m)
		return &m, ver, abs, nil
	}
	// No manifest provided: metadata alone cannot establish verified leakage-free result.
	// Construct a minimal manifest from available provenance hints for transparency but mark unverified.
	trainPath := strings.TrimSpace(resultPath)
	trainKind := "prediction_result"
	trainID := ""
	if trainPath == "" {
		trainPath = strings.TrimSpace(modelPath)
		trainKind = "model_or_prediction_source"
	}
	if split != nil {
		if strings.TrimSpace(split.TrainDataset) != "" {
			trainPath = split.TrainDataset
		}
	}
	opts := twin.ValidateManifestOptions{Strategy: "unknown", TrainPath: trainPath, TrainKind: trainKind, TrainID: trainID}
	if split != nil {
		if strings.TrimSpace(split.Strategy) != "" {
			opts.Strategy = split.Strategy
		}
		opts.TrainEnd = split.TrainEnd
		opts.ValidationStart = split.ValidationStart
		opts.BoundaryOrderField = split.BoundaryOrderField
		opts.SplitNotes = split.Notes
		opts.TrainRecordIDs = split.TrainIDs
		opts.ValidationRecordIDs = split.ValidationIDs
		if strings.TrimSpace(split.TrainDataset) != "" {
			opts.TrainID = split.TrainDataset
		}
		if strings.TrimSpace(split.ValidationSet) != "" {
			opts.ValidationID = split.ValidationSet
		}
	}
	if dataset != nil && opts.ValidationID == "" {
		opts.ValidationID = dataset.ID
	}
	m, err := twin.CreateValidateCompareManifest(actualPath, resultPath, opts)
	if err != nil {
		return nil, twin.LeakageVerification{Status: twin.LeakageStatusUnverified, Summary: "unverified: could not construct provenance manifest from metadata"}, "", nil
	}
	ver := twin.VerifyManifestSeparation(m)
	// Force metadata-only path to unverified even if incidental fields looked separable, unless explicitly backed by strong IDs?
	// Keep verification logic result but provenance source is metadata; caller can still inspect. Strict mode will fail on unverified.
	ver.Summary = "unverified: metadata-only provenance (no manifest provided); " + strings.TrimSpace(ver.Summary)
	ver.Verified = false
	if ver.Status == twin.LeakageStatusVerifiedNoLeakage {
		ver.Status = twin.LeakageStatusUnverified
	}
	ver.Reasons = append([]string{"no canonical manifest provided; metadata-only claims cannot establish verified leakage-free result"}, ver.Reasons...)
	return &m, ver, "", nil
}

func resolveBacktestManifest(manifestPath, inputPath string, predicted, actual []float64, split *twin.SplitSpec, dataset *twin.DatasetRef) (*twin.DatasetManifest, twin.LeakageVerification, string, error) {
	if strings.TrimSpace(manifestPath) != "" {
		abs := manifestPath
		if a, err := filepath.Abs(manifestPath); err == nil {
			abs = a
		}
		m, err := twin.LoadManifest(abs)
		if err != nil {
			return nil, twin.LeakageVerification{Status: twin.LeakageStatusUnverified, Summary: "unverified: failed to load manifest"}, "", err
		}
		ver := twin.VerifyManifestSeparation(m)
		return &m, ver, abs, nil
	}
	m, ver, err := twin.ComputeBacktestManifestFromInput(inputPath, predicted, actual, split, dataset)
	if err != nil {
		return nil, twin.LeakageVerification{Status: twin.LeakageStatusUnverified, Summary: "unverified: could not compute provenance manifest"}, "", nil
	}
	// Metadata-only/computed-without-manifest cannot be trusted as verified.
	ver.Verified = false
	if ver.Status == twin.LeakageStatusVerifiedNoLeakage {
		ver.Status = twin.LeakageStatusUnverified
	}
	ver.Summary = "unverified: metadata-only provenance (no manifest provided); " + strings.TrimSpace(ver.Summary)
	ver.Reasons = append([]string{"no canonical manifest provided; metadata-only claims cannot establish verified leakage-free result"}, ver.Reasons...)
	return &m, ver, "", nil
}

func buildEffectiveLeakageGuard(metadata *twin.LeakageGuard, manifest *twin.DatasetManifest, ver twin.LeakageVerification, manifestPath string) *twin.LeakageGuard {
	lg := &twin.LeakageGuard{Status: twin.LeakageStatusUnverified, Verified: false, Proven: false, Enforced: false, VerificationSource: "none", Reason: "no leakage verification performed"}
	if metadata != nil {
		// Copy caller metadata for traceability but do not trust as verification.
		cp := *metadata
		lg = &cp
		lg.Status = twin.LeakageStatusUnverified
		lg.Verified = false
		lg.Proven = false
		if lg.Enforced || lg.Proven {
			lg.VerificationSource = "metadata_unverified"
			if strings.TrimSpace(lg.Reason) == "" {
				lg.Reason = "metadata-only leakage claim provided but not verified against manifest/provenance"
			} else {
				lg.Reason = "metadata-only leakage claim not verified against manifest/provenance; " + lg.Reason
			}
		} else {
			lg.VerificationSource = "metadata_unverified"
			if strings.TrimSpace(lg.Reason) == "" {
				lg.Reason = "leakage not verified; metadata does not prove absence of leakage"
			}
		}
	}
	if manifestPath != "" {
		// Manifest-backed verification result is authoritative.
		lg = twin.ApplyLeakageVerification(lg, ver)
		lg.ManifestPath = manifestPath
		lg.VerificationSource = "manifest"
		lg.Enforced = true
		if manifest != nil {
			lg.ManifestSchema = manifest.SchemaVersion
			lg.ManifestKind = manifest.Kind
		}
		return lg
	}
	// No manifest path: keep unverified result, but include computed checks/reasons for transparency.
	lg.Checks = uniqueStrings(append(append([]string{}, lg.Checks...), ver.Checks...))
	if ver.OverlapCount > 0 {
		oc := ver.OverlapCount
		lg.OverlapCount = &oc
	}
	if strings.TrimSpace(lg.Status) == "" {
		lg.Status = ver.Status
	}
	if ver.Status == twin.LeakageStatusLeakageDetected {
		lg.Status = twin.LeakageStatusLeakageDetected
		lg.Enforced = true
	}
	if strings.TrimSpace(lg.Reason) == "" {
		lg.Reason = strings.TrimSpace(ver.Summary)
	}
	if strings.TrimSpace(lg.Method) == "" && len(ver.Checks) > 0 {
		lg.Method = strings.Join(ver.Checks, ",")
	}
	return lg
}

func enforceStrictLeakageVerification(lg *twin.LeakageGuard, ver twin.LeakageVerification, hasManifest bool) error {
	if !hasManifest {
		return fmt.Errorf("strict validation requires a canonical dataset manifest (--manifest)")
	}
	if lg == nil {
		return fmt.Errorf("strict validation requires leakage verification")
	}
	if ver.Status == twin.LeakageStatusLeakageDetected || lg.Status == twin.LeakageStatusLeakageDetected {
		return fmt.Errorf("leakage detected: %s", fallback(lg.Reason, "train/validation overlap detected"))
	}
	if ver.Status != twin.LeakageStatusVerifiedNoLeakage || !lg.Verified || !lg.Proven {
		reason := strings.TrimSpace(lg.Reason)
		if reason == "" {
			reason = strings.TrimSpace(ver.Summary)
		}
		if reason == "" {
			reason = "insufficient provenance/IDs to verify separation"
		}
		return fmt.Errorf("leakage cannot be verified as absent: %s", reason)
	}
	return nil
}

func hashFileSHA256Hex(path string) (string, error) {
	clean := filepath.Clean(strings.TrimSpace(path))
	b, err := os.ReadFile(clean) // #nosec G304 -- local artifact/file selected by operator for provenance hashing
	if err != nil {
		return "", err
	}
	return twin.HashBytesSHA256(b), nil
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func durationMS(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

func parseSplitMetaFlag(s string) (*twin.SplitSpec, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	var v twin.SplitSpec
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func parseDatasetMetaFlag(s string) (*twin.DatasetRef, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	var v twin.DatasetRef
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func parseLeakageMetaFlag(s string) (*twin.LeakageGuard, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	var v twin.LeakageGuard
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return nil, err
	}
	return &v, nil
}
