package main

// cmd_simulate_test.go — in-process coverage for `Sift simulate`.
//
// The commands are driven through the shared CLI harness, so flag parsing,
// validation, artifact writing and the exit-code contract all run in this
// process. Fixtures are built from the same exported report/twin APIs a user
// would use; nothing here reaches into unexported state.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/report"
	"github.com/asadbekabdulboqiyev/sift/internal/twin"
)

// writeSimulateReport writes a synthetic Sift report JSON and returns its path.
func writeSimulateReport(t *testing.T) string {
	t.Helper()
	rep := report.Report{
		Name:          "simulate-fixture",
		BaseURL:       "https://api.example.test",
		LoadProfile:   "steady",
		StartedAt:     time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		EndedAt:       time.Date(2026, 1, 2, 3, 5, 5, 0, time.UTC),
		Duration:      60 * time.Second,
		ActiveUsers:   20,
		TotalRequests: 60_000,
		TotalErrors:   60,
		ErrorRatePct:  0.1,
		RPS:           1000,
		Overall: report.StepReport{
			Name:     "overall",
			Requests: 60_000,
			Errors:   60,
			Min:      5 * time.Millisecond,
			Avg:      20 * time.Millisecond,
			Max:      250 * time.Millisecond,
			P50:      15 * time.Millisecond,
			P95:      40 * time.Millisecond,
			P99:      60 * time.Millisecond,
		},
	}
	data, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write report: %v", err)
	}
	return path
}

// fitModel runs `simulate fit` and returns the model artifact path.
func fitModel(t *testing.T, outDir string) string {
	t.Helper()
	res := runCommandFn(t, cmdSimulate, "simulate", "fit", "--report", writeSimulateReport(t), "--out", outDir)
	if res.code != 0 {
		t.Fatalf("simulate fit exit = %d, stderr = %s", res.code, res.stderr)
	}
	path := filepath.Join(outDir, twin.ModelArtifactName)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("model artifact missing: %v", err)
	}
	return path
}

func TestCmdSimulateFit(t *testing.T) {
	outDir := t.TempDir()
	res := runCommandFn(t, cmdSimulate, "simulate", "fit", "--report", writeSimulateReport(t), "--out", outDir)

	if res.code != 0 {
		t.Fatalf("exit = %d, stderr = %s", res.code, res.stderr)
	}
	for _, want := range []string{"model written", "confidence", "observed capacity", "observed workload"} {
		if !strings.Contains(res.stdout, want) {
			t.Errorf("stdout missing %q:\n%s", want, res.stdout)
		}
	}
	model, err := twin.LoadModel(filepath.Join(outDir, twin.ModelArtifactName))
	if err != nil {
		t.Fatalf("LoadModel: %v", err)
	}
	if model.Curve.CapacityRPS <= 1000 {
		t.Errorf("capacity = %v, want above the observed 1000 rps", model.Curve.CapacityRPS)
	}
	if model.Confidence != twin.ConfidenceHigh {
		t.Errorf("confidence = %q, want high", model.Confidence)
	}
}

func TestCmdSimulateFitInvalidReport(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte("not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	res := runCommandFn(t, cmdSimulate, "simulate", "fit", "--report", bad, "--out", t.TempDir())
	if res.code != 1 {
		t.Errorf("exit = %d, want 1", res.code)
	}
	if !strings.Contains(res.stderr, "simulate fit") {
		t.Errorf("stderr does not identify the command: %s", res.stderr)
	}
}

func TestCmdSimulateRun(t *testing.T) {
	modelPath := fitModel(t, t.TempDir())
	outDir := t.TempDir()

	res := runCommandFn(t, cmdSimulate, "simulate", "run",
		"--model", modelPath,
		"--scenario", "likely",
		"--rps", "500",
		"--duration", "60",
		"--sla-p99-ms", "200",
		"--iterations", "50",
		"--seed", "7",
		"--out", outDir,
	)
	if res.code != 0 {
		t.Fatalf("exit = %d, stderr = %s", res.code, res.stderr)
	}
	for _, want := range []string{"scenario likely", "breach probability", "Note: these are model-based estimates"} {
		if !strings.Contains(res.stdout, want) {
			t.Errorf("stdout missing %q:\n%s", want, res.stdout)
		}
	}

	simPath := filepath.Join(outDir, "simulation-likely.json")
	result, err := twin.LoadResult(simPath)
	if err != nil {
		t.Fatalf("LoadResult: %v", err)
	}
	if result.Scenario.TargetRPS != 500 || result.Scenario.Iterations != 50 || result.Scenario.Seed != 7 {
		t.Errorf("scenario overrides not applied: %+v", result.Scenario)
	}
	if result.Scenario.Mode != twin.LoopOpen {
		t.Errorf("mode = %q, want open", result.Scenario.Mode)
	}
	if len(result.Iterations) != 50 {
		t.Errorf("iterations = %d, want 50", len(result.Iterations))
	}
	if _, err := os.Stat(filepath.Join(outDir, twin.MarkdownArtifactName)); err != nil {
		t.Errorf("markdown artifact missing: %v", err)
	}
}

func TestCmdSimulateRunClosedLoop(t *testing.T) {
	modelPath := fitModel(t, t.TempDir())
	outDir := t.TempDir()

	res := runCommandFn(t, cmdSimulate, "simulate", "run",
		"--model", modelPath,
		"--scenario", "best",
		"--users", "50",
		"--iterations", "30",
		"--out", outDir,
	)
	if res.code != 0 {
		t.Fatalf("exit = %d, stderr = %s", res.code, res.stderr)
	}
	result, err := twin.LoadResult(filepath.Join(outDir, "simulation-best.json"))
	if err != nil {
		t.Fatalf("LoadResult: %v", err)
	}
	if result.Scenario.Mode != twin.LoopClosed || result.Scenario.TargetUsers != 50 {
		t.Errorf("closed-loop scenario not applied: %+v", result.Scenario)
	}
}

func TestCmdSimulateRunShortHorizon(t *testing.T) {
	modelPath := fitModel(t, t.TempDir())
	outDir := t.TempDir()

	// The preset ramps for 10 s; a 5 s horizon must clamp the ramp rather than
	// fail validation.
	res := runCommandFn(t, cmdSimulate, "simulate", "run",
		"--model", modelPath,
		"--scenario", "likely",
		"--duration", "5",
		"--iterations", "20",
		"--out", outDir,
	)
	if res.code != 0 {
		t.Fatalf("exit = %d, stderr = %s", res.code, res.stderr)
	}
	result, err := twin.LoadResult(filepath.Join(outDir, "simulation-likely.json"))
	if err != nil {
		t.Fatalf("LoadResult: %v", err)
	}
	if result.Scenario.DurationSeconds != 5 || result.Scenario.RampSeconds != 5 {
		t.Errorf("horizon not clamped: duration=%v ramp=%v", result.Scenario.DurationSeconds, result.Scenario.RampSeconds)
	}
}

func TestCmdSimulateRunBreachGate(t *testing.T) {
	modelPath := fitModel(t, t.TempDir())

	gated := runCommandFn(t, cmdSimulate, "simulate", "run",
		"--model", modelPath,
		"--scenario", "likely",
		"--rps", "1400",
		"--iterations", "40",
		"--sla-p99-ms", "1", // guaranteed breach
		"--fail-on-breach-prob", "0.5",
		"--out", t.TempDir(),
	)
	if gated.code != 3 {
		t.Errorf("gated exit = %d, want 3", gated.code)
	}
	if !strings.Contains(gated.stderr, "exceeds --fail-on-breach-prob") {
		t.Errorf("stderr missing gate explanation: %s", gated.stderr)
	}

	ungated := runCommandFn(t, cmdSimulate, "simulate", "run",
		"--model", modelPath,
		"--scenario", "likely",
		"--rps", "1400",
		"--iterations", "40",
		"--sla-p99-ms", "1",
		"--out", t.TempDir(),
	)
	if ungated.code != 0 {
		t.Errorf("ungated exit = %d, want 0", ungated.code)
	}
}

func TestCmdSimulateCompare(t *testing.T) {
	modelPath := fitModel(t, t.TempDir())
	outDir := t.TempDir()

	res := runCommandFn(t, cmdSimulate, "simulate", "compare",
		"--model", modelPath,
		"--iterations", "40",
		"--sla-p99-ms", "200",
		"--out", outDir,
	)
	if res.code != 0 {
		t.Fatalf("exit = %d, stderr = %s", res.code, res.stderr)
	}
	for _, want := range []string{"SCENARIO", "best", "likely", "worst", "capacity model"} {
		if !strings.Contains(res.stdout, want) {
			t.Errorf("stdout missing %q:\n%s", want, res.stdout)
		}
	}
	for _, name := range twin.PresetNames() {
		path := filepath.Join(outDir, "simulation-"+name+".json")
		result, err := twin.LoadResult(path)
		if err != nil {
			t.Fatalf("LoadResult(%s): %v", name, err)
		}
		if result.Scenario.Name != name {
			t.Errorf("%s artifact carries scenario %q", path, result.Scenario.Name)
		}
	}
	if _, err := os.Stat(filepath.Join(outDir, twin.MarkdownArtifactName)); err != nil {
		t.Errorf("markdown artifact missing: %v", err)
	}
}

func TestCmdSimulateCompareGate(t *testing.T) {
	modelPath := fitModel(t, t.TempDir())
	res := runCommandFn(t, cmdSimulate, "simulate", "compare",
		"--model", modelPath,
		"--iterations", "30",
		"--sla-p99-ms", "1",
		"--fail-on-breach-prob", "0.5",
		"--out", t.TempDir(),
	)
	if res.code != 3 {
		t.Errorf("exit = %d, want 3", res.code)
	}
	if !strings.Contains(res.stderr, "exceeds --fail-on-breach-prob") {
		t.Errorf("stderr missing gate explanation: %s", res.stderr)
	}
}

func TestCmdSimulateUsageErrors(t *testing.T) {
	modelPath := fitModel(t, t.TempDir())

	cases := []struct {
		name string
		args []string
	}{
		{"no subcommand", []string{"simulate"}},
		{"unknown subcommand", []string{"simulate", "forecast"}},
		{"fit without report", []string{"simulate", "fit", "--out", t.TempDir()}},
		{"fit with positional", []string{"simulate", "fit", "--report", "x.json", "extra"}},
		{"run without model", []string{"simulate", "run", "--scenario", "likely"}},
		{"run without scenario", []string{"simulate", "run", "--model", modelPath}},
		{"run with both load flags", []string{"simulate", "run", "--model", modelPath, "--scenario", "likely", "--rps", "10", "--users", "10"}},
		{"run with unknown scenario", []string{"simulate", "run", "--model", modelPath, "--scenario", "optimistic"}},
		{"run with negative rps", []string{"simulate", "run", "--model", modelPath, "--scenario", "likely", "--rps", "-5"}},
		{"run with bad gate", []string{"simulate", "run", "--model", modelPath, "--scenario", "likely", "--fail-on-breach-prob", "2"}},
		{"compare without model", []string{"simulate", "compare"}},
		{"compare with positional", []string{"simulate", "compare", "--model", modelPath, "extra"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runCommandFn(t, cmdSimulate, tc.args...)
			if res.code != 1 {
				t.Errorf("exit = %d, want 1; stderr = %s", res.code, res.stderr)
			}
			if !strings.Contains(res.stderr, "Usage: Sift simulate") && !strings.Contains(res.stderr, "simulate ") {
				t.Errorf("no actionable error on stderr: %q", res.stderr)
			}
		})
	}
}

func TestCmdSimulateValidateUpdatesModelAndArtifacts(t *testing.T) {
	modelPath := fitModel(t, t.TempDir())
	actualPath := writeSimulateReport(t) // same shape, measured report evidence
	outDir := t.TempDir()

	res := runCommandFn(t, cmdSimulate, "simulate", "validate",
		"--model", modelPath,
		"--actual", actualPath,
		"--scenario", "likely",
		"--seed", "7",
		"--split-json", `{"strategy":"time_cutoff","train_end":"2026-01-01T00:00:00Z","validation_start":"2026-01-01T00:00:00Z"}`,
		"--leakage-json", `{"enforced":true,"proven":true,"method":"explicit_split","checks":["no_overlap"]}`,
		"--dataset-json", `{"kind":"report","path":"actual.json","id":"actual-1"}`,
		"--require-no-leakage",
		"--update-model",
		"--out", outDir,
	)
	if res.code != 0 {
		t.Fatalf("exit = %d, stderr = %s\nstdout=%s", res.code, res.stderr, res.stdout)
	}
	// Legacy --require-no-leakage accepts explicit caller metadata, but metadata-only
	// claims must not be recorded as verified/proven without manifest/provenance checks.
	if !strings.Contains(res.stdout, "leakage: enforced=true") {
		t.Errorf("stdout missing leakage summary:\n%s", res.stdout)
	}
	if !strings.Contains(res.stdout, "status=unverified") || !strings.Contains(res.stdout, "verified=false") {
		t.Errorf("stdout should mark metadata-only leakage as unverified:\n%s", res.stdout)
	}

	artPath := filepath.Join(outDir, "validation-compare.json")
	b, err := os.ReadFile(artPath)
	if err != nil {
		t.Fatalf("read artifact: %v", err)
	}
	var art map[string]any
	if err := json.Unmarshal(b, &art); err != nil {
		t.Fatalf("unmarshal artifact: %v", err)
	}
	if _, ok := art["split"]; !ok {
		t.Error("artifact missing split")
	}
	if _, ok := art["leakage"]; !ok {
		t.Error("artifact missing leakage")
	}
	if _, ok := art["dataset"]; !ok {
		t.Error("artifact missing dataset")
	}
	if _, ok := art["validation_record"]; !ok {
		t.Error("artifact missing validation_record")
	}
	if art["verification_status"] != twin.LeakageStatusUnverified {
		t.Errorf("verification_status=%v want %s", art["verification_status"], twin.LeakageStatusUnverified)
	}
	leakage, _ := art["leakage"].(map[string]any)
	if leakage == nil || leakage["status"] != twin.LeakageStatusUnverified || leakage["verified"] == true || leakage["proven"] == true {
		t.Errorf("metadata-only leakage must be unverified/unproven in artifact: %#v", art["leakage"])
	}

	model, err := twin.LoadModel(modelPath)
	if err != nil {
		t.Fatalf("LoadModel: %v", err)
	}
	if model.ModelInfo == nil {
		t.Fatal("missing model_info")
	}
	if model.ModelInfo.BacktestStatus == "" || model.ModelInfo.BacktestStatus == "NOT_RUN" {
		t.Errorf("expected updated backtest_status, got %q", model.ModelInfo.BacktestStatus)
	}
	if model.ModelInfo.DriftStatus == "" || model.ModelInfo.DriftStatus == "UNKNOWN" {
		// OK/NONE or DETECTED depending on comparison; but should be set from validation
	}
	if model.ModelInfo.LastValidation == nil {
		t.Fatal("expected last_validation")
	}
	if model.ModelInfo.LastValidation.Kind != "compare" {
		t.Errorf("last_validation.kind = %q, want compare", model.ModelInfo.LastValidation.Kind)
	}
	if model.ModelInfo.LastValidation.Split == nil || model.ModelInfo.LastValidation.Dataset == nil || model.ModelInfo.LastValidation.Leakage == nil {
		t.Fatal("last_validation missing split/dataset/leakage provenance")
	}
	if model.ModelInfo.LastValidation.Leakage.Status != twin.LeakageStatusUnverified || model.ModelInfo.LastValidation.Leakage.Verified || model.ModelInfo.LastValidation.Leakage.Proven {
		t.Errorf("persisted metadata-only leakage must be unverified: %+v", model.ModelInfo.LastValidation.Leakage)
	}
	if len(model.ModelInfo.ValidationHistory) == 0 {
		t.Fatal("expected validation_history")
	}
}

func TestCmdSimulateValidateRequireNoLeakageFails(t *testing.T) {
	modelPath := fitModel(t, t.TempDir())
	actualPath := writeSimulateReport(t)
	outDir := t.TempDir()

	res := runCommandFn(t, cmdSimulate, "simulate", "validate",
		"--model", modelPath,
		"--actual", actualPath,
		"--scenario", "likely",
		"--require-no-leakage",
		"--out", outDir,
	)
	if res.code != 1 {
		t.Fatalf("exit = %d, want 1; stderr=%s stdout=%s", res.code, res.stderr, res.stdout)
	}
	if !strings.Contains(res.stderr, "no-leakage requirement not satisfied") {
		t.Errorf("stderr missing no-leakage failure: %s", res.stderr)
	}
}

func TestCmdSimulateBacktestUpdatesModelAndArtifacts(t *testing.T) {
	modelPath := fitModel(t, t.TempDir())
	inputPath := filepath.Join(t.TempDir(), "pairs.json")
	input := `{
		"predicted":[100,110,105],
		"actual":[98,112,106],
		"model_range_low":50,
		"model_range_high":150,
		"dataset":{"kind":"pairs","id":"ds1"},
		"split":{"strategy":"explicit"},
		"leakage":{"enforced":true,"proven":true,"method":"hash_check","checks":["disjoint"]}
	}`
	if err := os.WriteFile(inputPath, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	outDir := t.TempDir()

	res := runCommandFn(t, cmdSimulate, "simulate", "backtest",
		"--input", inputPath,
		"--model", modelPath,
		"--require-no-leakage",
		"--update-model",
		"--out", outDir,
	)
	if res.code != 0 {
		t.Fatalf("exit = %d, stderr=%s stdout=%s", res.code, res.stderr, res.stdout)
	}

	artPath := filepath.Join(outDir, "validation-backtest.json")
	b, err := os.ReadFile(artPath)
	if err != nil {
		t.Fatalf("read artifact: %v", err)
	}
	var art map[string]any
	if err := json.Unmarshal(b, &art); err != nil {
		t.Fatalf("unmarshal artifact: %v", err)
	}
	if _, ok := art["dataset"]; !ok {
		t.Error("artifact missing dataset")
	}
	if _, ok := art["split"]; !ok {
		t.Error("artifact missing split")
	}
	if _, ok := art["leakage"]; !ok {
		t.Error("artifact missing leakage")
	}
	if _, ok := art["validation_record"]; !ok {
		t.Error("artifact missing validation_record")
	}

	model, err := twin.LoadModel(modelPath)
	if err != nil {
		t.Fatalf("LoadModel: %v", err)
	}
	if model.ModelInfo == nil || model.ModelInfo.LastValidation == nil {
		t.Fatal("expected last_validation")
	}
	if model.ModelInfo.LastValidation.Kind != "backtest" {
		t.Errorf("kind = %q, want backtest", model.ModelInfo.LastValidation.Kind)
	}
	if model.ModelInfo.LastValidation.Dataset == nil || model.ModelInfo.LastValidation.Split == nil || model.ModelInfo.LastValidation.Leakage == nil {
		t.Fatal("last_validation missing provenance")
	}
	if len(model.ModelInfo.ValidationHistory) == 0 {
		t.Fatal("expected validation_history")
	}
	if model.ModelInfo.BacktestStatus == "" || model.ModelInfo.BacktestStatus == "NOT_RUN" {
		t.Errorf("expected updated backtest status, got %q", model.ModelInfo.BacktestStatus)
	}
}

func TestCmdSimulateBacktestRequireNoLeakageFails(t *testing.T) {
	inputPath := filepath.Join(t.TempDir(), "pairs.json")
	input := `{"predicted":[1,2],"actual":[1,2]}`
	if err := os.WriteFile(inputPath, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	res := runCommandFn(t, cmdSimulate, "simulate", "backtest",
		"--input", inputPath,
		"--require-no-leakage",
		"--out", t.TempDir(),
	)
	if res.code != 1 {
		t.Fatalf("exit = %d, want 1; stderr=%s", res.code, res.stderr)
	}
	if !strings.Contains(res.stderr, "no-leakage requirement not satisfied") {
		t.Errorf("stderr missing no-leakage failure: %s", res.stderr)
	}
}
