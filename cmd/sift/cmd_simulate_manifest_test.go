package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/asadbekabdulboqiyev/sift/internal/twin"
)

func writeBacktestPairsFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "pairs.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write pairs: %v", err)
	}
	return p
}

func TestDatasetManifestValidateLoadAndVerifyBacktestPairs(t *testing.T) {
	pairs := writeBacktestPairsFile(t, `{"predicted":[10,11,12,13],"actual":[10,10,12,12]}`)
	m, err := twin.CreateBacktestPairsManifest(pairs, []string{"0", "1"}, []string{"2", "3"}, "explicit_ids", twin.BacktestManifestOptions{RecordCount: 4, MetricScope: "latency_p99_ms"})
	if err != nil {
		t.Fatalf("CreateBacktestPairsManifest: %v", err)
	}
	if m.SchemaVersion != twin.DatasetManifestSchemaVersion {
		t.Fatalf("schema=%q want %q", m.SchemaVersion, twin.DatasetManifestSchemaVersion)
	}
	if len(m.Datasets) == 0 || m.Split == nil || m.Split.Train == nil || m.Split.Validation == nil {
		t.Fatalf("manifest missing dataset/split: %+v", m)
	}
	mpath := filepath.Join(t.TempDir(), "manifest.json")
	if _, err := twin.WriteManifest(mpath, m); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}
	loaded, err := twin.LoadManifest(mpath)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	ver := twin.VerifyManifestSeparation(loaded)
	if ver.Status != twin.LeakageStatusVerifiedNoLeakage || !ver.Verified || ver.LeakageDetected {
		t.Fatalf("expected verified no leakage, got %+v", ver)
	}
	if ver.OverlapCount != 0 {
		t.Fatalf("overlap=%d want 0", ver.OverlapCount)
	}
}

func TestManifestVerificationDetectsOverlapAndTimeBoundaryLeakage(t *testing.T) {
	pairs := writeBacktestPairsFile(t, `{"predicted":[1,2,3],"actual":[1,2,3]}`)
	overlap, err := twin.CreateBacktestPairsManifest(pairs, []string{"0", "1"}, []string{"1", "2"}, "explicit_ids", twin.BacktestManifestOptions{RecordCount: 3})
	if err != nil {
		t.Fatalf("create overlap manifest: %v", err)
	}
	ver := twin.VerifyManifestSeparation(overlap)
	if ver.Status != twin.LeakageStatusLeakageDetected || !ver.LeakageDetected || ver.OverlapCount == 0 {
		t.Fatalf("expected overlap leakage detected, got %+v", ver)
	}

	timeBad, err := twin.CreateBacktestPairsManifest(pairs, []string{"0"}, []string{"1"}, "time_cutoff", twin.BacktestManifestOptions{
		RecordCount:     2,
		TrainEnd:        "2026-01-02T00:00:00Z",
		ValidationStart: "2026-01-01T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("create time manifest: %v", err)
	}
	ver = twin.VerifyManifestSeparation(timeBad)
	if ver.Status != twin.LeakageStatusLeakageDetected || !ver.LeakageDetected {
		t.Fatalf("expected time boundary leakage detected, got %+v", ver)
	}
}

func TestCmdSimulateBacktestStrictValidationWithManifest(t *testing.T) {
	pairs := writeBacktestPairsFile(t, `{"predicted":[100,110,120,130],"actual":[98,109,121,129]}`)
	manifest := filepath.Join(t.TempDir(), "backtest-manifest.json")
	m, err := twin.CreateBacktestPairsManifest(pairs, []string{"0", "1"}, []string{"2", "3"}, "explicit_ids", twin.BacktestManifestOptions{RecordCount: 4})
	if err != nil {
		t.Fatalf("create manifest: %v", err)
	}
	if _, err := twin.WriteManifest(manifest, m); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	modelPath := fitModel(t, t.TempDir())
	outDir := t.TempDir()

	res := runCommandFn(t, cmdSimulate, "simulate", "backtest",
		"--input", pairs,
		"--model", modelPath,
		"--manifest", manifest,
		"--strict-validation",
		"--update-model",
		"--out", outDir,
	)
	if res.code != 0 {
		t.Fatalf("exit=%d stderr=%s stdout=%s", res.code, res.stderr, res.stdout)
	}
	if !strings.Contains(res.stdout, "leakage: status=verified_no_leakage verified=true proven=true") {
		t.Fatalf("stdout missing verified leakage status:\n%s", res.stdout)
	}
	art, err := os.ReadFile(filepath.Join(outDir, "validation-backtest.json"))
	if err != nil {
		t.Fatalf("read artifact: %v", err)
	}
	var obj map[string]any
	if err := json.Unmarshal(art, &obj); err != nil {
		t.Fatalf("unmarshal artifact: %v", err)
	}
	if obj["manifest_path"] == "" {
		t.Fatal("artifact missing manifest_path")
	}
	if obj["verification_status"] != twin.LeakageStatusVerifiedNoLeakage {
		t.Fatalf("verification_status=%v want %s", obj["verification_status"], twin.LeakageStatusVerifiedNoLeakage)
	}
	leakage, _ := obj["leakage"].(map[string]any)
	if leakage == nil || leakage["status"] != twin.LeakageStatusVerifiedNoLeakage || leakage["verified"] != true || leakage["proven"] != true {
		t.Fatalf("artifact leakage not verified: %#v", obj["leakage"])
	}
	vr, _ := obj["validation_record"].(map[string]any)
	if vr == nil || vr["manifest_path"] == "" {
		t.Fatalf("validation_record missing manifest provenance: %#v", vr)
	}
	model, err := twin.LoadModel(modelPath)
	if err != nil {
		t.Fatalf("LoadModel: %v", err)
	}
	if model.ModelInfo == nil || model.ModelInfo.LastValidation == nil {
		t.Fatal("expected persisted last_validation")
	}
	if model.ModelInfo.LastValidation.Leakage == nil || model.ModelInfo.LastValidation.Leakage.Status != twin.LeakageStatusVerifiedNoLeakage {
		t.Fatalf("persisted leakage status not verified: %+v", model.ModelInfo.LastValidation.Leakage)
	}
	if model.ModelInfo.LastValidation.ManifestPath == "" || model.ModelInfo.LastValidation.VerificationStatus != twin.LeakageStatusVerifiedNoLeakage {
		t.Fatalf("persisted validation record missing manifest/verification: %+v", model.ModelInfo.LastValidation)
	}
	if len(model.ModelInfo.ValidationHistory) == 0 {
		t.Fatal("expected validation history")
	}
}

func TestCmdSimulateBacktestStrictFailsOnOverlap(t *testing.T) {
	pairs := writeBacktestPairsFile(t, `{"predicted":[1,2,3,4],"actual":[1,2,3,4]}`)
	manifest := filepath.Join(t.TempDir(), "bad-manifest.json")
	m, err := twin.CreateBacktestPairsManifest(pairs, []string{"0", "1", "2"}, []string{"2", "3"}, "explicit_ids", twin.BacktestManifestOptions{RecordCount: 4})
	if err != nil {
		t.Fatalf("create manifest: %v", err)
	}
	if _, err := twin.WriteManifest(manifest, m); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	res := runCommandFn(t, cmdSimulate, "simulate", "backtest",
		"--input", pairs,
		"--manifest", manifest,
		"--strict-no-leakage",
		"--out", t.TempDir(),
	)
	if res.code != 1 {
		t.Fatalf("exit=%d want 1 stderr=%s stdout=%s", res.code, res.stderr, res.stdout)
	}
	if !strings.Contains(res.stderr, "leakage detected") {
		t.Fatalf("stderr missing leakage detected: %s", res.stderr)
	}
}

func TestCmdSimulateBacktestMetadataOnlyRejectedAsUnverifiedInStrictMode(t *testing.T) {
	pairs := writeBacktestPairsFile(t, `{"predicted":[1,2,3],"actual":[1,2,3],"split":{"strategy":"explicit"},"leakage":{"enforced":true,"proven":true,"method":"metadata"}}`)
	res := runCommandFn(t, cmdSimulate, "simulate", "backtest",
		"--input", pairs,
		"--strict-validation",
		"--out", t.TempDir(),
	)
	if res.code != 1 {
		t.Fatalf("exit=%d want 1 stderr=%s stdout=%s", res.code, res.stderr, res.stdout)
	}
	if !strings.Contains(res.stderr, "strict validation requires a canonical dataset manifest") && !strings.Contains(res.stderr, "leakage cannot be verified as absent") {
		t.Fatalf("stderr missing strict unverified failure: %s", res.stderr)
	}
}

func TestCmdSimulateBacktestMetadataOnlyRecordedAsUnverified(t *testing.T) {
	pairs := writeBacktestPairsFile(t, `{"predicted":[1,2,3],"actual":[1,2,3],"split":{"strategy":"explicit"},"leakage":{"enforced":true,"proven":true,"method":"metadata"}}`)
	outDir := t.TempDir()
	res := runCommandFn(t, cmdSimulate, "simulate", "backtest",
		"--input", pairs,
		"--out", outDir,
	)
	if res.code != 0 {
		t.Fatalf("exit=%d stderr=%s stdout=%s", res.code, res.stderr, res.stdout)
	}
	if !strings.Contains(res.stdout, "leakage: status=unverified verified=false proven=false") {
		t.Fatalf("stdout should record metadata-only as unverified:\n%s", res.stdout)
	}
	art, err := os.ReadFile(filepath.Join(outDir, "validation-backtest.json"))
	if err != nil {
		t.Fatalf("read artifact: %v", err)
	}
	var obj map[string]any
	if err := json.Unmarshal(art, &obj); err != nil {
		t.Fatalf("unmarshal artifact: %v", err)
	}
	leakage, _ := obj["leakage"].(map[string]any)
	if leakage == nil || leakage["status"] != twin.LeakageStatusUnverified || leakage["verified"] == true || leakage["proven"] == true {
		t.Fatalf("metadata-only claim must be unverified/unproven: %#v", obj["leakage"])
	}
}

func TestCmdSimulateValidateStrictWithManifestAndUnverifiedFailure(t *testing.T) {
	modelPath := fitModel(t, t.TempDir())
	actualPath := writeSimulateReport(t)
	outDir := t.TempDir()

	// Insufficient provenance manifest (same-source-style incomplete split) => strict must fail.
	badManifestPath := filepath.Join(t.TempDir(), "validate-bad.json")
	bad := twin.DatasetManifest{
		SchemaVersion: twin.DatasetManifestSchemaVersion,
		Kind:          twin.ManifestKindValidateCompare,
		Split: &twin.ManifestSplit{
			Strategy:   "unknown",
			Train:      &twin.SplitPartition{DatasetID: "train-src"},
			Validation: &twin.SplitPartition{DatasetID: "train-src"},
		},
	}
	if _, err := twin.WriteManifest(badManifestPath, bad); err != nil {
		t.Fatalf("write bad manifest: %v", err)
	}
	res := runCommandFn(t, cmdSimulate, "simulate", "validate",
		"--model", modelPath,
		"--actual", actualPath,
		"--scenario", "likely",
		"--manifest", badManifestPath,
		"--strict-validation",
		"--out", outDir,
	)
	if res.code != 1 {
		t.Fatalf("exit=%d want 1 stderr=%s stdout=%s", res.code, res.stderr, res.stdout)
	}
	if !strings.Contains(res.stderr, "leakage cannot be verified as absent") && !strings.Contains(res.stderr, "leakage detected") {
		t.Fatalf("stderr missing strict verification failure: %s", res.stderr)
	}

	// Verified separate-source manifest => strict passes and persists history.
	goodManifestPath := filepath.Join(t.TempDir(), "validate-good.json")
	good, err := twin.CreateValidateCompareManifest(actualPath, modelPath, twin.ValidateManifestOptions{
		Strategy:     "separate_files",
		TrainPath:    modelPath,
		TrainKind:    "prediction_model",
		TrainID:      "model-fit",
		ValidationID: "actual-report",
		MetricScope:  "p95_p99_rps",
	})
	if err != nil {
		t.Fatalf("create validate manifest: %v", err)
	}
	if _, err := twin.WriteManifest(goodManifestPath, good); err != nil {
		t.Fatalf("write good manifest: %v", err)
	}
	outDir2 := t.TempDir()
	res = runCommandFn(t, cmdSimulate, "simulate", "validate",
		"--model", modelPath,
		"--actual", actualPath,
		"--scenario", "likely",
		"--manifest", goodManifestPath,
		"--strict-no-leakage",
		"--update-model",
		"--out", outDir2,
	)
	if res.code != 0 {
		t.Fatalf("exit=%d stderr=%s stdout=%s", res.code, res.stderr, res.stdout)
	}
	if !strings.Contains(res.stdout, "status=verified_no_leakage") || !strings.Contains(res.stdout, "verified=true") || !strings.Contains(res.stdout, "proven=true") {
		t.Fatalf("stdout missing verified status:\n%s", res.stdout)
	}
	art, err := os.ReadFile(filepath.Join(outDir2, "validation-compare.json"))
	if err != nil {
		t.Fatalf("read artifact: %v", err)
	}
	var obj map[string]any
	if err := json.Unmarshal(art, &obj); err != nil {
		t.Fatalf("unmarshal artifact: %v", err)
	}
	if obj["manifest_path"] == "" || obj["verification_status"] != twin.LeakageStatusVerifiedNoLeakage {
		t.Fatalf("artifact missing verified manifest provenance: manifest_path=%v status=%v", obj["manifest_path"], obj["verification_status"])
	}
	model, err := twin.LoadModel(modelPath)
	if err != nil {
		t.Fatalf("LoadModel: %v", err)
	}
	if model.ModelInfo == nil || model.ModelInfo.LastValidation == nil {
		t.Fatal("expected persisted last_validation")
	}
	if model.ModelInfo.LastValidation.VerificationStatus != twin.LeakageStatusVerifiedNoLeakage {
		t.Fatalf("persisted verification status=%q", model.ModelInfo.LastValidation.VerificationStatus)
	}
	if model.ModelInfo.LastValidation.ManifestPath == "" || model.ModelInfo.LastValidation.Leakage == nil || !model.ModelInfo.LastValidation.Leakage.Proven {
		t.Fatalf("persisted record missing manifest/proven leakage: %+v", model.ModelInfo.LastValidation)
	}
	if len(model.ModelInfo.ValidationHistory) == 0 || model.ModelInfo.ValidationHistory[0].ManifestPath == "" {
		t.Fatalf("expected validation history with manifest provenance: %+v", model.ModelInfo.ValidationHistory)
	}
}
