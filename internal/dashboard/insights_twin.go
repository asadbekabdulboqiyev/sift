package dashboard

import (
	"encoding/json"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/report"
	"github.com/asadbekabdulboqiyev/sift/internal/twin"
)

type twinSimulateRequest struct {
	Model            twin.Model `json:"model"`
	Scenario         string     `json:"scenario"`
	Mode             string     `json:"mode,omitempty"`
	TargetRPS        float64    `json:"target_rps,omitempty"`
	TargetUsers      float64    `json:"target_users,omitempty"`
	DurationSeconds  float64    `json:"duration_seconds,omitempty"`
	SLAP95MS         float64    `json:"sla_p95_ms,omitempty"`
	SLAP99MS         float64    `json:"sla_p99_ms,omitempty"`
	MaxErrorRatePct  float64    `json:"max_error_rate_pct,omitempty"`
	MinThroughputRPS float64    `json:"min_throughput_rps,omitempty"`
	Iterations       int        `json:"iterations,omitempty"`
	Seed             int64      `json:"seed,omitempty"`
	RampSeconds      *float64   `json:"ramp_seconds,omitempty"`
	FailOnBreachProb float64    `json:"fail_on_breach_prob,omitempty"`
	ScenarioType     string     `json:"scenario_type,omitempty"`
	// UI/legacy aliases for threshold fields.
	P95MSAlias      float64 `json:"p95_ms,omitempty"`
	P99MSAlias      float64 `json:"p99_ms,omitempty"`
	ErrorRateAlias  float64 `json:"error_rate_pct,omitempty"`
	ThroughputAlias float64 `json:"throughput_rps_min,omitempty"`
}

type twinCompareRequest struct {
	Model            *twin.Model           `json:"model,omitempty"`
	Scenario         string                `json:"scenario,omitempty"`
	Result           *twin.Result          `json:"result,omitempty"`
	Actual           report.Report         `json:"actual"`
	Seed             int64                 `json:"seed,omitempty"`
	Parameters       map[string]any        `json:"parameters,omitempty"`
	Assumptions      []string              `json:"assumptions,omitempty"`
	Dataset          *twin.DatasetRef      `json:"dataset,omitempty"`
	Split            *twin.SplitSpec       `json:"split,omitempty"`
	Leakage          *twin.LeakageGuard    `json:"leakage,omitempty"`
	Manifest         *twin.DatasetManifest `json:"manifest,omitempty"`
	StrictValidation bool                  `json:"strict_validation,omitempty"`
	StrictNoLeakage  bool                  `json:"strict_no_leakage,omitempty"`
}

type twinSensitivityRequest struct {
	Model    twin.Model     `json:"model"`
	Scenario string         `json:"scenario,omitempty"`
	Base     *twin.Scenario `json:"base,omitempty"`
	Seed     int64          `json:"seed,omitempty"`
}

type twinBacktestRequest struct {
	Predicted        []float64             `json:"predicted"`
	Actual           []float64             `json:"actual"`
	ModelRangeLow    float64               `json:"model_range_low,omitempty"`
	ModelRangeHigh   float64               `json:"model_range_high,omitempty"`
	ModelVersion     string                `json:"model_version,omitempty"`
	Parameters       map[string]any        `json:"parameters,omitempty"`
	Assumptions      []string              `json:"assumptions,omitempty"`
	Dataset          *twin.DatasetRef      `json:"dataset,omitempty"`
	Split            *twin.SplitSpec       `json:"split,omitempty"`
	Leakage          *twin.LeakageGuard    `json:"leakage,omitempty"`
	Manifest         *twin.DatasetManifest `json:"manifest,omitempty"`
	StrictValidation bool                  `json:"strict_validation,omitempty"`
	StrictNoLeakage  bool                  `json:"strict_no_leakage,omitempty"`
}

func (s *Server) handleInsightsTwinFit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin requests are not allowed", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, insightsMaxBody)
	defer func() { _ = r.Body.Close() }()

	var req twinFitRequest
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid JSON: " + err.Error()})
		return
	}
	if msg := validateFitReport(req.Report); msg != "" {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": msg})
		return
	}
	if req.TargetP99MS < 0 || math.IsNaN(req.TargetP99MS) || math.IsInf(req.TargetP99MS, 0) {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "target_p99_ms must be a finite non-negative number"})
		return
	}

	model, err := twin.Fit(req.Report, twin.FitOptions{TargetP99MS: req.TargetP99MS})
	if err != nil {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	insightsJSON(w, http.StatusOK, map[string]any{
		"ok":    true,
		"model": model,
		"note":  "Capacity model fitted from observed evidence with quantified confidence and uncertainty bounds.",
	})
}

func (s *Server) handleInsightsTwinSimulate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin requests are not allowed", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, insightsMaxBody)
	defer func() { _ = r.Body.Close() }()

	var req twinSimulateRequest
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid JSON: " + err.Error()})
		return
	}
	if strings.TrimSpace(req.Model.SchemaVersion) == "" && req.Model.Curve.CapacityRPS <= 0 {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "model is required"})
		return
	}
	if math.IsNaN(req.FailOnBreachProb) || math.IsInf(req.FailOnBreachProb, 0) || req.FailOnBreachProb < 0 || req.FailOnBreachProb > 1 {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "fail_on_breach_prob must be between 0 and 1"})
		return
	}

	sc, err := buildTwinScenario(req)
	if err != nil {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	seed := req.Seed
	if seed == 0 {
		seed = 42
	}
	res, err := twin.Simulate(req.Model, sc, seed)
	if err != nil {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}

	status := http.StatusOK
	breached := false
	if req.FailOnBreachProb > 0 && res.Summary.SLAProbabilityBreach > req.FailOnBreachProb {
		breached = true
		status = http.StatusConflict
	}
	insightsJSON(w, status, map[string]any{
		"ok":          !breached,
		"result":      res,
		"breach_gate": breached,
		"note":        "Scenario results include quantified uncertainty and confidence intervals for planning decisions.",
	})
}

func buildTwinScenario(req twinSimulateRequest) (twin.Scenario, error) {
	name := strings.ToLower(strings.TrimSpace(req.Scenario))
	if name == "" {
		name = "likely"
	}
	var sc twin.Scenario
	if preset, err := twin.Preset(name, req.Model); err == nil {
		sc = preset
	} else {
		// Custom: start from likely preset defaults if available, else minimal.
		if likely, lerr := twin.Preset("likely", req.Model); lerr == nil {
			sc = likely
			sc.Name = name
		} else {
			sc = twin.Scenario{Name: name, Mode: twin.LoopOpen, DurationSeconds: 60, Iterations: 200}
		}
	}

	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode == "closed" || req.TargetUsers > 0 {
		sc.Mode = twin.LoopClosed
		if req.TargetUsers > 0 {
			sc.TargetUsers = req.TargetUsers
		}
		if sc.TargetUsers <= 0 {
			sc.TargetUsers = req.Model.Workload.Concurrency
		}
	} else {
		sc.Mode = twin.LoopOpen
		if req.TargetRPS > 0 {
			sc.TargetRPS = req.TargetRPS
		}
		if sc.TargetRPS <= 0 {
			sc.TargetRPS = req.Model.Workload.RPS
		}
	}

	if req.DurationSeconds > 0 {
		sc.DurationSeconds = req.DurationSeconds
	}
	if req.SLAP95MS <= 0 {
		req.SLAP95MS = req.P95MSAlias
	}
	if req.SLAP99MS <= 0 {
		req.SLAP99MS = req.P99MSAlias
	}
	if req.MaxErrorRatePct <= 0 {
		req.MaxErrorRatePct = req.ErrorRateAlias
	}
	if req.MinThroughputRPS <= 0 {
		req.MinThroughputRPS = req.ThroughputAlias
	}
	if req.SLAP95MS > 0 {
		sc.SLAP95MS = req.SLAP95MS
	}
	if req.SLAP99MS > 0 {
		sc.SLAP99MS = req.SLAP99MS
	}
	if req.MaxErrorRatePct > 0 {
		sc.MaxErrorRatePct = req.MaxErrorRatePct
	}
	if req.MinThroughputRPS > 0 {
		sc.MinThroughputRPS = req.MinThroughputRPS
	}
	if strings.TrimSpace(req.ScenarioType) != "" {
		sc.ScenarioType = strings.TrimSpace(req.ScenarioType)
	}
	if req.Iterations > 0 {
		sc.Iterations = req.Iterations
	}
	if req.RampSeconds != nil {
		sc.RampSeconds = *req.RampSeconds
	}
	if sc.Iterations <= 0 {
		sc.Iterations = 200
	}
	if sc.DurationSeconds <= 0 {
		sc.DurationSeconds = 60
	}
	return sc, nil
}

// compareValidation groups the provenance/leakage outputs built for a compare
// request. Pointers are preserved so caller-visible mutation semantics are
// identical to the original inline block.
type compareValidation struct {
	leakage      *twin.LeakageGuard
	manifestCopy *twin.DatasetManifest
	verification *twin.LeakageVerification
	manifestPath string
}

// prepareCompareValidation builds the effective leakage guard from an inline
// manifest, or downgrades metadata-only claims. It never writes a response.
func prepareCompareValidation(req *twinCompareRequest) compareValidation {
	var manifestCopy *twin.DatasetManifest
	var verification *twin.LeakageVerification
	var manifestPath string
	leakage := req.Leakage
	if req.Manifest != nil {
		m := *req.Manifest
		manifestCopy = &m
		manifestPath = "inline:manifest"
		ver := twin.VerifyManifestSeparation(m)
		verification = &ver
		// Build effective leakage guard from manifest verification (provenance-based).
		eff := &twin.LeakageGuard{
			Enforced:           ver.Status == twin.LeakageStatusVerifiedNoLeakage,
			Proven:             ver.Verified && ver.Status == twin.LeakageStatusVerifiedNoLeakage,
			Verified:           ver.Verified,
			Status:             ver.Status,
			Method:             "manifest_provenance_verification",
			OverlapCount:       &ver.OverlapCount,
			Checks:             append([]string(nil), ver.Checks...),
			ManifestSchema:     m.SchemaVersion,
			ManifestKind:       m.Kind,
			VerificationSource: "manifest",
			Reason:             ver.Summary,
		}
		if len(ver.Reasons) > 0 {
			if strings.TrimSpace(eff.Reason) != "" {
				eff.Reason += "; " + strings.Join(ver.Reasons, "; ")
			} else {
				eff.Reason = strings.Join(ver.Reasons, "; ")
			}
		}
		// Preserve caller-provided metadata hints if not contradicted, but do not upgrade unverified status.
		if leakage != nil && strings.TrimSpace(leakage.Method) != "" && strings.TrimSpace(eff.Method) == "" {
			eff.Method = leakage.Method
		}
		leakage = eff
	} else if leakage == nil {
		leakage = &twin.LeakageGuard{Enforced: false, Proven: false, Status: twin.LeakageStatusUnverified, Reason: "no leakage proof provided; caller-provided metadata only (not persisted)"}
	} else {
		// Metadata-only claims are not provenance-verified without manifest
		// verification. Never accept a false verified_no_leakage on
		// contradictory/missing provenance.
		if leakage.Status == twin.LeakageStatusVerifiedNoLeakage || leakage.Verified || leakage.Proven || leakage.Enforced {
			leakage.Status = twin.LeakageStatusUnverified
			leakage.Proven = false
			leakage.Verified = false
			leakage.Enforced = false
			if strings.TrimSpace(leakage.Reason) == "" {
				leakage.Reason = "metadata-only leakage claim cannot be verified without manifest/provenance evidence"
			}
			leakage.VerificationSource = "metadata_unverified"
		}
		if strings.TrimSpace(leakage.Status) == "" {
			leakage.Status = twin.LeakageStatusUnverified
		}
		if !leakage.Enforced || !leakage.Proven || leakage.Status != twin.LeakageStatusVerifiedNoLeakage {
			if strings.TrimSpace(leakage.Reason) == "" {
				leakage.Reason = "leakage not explicitly enforced+proven by provided metadata"
			}
			if strings.TrimSpace(leakage.VerificationSource) == "" {
				leakage.VerificationSource = "metadata_unverified"
			}
		}
	}
	return compareValidation{
		leakage:      leakage,
		manifestCopy: manifestCopy,
		verification: verification,
		manifestPath: manifestPath,
	}
}

// compareModelMetadata collects model version, parameters and assumption
// lines for the validation record. It is pure and has no response writes.
func compareModelMetadata(req *twinCompareRequest) (string, map[string]any, []string) {
	modelVersion := ""
	var modelParams map[string]any
	var modelAssumptions []string
	if req.Model != nil && req.Model.ModelInfo != nil {
		modelVersion = req.Model.ModelInfo.Version
		if req.Model.ModelInfo.Parameters != nil {
			modelParams = make(map[string]any, len(req.Model.ModelInfo.Parameters))
			for k, v := range req.Model.ModelInfo.Parameters {
				modelParams[k] = v
			}
		}
		modelAssumptions = req.Model.ModelInfo.Assumptions
	}
	for k, v := range req.Parameters {
		if modelParams == nil {
			modelParams = map[string]any{}
		}
		modelParams[k] = v
	}
	assumptions := append([]string{
		"Prediction-vs-actual compares model-based simulated estimates to the provided actual report as validation evidence (actual metrics are not fabricated).",
		"Leakage/split provenance is caller-provided metadata unless independently verifiable; dashboard compare is stateless and does not persist or prove no-leakage.",
	}, modelAssumptions...)
	assumptions = append(assumptions, req.Assumptions...)
	return modelVersion, modelParams, assumptions
}

func (s *Server) handleInsightsTwinCompare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin requests are not allowed", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, insightsMaxBody)
	defer func() { _ = r.Body.Close() }()
	var req twinCompareRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid JSON: " + err.Error()})
		return
	}
	if req.Actual.Duration <= 0 && req.Actual.TotalRequests == 0 {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "actual report is required"})
		return
	}
	res := req.Result
	if res == nil {
		if req.Model == nil {
			insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "result or model+scenario required"})
			return
		}
		sc, err := buildTwinScenario(twinSimulateRequest{Model: *req.Model, Scenario: req.Scenario})
		if err != nil {
			insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		seed := req.Seed
		if seed == 0 {
			seed = 42
		}
		sim, err := twin.Simulate(*req.Model, sc, seed)
		if err != nil {
			insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		res = &sim
	}
	cmp := twin.ComparePredictionToActual(*res, req.Actual)
	derivedStatus, derivedDrift, derivedNote := twin.ComparisonValidationStatus(cmp)

	strict := req.StrictValidation || req.StrictNoLeakage
	cv := prepareCompareValidation(&req)
	manifestCopy, verification, manifestPath, leakage := cv.manifestCopy, cv.verification, cv.manifestPath, cv.leakage
	if strict {
		if req.Manifest == nil {
			insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "strict validation requires manifest/provenance (provide inline manifest with verifiable IDs/hashes/boundaries)"})
			return
		}
		if verification == nil || verification.Status != twin.LeakageStatusVerifiedNoLeakage || verification.LeakageDetected || !verification.Verified {
			reason := "manifest verification did not prove no leakage"
			if verification != nil && strings.TrimSpace(verification.Summary) != "" {
				reason = verification.Summary
			}
			insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "strict validation failed: " + reason, "verification": verification})
			return
		}
		if leakage == nil || !leakage.Enforced || !leakage.Proven || leakage.Status != twin.LeakageStatusVerifiedNoLeakage {
			insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "strict validation failed: leakage not proven absent by manifest/provenance verification"})
			return
		}
	}

	modelVersion, modelParams, assumptions := compareModelMetadata(&req)
	cmpCopy := cmp
	if verification != nil {
		assumptions = append(assumptions, "Manifest/provenance verification executed for provided inline manifest (stateless).")
	}
	if strict {
		assumptions = append(assumptions, "Strict validation requested: manifest/provenance verification required and leakage must be proven absent.")
	}
	validationRecord := twin.ValidationRecord{
		SchemaVersion:      "sift.twin-validation/v1",
		Kind:               "compare",
		GeneratedAt:        time.Now().UTC().Format(time.RFC3339Nano),
		ModelVersion:       modelVersion,
		Parameters:         modelParams,
		Assumptions:        assumptions,
		Dataset:            req.Dataset,
		Split:              req.Split,
		Leakage:            leakage,
		Manifest:           manifestCopy,
		ManifestPath:       manifestPath,
		VerificationStatus: leakage.Status,
		Verification:       verification,
		Comparison:         &cmpCopy,
		BacktestStatus:     derivedStatus,
		DriftStatus:        derivedDrift,
		ValidationNotes: []string{
			derivedNote,
			"Comparison uses provided actual report as validation evidence.",
			"Stateless dashboard response: not persisted.",
		},
	}
	resp := map[string]any{
		"ok":                        true,
		"comparison":                cmp,
		"derived_validation_status": derivedStatus,
		"derived_drift_status":      derivedDrift,
		"derived_note":              derivedNote,
		"parameters":                modelParams,
		"assumptions":               assumptions,
		"dataset":                   req.Dataset,
		"split":                     req.Split,
		"leakage":                   leakage,
		"validation_record":         validationRecord,
		"persisted":                 false,
		"persistence":               "not_persisted",
		"note":                      "Prediction-vs-actual compares model-based simulated estimates to measured report evidence (not fabricated). Stateless dashboard response includes structured provenance and is not persisted.",
	}
	if manifestCopy != nil {
		resp["manifest"] = manifestCopy
	}
	if verification != nil {
		resp["verification"] = verification
	}
	insightsJSON(w, http.StatusOK, resp)
}

func (s *Server) handleInsightsTwinSensitivity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin requests are not allowed", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, insightsMaxBody)
	defer func() { _ = r.Body.Close() }()
	var req twinSensitivityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid JSON: " + err.Error()})
		return
	}
	if req.Model.Curve.CapacityRPS <= 0 && strings.TrimSpace(req.Model.SchemaVersion) == "" {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "model is required"})
		return
	}
	base := req.Base
	if base == nil {
		name := strings.TrimSpace(req.Scenario)
		if name == "" {
			name = "normal"
		}
		sc, err := buildTwinScenario(twinSimulateRequest{Model: req.Model, Scenario: name})
		if err != nil {
			insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		base = &sc
	}
	seed := req.Seed
	if seed == 0 {
		seed = 42
	}
	sens, err := twin.AnalyzeSensitivity(req.Model, *base, seed)
	if err != nil {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	insightsJSON(w, http.StatusOK, map[string]any{
		"ok": true, "sensitivity": sens,
		"note": "Sensitivity analysis is deterministic for the same seed and quantifies model-based impact (proxies used where direct resource metrics unavailable).",
	})
}

func (s *Server) handleInsightsTwinBacktest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin requests are not allowed", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, insightsMaxBody)
	defer func() { _ = r.Body.Close() }()
	var req twinBacktestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid JSON: " + err.Error()})
		return
	}
	bt := twin.BacktestErrors(req.Predicted, req.Actual, req.ModelRangeLow, req.ModelRangeHigh)
	backtestStatus, driftStatus := bt.ValidationStatus()
	assumptions := append([]string{
		"Train/validation split and no-leakage must be enforced by the workflow when using historical datasets.",
		"Predictions and actuals must represent comparable scenarios/metrics.",
	}, req.Assumptions...)

	strict := req.StrictValidation || req.StrictNoLeakage
	var manifestCopy *twin.DatasetManifest
	var verification *twin.LeakageVerification
	var manifestPath string
	leakage := req.Leakage
	if req.Manifest != nil {
		m := *req.Manifest
		manifestCopy = &m
		manifestPath = "inline:manifest"
		ver := twin.VerifyManifestSeparation(m)
		verification = &ver
		eff := &twin.LeakageGuard{
			Enforced:           ver.Status == twin.LeakageStatusVerifiedNoLeakage,
			Proven:             ver.Verified && ver.Status == twin.LeakageStatusVerifiedNoLeakage,
			Verified:           ver.Verified,
			Status:             ver.Status,
			Method:             "manifest_provenance_verification",
			OverlapCount:       &ver.OverlapCount,
			Checks:             append([]string(nil), ver.Checks...),
			ManifestSchema:     m.SchemaVersion,
			ManifestKind:       m.Kind,
			VerificationSource: "manifest",
			Reason:             ver.Summary,
		}
		if len(ver.Reasons) > 0 {
			if strings.TrimSpace(eff.Reason) != "" {
				eff.Reason += "; " + strings.Join(ver.Reasons, "; ")
			} else {
				eff.Reason = strings.Join(ver.Reasons, "; ")
			}
		}
		leakage = eff
	} else if leakage == nil {
		leakage = &twin.LeakageGuard{Enforced: false, Proven: false, Status: twin.LeakageStatusUnverified, Reason: "no leakage proof provided; caller/workflow must enforce train/validation split and prevent leakage"}
	} else {
		// Metadata-only claims are not provenance-verified without manifest
		// verification. Never accept a false verified_no_leakage on
		// contradictory/missing provenance.
		if leakage.Status == twin.LeakageStatusVerifiedNoLeakage || leakage.Verified || leakage.Proven || leakage.Enforced {
			leakage.Status = twin.LeakageStatusUnverified
			leakage.Proven = false
			leakage.Verified = false
			leakage.Enforced = false
			if strings.TrimSpace(leakage.Reason) == "" {
				leakage.Reason = "metadata-only leakage claim cannot be verified without manifest/provenance evidence"
			}
			leakage.VerificationSource = "metadata_unverified"
		}
		if strings.TrimSpace(leakage.Status) == "" {
			leakage.Status = twin.LeakageStatusUnverified
		}
		if !leakage.Enforced || !leakage.Proven || leakage.Status != twin.LeakageStatusVerifiedNoLeakage {
			if strings.TrimSpace(leakage.Reason) == "" {
				leakage.Reason = "leakage not proven/enforced by provided metadata"
			}
			if strings.TrimSpace(leakage.VerificationSource) == "" {
				leakage.VerificationSource = "metadata_unverified"
			}
		}
	}
	if strict {
		if req.Manifest == nil {
			insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "strict validation requires manifest/provenance (provide inline manifest with verifiable IDs/hashes/boundaries)"})
			return
		}
		if verification == nil || verification.Status != twin.LeakageStatusVerifiedNoLeakage || verification.LeakageDetected || !verification.Verified {
			reason := "manifest verification did not prove no leakage"
			if verification != nil && strings.TrimSpace(verification.Summary) != "" {
				reason = verification.Summary
			}
			insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "strict validation failed: " + reason, "verification": verification})
			return
		}
		if leakage == nil || !leakage.Enforced || !leakage.Proven || leakage.Status != twin.LeakageStatusVerifiedNoLeakage {
			insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "strict validation failed: leakage not proven absent by manifest/provenance verification"})
			return
		}
	}
	if verification != nil {
		assumptions = append(assumptions, "Manifest/provenance verification executed for provided inline manifest (stateless).")
	}
	if strict {
		assumptions = append(assumptions, "Strict validation requested: manifest/provenance verification required and leakage must be proven absent.")
	}

	btCopy := bt
	record := twin.ValidationRecord{
		SchemaVersion:      "sift.twin-validation/v1",
		Kind:               "backtest",
		GeneratedAt:        time.Now().UTC().Format(time.RFC3339Nano),
		ModelVersion:       req.ModelVersion,
		Parameters:         req.Parameters,
		Assumptions:        assumptions,
		Dataset:            req.Dataset,
		Split:              req.Split,
		Leakage:            leakage,
		Manifest:           manifestCopy,
		ManifestPath:       manifestPath,
		VerificationStatus: leakage.Status,
		Verification:       verification,
		Backtest:           &btCopy,
		BacktestStatus:     backtestStatus,
		DriftStatus:        driftStatus,
	}
	resp := map[string]any{
		"ok": true, "backtest": bt, "validation_record": record,
		"derived_backtest_status": backtestStatus,
		"derived_drift_status":    driftStatus,
		"note":                    "Backtesting/validation metrics computed from provided paired samples; historical run orchestration and leakage prevention are caller/workflow responsibilities unless explicitly proven in metadata/manifest verification.",
		"leakage":                 leakage,
	}
	if manifestCopy != nil {
		resp["manifest"] = manifestCopy
	}
	if verification != nil {
		resp["verification"] = verification
	}
	insightsJSON(w, http.StatusOK, resp)
}
