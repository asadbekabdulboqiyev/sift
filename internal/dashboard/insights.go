package dashboard

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/bounty"
	"github.com/asadbekabdulboqiyev/sift/internal/hostxray"
	"github.com/asadbekabdulboqiyev/sift/internal/report"
	"github.com/asadbekabdulboqiyev/sift/internal/twin"
)

const (
	insightsMaxBody = 4 << 20
	triageMaxBody   = 2 << 20
)

type twinFitRequest struct {
	Report      report.Report `json:"report"`
	TargetP99MS float64       `json:"target_p99_ms,omitempty"`
}

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

type xrayCorrelateRequest struct {
	Samples []hostxray.Sample `json:"samples"`
	Signals []hostxray.Signal `json:"signals"`
	Window  string            `json:"window,omitempty"`
}

type bountyValidateRequest struct {
	Manifest bounty.Manifest `json:"manifest"`
}

type bountyStatusRequest struct {
	Events []bounty.Event `json:"events"`
}

func insightsJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	writeJSON(w, v)
}

func (s *Server) handleInsightsXRayCapabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	caps := hostxray.DetectCapabilities()
	insightsJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"capabilities": caps,
		"note":         "Informational only. This server never loads eBPF programs and never escalates privileges.",
	})
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
	defer r.Body.Close()

	var req twinFitRequest
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid JSON: " + err.Error()})
		return
	}
	if req.Report.TotalRequests == 0 {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "report has no completed requests; cannot fit a model from zero samples"})
		return
	}
	if req.Report.Duration <= 0 {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "report duration must be positive"})
		return
	}
	if err := req.Report.ValidateTimestamps(); err != nil {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "report timing is inconsistent: " + err.Error()})
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
	defer r.Body.Close()

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

func (s *Server) handleInsightsXRayCorrelate(w http.ResponseWriter, r *http.Request) {
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
	defer r.Body.Close()

	var req xrayCorrelateRequest
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid JSON: " + err.Error()})
		return
	}
	if len(req.Samples) == 0 || len(req.Signals) == 0 {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "samples and signals are required"})
		return
	}
	const maxCorrelateSamples = 50000
	const maxCorrelateSignals = 50000
	if len(req.Samples) > maxCorrelateSamples || len(req.Signals) > maxCorrelateSignals {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "too many samples or signals"})
		return
	}

	opts := hostxray.CorrelateOptions{}
	if strings.TrimSpace(req.Window) != "" {
		d, err := time.ParseDuration(req.Window)
		if err != nil {
			insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid window: " + err.Error()})
			return
		}
		opts.Window = d
	}
	indicators := hostxray.Correlate(req.Samples, req.Signals, opts)
	insightsJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"indicators": indicators,
		"note":       "Indicators highlight time-correlated host and workload evidence to guide investigation.",
	})
}

func (s *Server) handleInsightsBountyValidate(w http.ResponseWriter, r *http.Request) {
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
	defer r.Body.Close()

	var req bountyValidateRequest
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid JSON: " + err.Error()})
		return
	}
	m := req.Manifest
	if strings.TrimSpace(m.SchemaVersion) == "" {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "manifest is required"})
		return
	}

	checks := make([]bounty.Check, 0, 4)
	if err := m.Validate(); err != nil {
		checks = append(checks, bounty.Check{Name: "manifest", Status: bounty.StatusFail, Detail: err.Error()})
		insightsJSON(w, http.StatusOK, map[string]any{"ok": true, "verdict": bounty.VerdictFailed, "checks": checks, "reasons": []string{err.Error()}})
		return
	}
	checks = append(checks, bounty.Check{Name: "manifest", Status: bounty.StatusPass, Detail: "structure and fields are valid"})

	want, err := m.ComputeDigest()
	if err != nil {
		checks = append(checks, bounty.Check{Name: "package_digest", Status: bounty.StatusFail, Detail: err.Error()})
		insightsJSON(w, http.StatusOK, map[string]any{"ok": true, "verdict": bounty.VerdictFailed, "checks": checks, "reasons": []string{err.Error()}})
		return
	}
	if !strings.EqualFold(strings.TrimSpace(m.PackageDigest), want) {
		checks = append(checks, bounty.Check{Name: "package_digest", Status: bounty.StatusFail, Detail: "manifest digest mismatch"})
		insightsJSON(w, http.StatusOK, map[string]any{"ok": true, "verdict": bounty.VerdictFailed, "checks": checks, "reasons": []string{"package digest does not match canonical manifest"}})
		return
	}
	checks = append(checks, bounty.Check{Name: "package_digest", Status: bounty.StatusPass, Detail: "canonical digest matches"})

	wantID := want
	const bountyIDPrefix = "bty_"
	const bountyIDWidth = 26
	if len(wantID) >= bountyIDWidth {
		wantID = bountyIDPrefix + wantID[:bountyIDWidth]
	} else {
		wantID = bountyIDPrefix + wantID
	}
	pid := strings.TrimSpace(m.PackageID)
	if pid != "" && !strings.EqualFold(pid, wantID) && !strings.EqualFold(pid, want) && !strings.EqualFold(pid, "bty_"+want) {
		checks = append(checks, bounty.Check{Name: "package_id", Status: bounty.StatusFail, Detail: "package id does not match digest"})
		insightsJSON(w, http.StatusOK, map[string]any{"ok": true, "verdict": bounty.VerdictFailed, "checks": checks, "reasons": []string{"package id mismatch"}})
		return
	}
	checks = append(checks, bounty.Check{Name: "package_id", Status: bounty.StatusPass, Detail: "package id is consistent"})

	for _, a := range m.Artifacts {
		if len(strings.TrimSpace(a.SHA256)) != 64 {
			checks = append(checks, bounty.Check{Name: "artifact:" + string(a.Role), Status: bounty.StatusFail, Detail: "invalid sha256"})
			insightsJSON(w, http.StatusOK, map[string]any{"ok": true, "verdict": bounty.VerdictFailed, "checks": checks, "reasons": []string{"artifact hash format invalid"}})
			return
		}
	}

	checks = append(checks, bounty.Check{Name: "artifacts", Status: bounty.StatusSkip, Detail: "artifact bytes not provided in manifest-only validation; use full verify (upload) for re-hash and attestation replay"})

	insightsJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"verdict":        bounty.VerdictUnverified,
		"checks":         checks,
		"package_digest": m.PackageDigest,
		"package_id":     m.PackageID,
		"notes": []string{
			"Manifest structure and canonical digest are valid.",
			"Full artifact re-hash and attestation replay are available via POST /api/insights/bounty/verify-upload (or 'sift bounty verify').",
			"Evidence integrity supports triage; human review determines finding validity and outcomes.",
		},
	})
}

func (s *Server) handleInsightsBountyStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin requests are not allowed", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, triageMaxBody)
	defer r.Body.Close()

	var req bountyStatusRequest
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid JSON: " + err.Error()})
		return
	}
	events := req.Events
	if len(events) == 0 {
		insightsJSON(w, http.StatusOK, map[string]any{"ok": true, "state": "(none)", "events": 0})
		return
	}
	current, err := bounty.CurrentState(events)
	if err != nil {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error(), "events": len(events)})
		return
	}
	last := events[len(events)-1]
	insightsJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"state":  string(current),
		"events": len(events),
		"last":   last,
		"note":   "Triage states provide a complete auditable workflow and outcomes log.",
	})
}

func (s *Server) handleInsightsBountyVerifyUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin requests are not allowed", http.StatusForbidden)
		return
	}
	// Allow manifest + artifact files + optional bundle/samples. Limits align with bounty package constraints.
	const uploadMaxBody = bounty.MaxArtifactBytes*int64(bounty.MaxArtifacts) + 8<<20
	r.Body = http.MaxBytesReader(w, r.Body, uploadMaxBody)
	if err := r.ParseMultipartForm(32 << 20); err != nil { // #nosec G120 -- request body is bounded by MaxBytesReader above; in-memory form cap is intentional.
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid multipart form: " + err.Error()})
		return
	}
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()

	manifestJSON := strings.TrimSpace(r.FormValue("manifest"))
	if manifestJSON == "" {
		// Also accept uploaded manifest file named "bounty-package.json" or field "manifest_file".
		manifestJSON = readUploadedText(r, "manifest_file")
		if manifestJSON == "" {
			manifestJSON = readUploadedFileByName(r, "bounty-package.json")
		}
	}
	if manifestJSON == "" {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "manifest JSON is required (field 'manifest' or uploaded manifest file)"})
		return
	}
	var m bounty.Manifest
	if err := json.Unmarshal([]byte(manifestJSON), &m); err != nil {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid manifest JSON: " + err.Error()})
		return
	}

	tmpDir, err := os.MkdirTemp("", "sift-bounty-verify-*")
	if err != nil {
		insightsJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "failed to create temp directory"})
		return
	}
	defer os.RemoveAll(tmpDir)

	// Persist all uploaded files into temp dir using sanitized relative paths.
	saved := map[string]string{} // rel path as saved -> absolute path
	for _, fhs := range r.MultipartForm.File {
		for _, fh := range fhs {
			if fh == nil {
				continue
			}
			rel := sanitizeUploadPath(fh.Filename)
			if rel == "" {
				continue
			}
			dst := filepath.Join(tmpDir, filepath.FromSlash(rel))
			if err := saveMultipartFile(fh, tmpDir, dst); err != nil {
				insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "save " + rel + ": " + err.Error()})
				return
			}
			saved[rel] = dst
		}
	}

	// Write manifest into temp dir as bounty-package.json for consistency.
	manifestPath := filepath.Join(tmpDir, "bounty-package.json")
	mb, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "failed to encode manifest: " + err.Error()})
		return
	}
	tmpManifest, err := os.CreateTemp(tmpDir, "bounty-package.*.tmp")
	if err != nil {
		insightsJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "failed to create manifest temp: " + err.Error()})
		return
	}
	tmpManifestName := tmpManifest.Name()
	if err := tmpManifest.Chmod(0o600); err != nil {
		_ = tmpManifest.Close()
		_ = os.Remove(tmpManifestName)
		insightsJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "failed to prepare manifest: " + err.Error()})
		return
	}
	if _, err := tmpManifest.Write(mb); err != nil {
		_ = tmpManifest.Close()
		_ = os.Remove(tmpManifestName)
		insightsJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "failed to write manifest: " + err.Error()})
		return
	}
	if err := tmpManifest.Sync(); err != nil {
		_ = tmpManifest.Close()
		_ = os.Remove(tmpManifestName)
		insightsJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "failed to sync manifest: " + err.Error()})
		return
	}
	if err := tmpManifest.Close(); err != nil {
		_ = os.Remove(tmpManifestName)
		insightsJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "failed to close manifest: " + err.Error()})
		return
	}
	if err := os.Rename(tmpManifestName, manifestPath); err != nil {
		_ = os.Remove(tmpManifestName)
		insightsJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "failed to finalize manifest: " + err.Error()})
		return
	}

	// Ensure uploaded files are available at manifest-declared artifact paths.
	// Browsers often provide basenames only; copy matched uploads to expected paths.
	// Matching is deterministic: prefer exact relative-path key, then lexicographically
	// smallest uploaded path whose basename matches (fail-closed on ambiguity is not
	// required because verification re-hashes against the manifest).
	for _, art := range m.Artifacts {
		want := filepath.ToSlash(art.Path)
		wantAbs := filepath.Join(tmpDir, filepath.FromSlash(want))
		if _, err := os.Stat(wantAbs); err == nil {
			saved[want] = wantAbs
			continue
		}
		var src string
		if pth, ok := saved[want]; ok {
			src = pth
		} else {
			candidates := make([]string, 0, 1)
			wantBase := filepath.Base(want)
			for rel := range saved {
				if rel == wantBase || filepath.Base(rel) == wantBase {
					candidates = append(candidates, rel)
				}
			}
			sort.Strings(candidates)
			if len(candidates) > 0 {
				src = saved[candidates[0]]
			}
		}
		if src == "" {
			continue
		}
		if err := copyFileTo(src, tmpDir, wantAbs); err == nil {
			saved[want] = wantAbs
		}
	}

	pubKey := strings.TrimSpace(r.FormValue("key"))
	if pubKey == "" {
		pubKey = strings.TrimSpace(r.FormValue("public_key"))
	}
	opts := bounty.VerifyOptions{
		Target:       strings.TrimSpace(r.FormValue("target")),
		PublicKeyHex: pubKey,
		SkipCICheck:  strings.EqualFold(strings.TrimSpace(r.FormValue("skip_ci_check")), "true") || r.FormValue("skip_ci_check") == "1",
	}
	if v := strings.TrimSpace(r.FormValue("max_samples_total")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			opts.MaxSamplesTotal = n
		}
	}

	// Auto-detect bundle/samples paths from manifest artifact roles.
	for _, art := range m.Artifacts {
		pth, ok := saved[filepath.ToSlash(art.Path)]
		if !ok {
			continue
		}
		switch art.Role {
		case bounty.ArtifactBundle:
			if opts.BundlePath == "" {
				opts.BundlePath = pth
			}
		case bounty.ArtifactSamples:
			if opts.SamplesPath == "" {
				opts.SamplesPath = pth
			}
		}
	}
	// Allow explicit upload field names "bundle"/"samples".
	if opts.BundlePath == "" {
		if pth, ok := saved["bundle"]; ok {
			opts.BundlePath = pth
		}
		if pth, ok := saved["bundle.json"]; ok && opts.BundlePath == "" {
			opts.BundlePath = pth
		}
	}
	if opts.SamplesPath == "" {
		if pth, ok := saved["samples"]; ok {
			opts.SamplesPath = pth
		}
		if pth, ok := saved["samples.jsonl"]; ok && opts.SamplesPath == "" {
			opts.SamplesPath = pth
		}
	}

	report, err := bounty.VerifyPackage(m, tmpDir, opts)
	if err != nil {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	status := http.StatusOK
	if report.Verdict == bounty.VerdictFailed {
		status = http.StatusConflict
	}
	insightsJSON(w, status, map[string]any{
		"ok":                 report.Verdict != bounty.VerdictFailed,
		"report":             report,
		"verdict":            report.Verdict,
		"uploaded_artifacts": len(saved),
		"note":               "Full package verification executed on uploaded artifacts. Evidence integrity does not by itself establish finding validity; human triage determines outcomes.",
	})
}

func copyFileTo(src, baseDir, dst string) error {
	base := filepath.Clean(baseDir)
	cleanDst := filepath.Clean(dst)
	rel, err := filepath.Rel(base, cleanDst)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("path escapes temp directory")
	}
	if err := os.MkdirAll(filepath.Dir(cleanDst), 0o700); err != nil {
		return err
	}
	in, err := os.Open(src) // #nosec G304 -- src is an internal path previously saved within the request-scoped temp directory.
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(cleanDst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	n, err := io.Copy(out, io.LimitReader(in, bounty.MaxArtifactBytes+1))
	if err != nil {
		return err
	}
	if n > bounty.MaxArtifactBytes {
		return fmt.Errorf("file exceeds %d byte limit", bounty.MaxArtifactBytes)
	}
	return nil
}

func readUploadedText(r *http.Request, field string) string {
	fhs := r.MultipartForm.File[field]
	if len(fhs) == 0 {
		return ""
	}
	f, err := fhs[0].Open()
	if err != nil {
		return ""
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 4<<20))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func readUploadedFileByName(r *http.Request, name string) string {
	for _, fhs := range r.MultipartForm.File {
		for _, fh := range fhs {
			if fh == nil || filepath.Base(fh.Filename) != name {
				continue
			}
			f, err := fh.Open()
			if err != nil {
				return ""
			}
			b, err := io.ReadAll(io.LimitReader(f, 4<<20))
			_ = f.Close()
			if err != nil {
				return ""
			}
			return strings.TrimSpace(string(b))
		}
	}
	return ""
}

func sanitizeUploadPath(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	name = strings.ReplaceAll(name, "\\", "/")
	name = filepath.ToSlash(filepath.Clean(name))
	name = strings.TrimPrefix(name, "/")
	if name == "." || name == ".." || strings.HasPrefix(name, "../") || strings.Contains(name, "/../") {
		return filepath.Base(name)
	}
	// keep relative subpaths; verifier will reject unsafe ones too
	return name
}

func saveMultipartFile(fh *multipart.FileHeader, baseDir, dst string) error {
	base := filepath.Clean(baseDir)
	cleanDst := filepath.Clean(dst)
	rel, err := filepath.Rel(base, cleanDst)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("path escapes temp directory")
	}
	if err := os.MkdirAll(filepath.Dir(cleanDst), 0o700); err != nil {
		return err
	}
	src, err := fh.Open()
	if err != nil {
		return err
	}
	defer src.Close()
	out, err := os.OpenFile(cleanDst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	n, err := io.Copy(out, io.LimitReader(src, bounty.MaxArtifactBytes+1))
	if err != nil {
		return err
	}
	if n > bounty.MaxArtifactBytes {
		return fmt.Errorf("file exceeds %d byte limit", bounty.MaxArtifactBytes)
	}
	return nil
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

type resourceAssessmentRequest struct {
	CPU                *float64               `json:"cpu,omitempty"`
	Memory             *float64               `json:"memory,omitempty"`
	Network            *float64               `json:"network,omitempty"`
	Connections        *float64               `json:"connections,omitempty"`
	ServerResponseTime *float64               `json:"server_response_time,omitempty"`
	MemoryGrowth       *float64               `json:"memory_growth,omitempty"`
	Samples            []hostxray.Sample      `json:"samples,omitempty"`
	Capabilities       *hostxray.Capabilities `json:"capabilities,omitempty"`
	Source             string                 `json:"source,omitempty"`
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
	defer r.Body.Close()
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
	defer r.Body.Close()
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
	defer r.Body.Close()
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

func resourceEvidenceToTwin(derived hostxray.DerivedResourceEvidence, source string) twin.ResourceAvailability {
	if strings.TrimSpace(source) == "" {
		source = derived.Source
	}
	ra := twin.ResourceAvailability{
		Values:              map[string]float64{},
		MetricsDetail:       make(map[string]twin.ResourceMetricEvidence, len(derived.Metrics)),
		Notes:               append([]string(nil), derived.Notes...),
		Source:              source,
		SchemaVersion:       derived.SchemaVersion,
		SampleCount:         derived.SampleCount,
		ObservedAt:          derived.ObservedAt,
		ObservedWindowStart: derived.ObservedWindowStart,
		ObservedWindowEnd:   derived.ObservedWindowEnd,
	}
	names := make([]string, 0, len(derived.Metrics))
	for n := range derived.Metrics {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		m := derived.Metrics[n]
		detail := twin.ResourceMetricEvidence{
			Name:                   m.Name,
			Status:                 string(m.Status),
			Value:                  m.Value,
			Unit:                   m.Unit,
			Source:                 m.Source,
			Reason:                 m.Reason,
			Notes:                  append([]string(nil), m.Notes...),
			ObservedAt:             m.ObservedAt,
			ObservedWindowStart:    m.ObservedWindowStart,
			ObservedWindowEnd:      m.ObservedWindowEnd,
			ObservationSampleCount: m.ObservationSampleCount,
		}
		// Preserve metric identity/name as provided by hostxray evidence.
		if strings.TrimSpace(detail.Name) == "" {
			detail.Name = n
		}
		ra.MetricsDetail[n] = detail
		if m.Status == hostxray.ResourceStatusAvailable && m.Value != nil && !math.IsNaN(*m.Value) && !math.IsInf(*m.Value, 0) {
			ra.Available = true
			ra.Metrics = append(ra.Metrics, n)
			ra.Values[n] = *m.Value
		} else {
			ra.Missing = append(ra.Missing, n)
			// Never report contradictory evidence: non-finite/missing values are not available.
			if detail.Status == "available" {
				detail.Status = "insufficient_data"
				if strings.TrimSpace(detail.Reason) == "" {
					detail.Reason = "derived value missing or non-finite"
				}
				detail.Value = nil
			}
			ra.MetricsDetail[n] = detail
		}
	}
	sort.Strings(ra.Metrics)
	sort.Strings(ra.Missing)
	if strings.TrimSpace(ra.Source) == "" {
		ra.Source = "hostxray-derived"
	}
	if strings.TrimSpace(ra.SchemaVersion) == "" {
		ra.SchemaVersion = "sift.resource-evidence/v1"
	}
	return ra
}

func (s *Server) handleInsightsResourceAssessment(w http.ResponseWriter, r *http.Request) {
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
	defer r.Body.Close()
	var req resourceAssessmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid JSON: " + err.Error()})
		return
	}
	source := strings.TrimSpace(req.Source)
	if len(req.Samples) > 0 {
		const maxResourceSamples = 50000
		if len(req.Samples) > maxResourceSamples {
			insightsJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": fmt.Sprintf("too many samples (max %d)", maxResourceSamples)})
			return
		}
		caps := hostxray.Capabilities{}
		if req.Capabilities != nil {
			caps = *req.Capabilities
		}
		derived := hostxray.DeriveResourceEvidence(req.Samples, caps)
		if source == "" {
			source = "hostxray-derived"
		}
		ra := resourceEvidenceToTwin(derived, source)
		// Allow explicit manual overrides/supplements (measured evidence) to take precedence.
		if req.CPU != nil || req.Memory != nil || req.Network != nil || req.Connections != nil || req.ServerResponseTime != nil || req.MemoryGrowth != nil {
			manual := twin.AssessResourceMonitoringExtended(req.CPU, req.Memory, req.Network, req.Connections, req.ServerResponseTime, req.MemoryGrowth)
			for k, v := range manual.Values {
				ra.Values[k] = v
				if !containsStr(ra.Metrics, k) {
					ra.Metrics = append(ra.Metrics, k)
				}
				ra.Missing = removeStr(ra.Missing, k)
				ra.Available = true
				vv := v
				d := ra.MetricsDetail[k]
				d.Name = k
				d.Status = "available"
				d.Value = &vv
				d.Source = "manual/provided"
				d.Reason = ""
				if d.Unit == "" {
					d.Unit = guessResourceUnit(k)
				}
				// Manual override is explicit evidence but not observed from hostxray samples.
				d.ObservedAt = ""
				d.ObservedWindowStart = ""
				d.ObservedWindowEnd = ""
				d.ObservationSampleCount = 0
				ra.MetricsDetail[k] = d
			}
			sort.Strings(ra.Metrics)
			sort.Strings(ra.Missing)
			ra.Notes = append([]string{"Manual/measured overrides applied for provided metrics (explicit evidence)."}, ra.Notes...)
			ra.Source = "mixed:hostxray+manual"
		}
		insightsJSON(w, http.StatusOK, map[string]any{
			"ok": true, "resource_monitoring": ra,
			"derived_from_samples": true,
			"sample_count":         len(req.Samples),
			"note":                 "Resource metrics are derived from provided hostxray samples and/or explicit evidence; unavailable/insufficient metrics are labeled and never fabricated.",
		})
		return
	}
	if source == "" {
		source = "manual/provided"
	}
	ra := twin.AssessResourceMonitoringExtended(req.CPU, req.Memory, req.Network, req.Connections, req.ServerResponseTime, req.MemoryGrowth)
	if ra.Source == "" {
		ra.Source = source
	}
	// Ensure standardized detail/metadata consistency (additive; no fabricated timestamps).
	if ra.MetricsDetail == nil {
		ra.MetricsDetail = make(map[string]twin.ResourceMetricEvidence)
	}
	for _, n := range []string{"cpu", "memory", "network", "connections", "server_response_time", "memory_growth"} {
		if d, ok := ra.MetricsDetail[n]; ok {
			if strings.TrimSpace(d.Unit) == "" {
				d.Unit = guessResourceUnit(n)
			}
			if strings.TrimSpace(d.Source) == "" {
				d.Source = source
			}
			if strings.TrimSpace(d.Status) == "" {
				d.Status = "unavailable"
				if strings.TrimSpace(d.Reason) == "" {
					d.Reason = "not provided"
				}
			}
			ra.MetricsDetail[n] = d
			continue
		}
		v, ok := ra.Values[n]
		d := twin.ResourceMetricEvidence{Name: n, Unit: guessResourceUnit(n), Source: source}
		if ok {
			vv := v
			d.Status = "available"
			d.Value = &vv
		} else {
			d.Status = "unavailable"
			d.Reason = "not provided"
		}
		ra.MetricsDetail[n] = d
	}
	if strings.TrimSpace(ra.SchemaVersion) == "" {
		ra.SchemaVersion = "sift.resource-evidence/v1"
	}
	insightsJSON(w, http.StatusOK, map[string]any{
		"ok": true, "resource_monitoring": ra,
		"derived_from_samples": false,
		"note":                 "Resource metrics are reported only when provided; unavailable metrics are explicitly labeled and never fabricated.",
	})
}

func containsStr(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
func removeStr(ss []string, s string) []string {
	out := ss[:0]
	for _, x := range ss {
		if x != s {
			out = append(out, x)
		}
	}
	return out
}
func guessResourceUnit(name string) string {
	switch name {
	case "cpu", "memory", "network", "memory_growth":
		return "percent"
	case "connections":
		return "count"
	case "server_response_time":
		return "ms"
	default:
		return ""
	}
}

// Keep references for stable builds if refactoring trims imports.
var _ = fmt.Sprintf
var _ = errors.New
var _ = sort.Strings
