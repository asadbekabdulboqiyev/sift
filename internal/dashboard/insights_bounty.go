package dashboard

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/asadbekabdulboqiyev/sift/internal/bounty"
)

type bountyValidateRequest struct {
	Manifest bounty.Manifest `json:"manifest"`
}

type bountyStatusRequest struct {
	Events []bounty.Event `json:"events"`
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
	defer func() { _ = r.Body.Close() }()

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
	defer func() { _ = r.Body.Close() }()

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

// writeBountyVerifyManifest durably writes the canonical manifest into the
// request-scoped temp directory. It returns (status, errorText); an empty
// errorText means success. Status codes and messages are unchanged.
func writeBountyVerifyManifest(tmpDir string, m bounty.Manifest) (int, string) {
	manifestPath := filepath.Join(tmpDir, "bounty-package.json")
	mb, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return http.StatusBadRequest, "failed to encode manifest: " + err.Error()
	}
	tmpManifest, err := os.CreateTemp(tmpDir, "bounty-package.*.tmp")
	if err != nil {
		return http.StatusInternalServerError, "failed to create manifest temp: " + err.Error()
	}
	tmpManifestName := tmpManifest.Name()
	if err := tmpManifest.Chmod(0o600); err != nil {
		_ = tmpManifest.Close()
		_ = os.Remove(tmpManifestName)
		return http.StatusInternalServerError, "failed to prepare manifest: " + err.Error()
	}
	if _, err := tmpManifest.Write(mb); err != nil {
		_ = tmpManifest.Close()
		_ = os.Remove(tmpManifestName)
		return http.StatusInternalServerError, "failed to write manifest: " + err.Error()
	}
	if err := tmpManifest.Sync(); err != nil {
		_ = tmpManifest.Close()
		_ = os.Remove(tmpManifestName)
		return http.StatusInternalServerError, "failed to sync manifest: " + err.Error()
	}
	if err := tmpManifest.Close(); err != nil {
		_ = os.Remove(tmpManifestName)
		return http.StatusInternalServerError, "failed to close manifest: " + err.Error()
	}
	if err := os.Rename(tmpManifestName, manifestPath); err != nil {
		_ = os.Remove(tmpManifestName)
		return http.StatusInternalServerError, "failed to finalize manifest: " + err.Error()
	}
	return 0, ""
}

// ensureBountyArtifactPaths maps uploaded files onto the paths declared by the
// manifest. Untrusted traversal paths are skipped before any filesystem call.
func ensureBountyArtifactPaths(tmpDir string, arts []bounty.Artifact, saved map[string]string) {
	for _, art := range arts {
		want := filepath.ToSlash(art.Path)
		// The manifest is user-supplied, so art.Path is untrusted. Reject any
		// path that is not a plain relative path before it reaches the
		// filesystem: a traversal path used to be joined onto the temp dir and
		// os.Stat'ed, so uploaded_artifacts reported whether an arbitrary file
		// on the host exists. VerifyPackage rejects such paths anyway.
		if !bounty.ValidArtifactPath(want) {
			continue
		}
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
}

func bountyVerifyOptions(r *http.Request) bounty.VerifyOptions {
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
	return opts
}

func detectBundleAndSamples(arts []bounty.Artifact, saved map[string]string, opts *bounty.VerifyOptions) {
	// Auto-detect bundle/samples paths from manifest artifact roles.
	for _, art := range arts {
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
	defer func() { _ = os.RemoveAll(tmpDir) }()

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
	if status, msg := writeBountyVerifyManifest(tmpDir, m); msg != "" {
		insightsJSON(w, status, map[string]any{"ok": false, "error": msg})
		return
	}

	// Ensure uploaded files are available at manifest-declared artifact paths.
	// Browsers often provide basenames only; copy matched uploads to expected paths.
	ensureBountyArtifactPaths(tmpDir, m.Artifacts, saved)

	opts := bountyVerifyOptions(r)
	detectBundleAndSamples(m.Artifacts, saved, &opts)

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
