package dashboard

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/asadbekabdulboqiyev/sift/internal/attest"
)

// verifyResultMap renders an attest.VerifyResult for the JSON API. It is shared
// by the "verify the dashboard's own run" endpoint and the "verify a bundle the
// operator uploaded" endpoint so both report identical field names.
func verifyResultMap(res attest.VerifyResult) map[string]interface{} {
	out := map[string]interface{}{
		"valid":         res.Valid,
		"format":        res.Format,
		"samplesAbsent": res.SamplesAbsent,
		// The CLI prints "issuer:"; the dashboard used to drop the verdict
		// entirely. With no trust store the verifier still returns Valid=true,
		// so the unpinned status is the only honest signal that nobody checked
		// WHO signed the bundle. Keep it in every response, valid or not.
		"issuerTrust":   string(res.IssuerTrust),
		"issuerTrusted": res.IssuerTrust.Trusted(),
		"bundleDigest":  res.BundleDigest,
		"workers":       len(res.Workers),
		"summary": map[string]interface{}{
			"workers":        res.Summary.Workers,
			"workersOK":      res.Summary.WorkersOK,
			"workersFailed":  res.Summary.WorkersFailed,
			"samplesTotal":   res.Summary.SamplesTotal,
			"checksRun":      res.Summary.ChecksRun,
			"checksFailed":   res.Summary.ChecksFailed,
			"proofsVerified": res.Summary.ProofsVerified,
		},
	}
	if !res.Valid {
		reasons := make([]string, 0, len(res.Checks)+len(res.Workers))
		for _, c := range res.Checks {
			if !c.OK {
				reasons = append(reasons, "bundle/"+c.Name+": "+c.Detail)
			}
		}
		for _, w := range res.Workers {
			for _, e := range w.Errors {
				reasons = append(reasons, e.Error())
			}
		}
		if len(reasons) > 0 {
			out["reason"] = strings.Join(reasons, "; ")
		} else {
			out["reason"] = "verification failed"
		}
	}
	return out
}

func verifyAttestation(bundlePath, samplesPath string) map[string]interface{} {
	bundle, err := attest.LoadBundle(bundlePath)
	if err != nil {
		return map[string]interface{}{
			"valid":      false,
			"reason":     fmt.Sprintf("load bundle failed: %v", err),
			"bundlePath": bundlePath,
		}
	}

	var samples map[string][]attest.Record
	var loadStats attest.SampleLoadStats
	if samplesPath != "" {
		samples, loadStats, err = attest.LoadSamples(samplesPath, attest.DefaultSampleLoadOptions())
		if err != nil {
			return map[string]interface{}{
				"valid":        false,
				"reason":       fmt.Sprintf("load samples failed: %v", err),
				"bundlePath":   bundlePath,
				"samplesPath":  samplesPath,
				"samplesStats": map[string]interface{}{"lines": loadStats.Lines},
			}
		}
	}

	// Deliberately self-consistency-only: this endpoint has no trust store, so
	// RequireTrustAnchor stays false. verifyResultMap always reports the issuer
	// verdict (issuerTrust/issuerTrusted); the UI MUST render issuerTrusted=false
	// as "VALID (UNPINNED)" and never as a plain successful verification (F-03).
	res := attest.VerifyWith(bundle, samples, attest.VerifyOptions{})
	out := verifyResultMap(res)
	if loadStats.Lines > 0 {
		out["samplesStats"] = map[string]interface{}{
			"lines":        loadStats.Lines,
			"records":      loadStats.Records,
			"blankLines":   loadStats.BlankLines,
			"nonCanonical": loadStats.NonCanonicalLines,
			"unsorted":     loadStats.UnsortedLines,
			"bytes":        loadStats.Bytes,
			"workers":      loadStats.Workers,
		}
	}
	return out
}

func (s *Server) handleAttestationGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	s.attestMu.RLock()
	info := s.attestInfo
	s.attestMu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(info)
}

func (s *Server) handleAttestationDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	typ := r.URL.Query().Get("type")
	s.attestMu.RLock()
	info := s.attestInfo
	s.attestMu.RUnlock()
	if !info.Exists {
		http.NotFound(w, r)
		return
	}
	var path string
	if typ == "bundle" {
		path = info.BundlePath
	} else if typ == "samples" {
		path = info.SamplesPath
	} else {
		http.Error(w, "type must be bundle|samples", http.StatusBadRequest)
		return
	}
	if path == "" {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, path)
}

func (s *Server) handleAttestationVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin requests are not allowed", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAPIRequestBody)
	// DisallowUnknownFields makes this contract fail-closed: a body that tries
	// to name a path ({"bundlePath": "..."}) is rejected with 400 instead of
	// being silently ignored. See AttestationVerifyRequest.
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req AttestationVerifyRequest
	if err := dec.Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.attestMu.RLock()
	info := s.attestInfo
	s.attestMu.RUnlock()
	if !info.Exists || info.BundlePath == "" {
		http.Error(w, "no attestation available to verify", http.StatusBadRequest)
		return
	}
	res := verifyAttestation(info.BundlePath, info.SamplesPath)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

// handleAttestationVerifyUpload verifies an attestation bundle the operator
// uploaded from the Certificate page.
//
// The body is the bundle JSON itself, never a path: the endpoint parses what it
// was given and runs the same verifier as the CLI. Without the sample sidecar it
// establishes the coordinator signature, the per-worker commit signatures and
// the internal cross-sums, and reports samplesAbsent — the honest scope of what
// a lone bundle can prove.
func (s *Server) handleAttestationVerifyUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin requests are not allowed", http.StatusForbidden)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxAPIRequestBody)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "request body too large or unreadable", http.StatusRequestEntityTooLarge)
		return
	}

	bundle, err := attest.ParseBundle(raw)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"valid":  false,
			"reason": fmt.Sprintf("not an attestation bundle: %v", err),
		})
		return
	}

	// Same policy as the stored-run endpoint above (F-03): no trust store here,
	// so the honest issuer verdict is returned and the UI must not present a
	// self-consistent-but-unpinned bundle as an identity-verified one.
	res := attest.Verify(bundle, nil)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(verifyResultMap(res))
}
