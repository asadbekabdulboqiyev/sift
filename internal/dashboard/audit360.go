package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/audit360"
	"github.com/asadbekabdulboqiyev/sift/internal/authz"
)

const audit360MaxBody = 16 << 10

func (s *Server) ensureAudit360Manager() *audit360.Manager {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.audit360 == nil {
		// Seal with the persistent 360° identity, not a throwaway key: a report
		// a customer downloads must be attributable to this install, which is
		// what lets `sift audit360 verify --key <hex>` mean something.
		s.audit360 = audit360.NewManagerWithSignerKey(audit360SigningKeyPath())
	}
	return s.audit360
}

// audit360SigningKeyPath is the same home the certificate key lives in, so one
// backup covers every identity the install issues with.
func audit360SigningKeyPath() string {
	return filepath.Join(authz.ConfigHome(), "audit360-key.pem")
}

func (s *Server) demoStoreTargetURL() string {
	s.mu.RLock()
	st := s.store
	s.mu.RUnlock()
	if st == nil {
		return "http://127.0.0.1:8090"
	}
	return st.URL()
}

// audit360Gate runs the authorization decision the CLI runs before it touches a
// target. The 360° audit is an OpScan: it is not an exploit run, but it does
// send traffic, so the class-based boundary (metadata closed, private ranges
// need a rule) applies to the browser exactly as it does to a shell.
func audit360Gate(target string) (owaspGateOutcome, error) {
	return owaspGate(authz.OpScan, target, "")
}

// audit360Audit appends the decision to the dashboard's audit log — the same
// hash-chained file the CLI writes.
func audit360Audit(e authz.Entry) error {
	return owaspAudit(e)
}

func (s *Server) handleAudit360Start(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin requests are not allowed", http.StatusForbidden)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, audit360MaxBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req audit360.StartRequest
	if err := dec.Decode(&req); err != nil {
		writeAudit360JSON(w, http.StatusBadRequest, audit360.StartResponse{OK: false, Error: "invalid JSON body: " + err.Error()})
		return
	}

	demoURL := s.demoStoreTargetURL()
	adminBypass := s.authMiddleware == nil
	if s.auth != nil {
		principal, roles, _ := PrincipalAndRolesFromContext(r.Context())
		adminBypass = s.auth.rbacAllowed(principal, roles, "admin:access")
	}
	target, maxDur, mode, err := audit360.ValidateStartRequest(req, demoURL, adminBypass)
	if err != nil {
		msg := err.Error()
		code := http.StatusForbidden
		switch {
		case strings.Contains(msg, "mode must be"):
			code = http.StatusBadRequest
		case strings.Contains(msg, "target_url") && (strings.Contains(msg, "required") || strings.Contains(msg, "valid") || strings.Contains(msg, "credentials")):
			code = http.StatusBadRequest
		case strings.Contains(msg, "admin mode is not permitted") || strings.Contains(msg, "authorized confirmation"):
			code = http.StatusForbidden
		}
		writeAudit360JSON(w, code, audit360.StartResponse{OK: false, Error: msg})
		return
	}

	// Authorization: the 360° audit sends traffic at the target (a load test in
	// standard mode), so the browser path must not be a bypass of the check the
	// CLI runs. The gate is the class-based boundary: instance metadata is
	// always closed, and private, link-local, CGNAT, multicast and reserved
	// targets need an explicit rule. The decision is written to the same
	// hash-chained audit trail as CLI and OWASP scans, allowed or denied.
	decision, gerr := audit360Gate(target)
	if gerr != nil {
		writeAudit360JSON(w, http.StatusInternalServerError, audit360.StartResponse{OK: false, Error: "authorization policy error: " + gerr.Error()})
		return
	}
	auditErr := audit360Audit(authz.Entry{
		Action:  authz.OpScan.String(),
		Targets: []string{target},
		IPs:     decision.IPs,
		Class:   decision.Class,
		Allowed: decision.Allowed,
		Rule:    decision.Rule,
		Reason:  decision.Reason,
		Argv:    []string{"Sift dashboard", "POST /api/audit-360"},
	})
	if !decision.Allowed {
		// Deny is the safe action, so a broken audit trail must not turn a
		// refusal into a run — but say so, because the trail is now incomplete.
		reason := decision.Reason
		if auditErr != nil {
			reason += " (audit log unavailable: " + auditErr.Error() + ")"
		}
		writeAudit360JSON(w, http.StatusForbidden, audit360.StartResponse{OK: false, Error: reason})
		return
	}
	if auditErr != nil {
		// Fail closed: an allowed run that cannot be recorded is not an
		// authorized run.
		writeAudit360JSON(w, http.StatusInternalServerError,
			audit360.StartResponse{OK: false, Error: "cannot record the authorization decision: " + auditErr.Error()})
		return
	}

	mgr := s.ensureAudit360Manager()
	// Re-apply the gate decision at dial time: the socket may resolve the target
	// to a different class than the gate did, so audit360's scan, engine and
	// OWASP dials must carry the same class boundary the gate approved.
	jobID, err := mgr.StartWithControl(context.Background(), target, maxDur, demoURL, mode, authz.DialControl(decision.ClassValue))
	if err != nil {
		writeAudit360JSON(w, http.StatusInternalServerError, audit360.StartResponse{OK: false, Error: err.Error()})
		return
	}
	writeAudit360JSON(w, http.StatusAccepted, audit360.StartResponse{
		OK:        true,
		JobID:     jobID,
		StatusURL: "/api/audit-360/status?job_id=" + jobID,
		StreamURL: "/api/audit-360/stream?job_id=" + jobID,
	})
}

func (s *Server) handleAudit360Status(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	jobID := strings.TrimSpace(r.URL.Query().Get("job_id"))
	if jobID == "" {
		writeAudit360JSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "job_id is required"})
		return
	}
	mgr := s.ensureAudit360Manager()
	st, ok := mgr.Get(jobID)
	if !ok {
		writeAudit360JSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "job not found"})
		return
	}
	writeAudit360JSON(w, http.StatusOK, st)
}

func (s *Server) handleAudit360Stream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	jobID := strings.TrimSpace(r.URL.Query().Get("job_id"))
	if jobID == "" {
		http.Error(w, "job_id is required", http.StatusBadRequest)
		return
	}
	mgr := s.ensureAudit360Manager()
	ch, cancelSub, ok := mgr.Subscribe(jobID)
	if !ok {
		http.Error(w, "job not found", http.StatusNotFound)
		return
	}
	defer cancelSub()

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	// Initial comment to establish stream promptly.
	_, _ = fmt.Fprintf(w, ": ok\n\n")
	flusher.Flush()

	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			b, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			_, _ = fmt.Fprintf(w, "event: %s\n", ev.Type)
			_, _ = fmt.Fprintf(w, "data: %s\n\n", b)
			flusher.Flush()
			if ev.Type == "completed" || ev.Type == "failed" {
				return
			}
		case <-keepalive.C:
			_, _ = fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

func writeAudit360JSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) handleAudit360Download(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin requests are not allowed", http.StatusForbidden)
		return
	}
	jobID := strings.TrimSpace(r.URL.Query().Get("job_id"))
	if jobID == "" {
		writeAudit360JSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "job_id is required"})
		return
	}
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "json"
	}
	mgr := s.ensureAudit360Manager()
	st, ok := mgr.Get(jobID)
	if !ok {
		writeAudit360JSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "job not found"})
		return
	}
	if st.Report == nil {
		writeAudit360JSON(w, http.StatusConflict, map[string]any{"ok": false, "error": "report is not available yet (job state: " + st.State + ")"})
		return
	}
	report := st.Report
	certID := strings.TrimSpace(report.CertificateID)
	if certID == "" {
		certID = "report"
	}
	safeID := sanitizeAudit360DownloadID(certID)
	base := "sift-audit360-signed-" + safeID

	switch format {
	case "json", "signed-json":
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.json"`, base))
		payload := map[string]any{"job_id": st.JobID, "state": st.State, "report": report}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(payload)
		return
	case "html":
		doc := audit360.RenderHTML(report)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// The report is offered as a download, so keep it in a sandbox with no
		// scripts, forms or downloads even if a browser opens it inline.
		w.Header().Set("Content-Security-Policy", "sandbox")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.html"`, base))
		// #nosec G705 -- RenderHTML escapes every report-derived value with
		// html.EscapeString (internal/audit360/document.go); styles and class
		// names are fixed literals. The sandbox header above is a second layer.
		_, _ = w.Write([]byte(doc))
		return
	case "pdf":
		b, err := audit360.RenderPDF(report)
		if err != nil {
			writeAudit360JSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "failed to render pdf: " + err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.pdf"`, base))
		// #nosec G705 -- the taint rule flags any write of a rendered artifact,
		// but RenderPDF builds bytes with a pure-Go PDF writer (no browser, no
		// HTML, no JavaScript), so this is a binary download, not a web response.
		_, _ = w.Write(b)
		return
	default:
		writeAudit360JSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "unsupported format (use json, html, or pdf)"})
		return
	}
}

func sanitizeAudit360DownloadID(s string) string {
	if s == "" {
		return "report"
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if out == "" {
		return "report"
	}
	if len(out) > 80 {
		out = out[:80]
	}
	return out
}
