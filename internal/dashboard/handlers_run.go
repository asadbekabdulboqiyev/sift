package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/adminlock"
	"github.com/asadbekabdulboqiyev/sift/internal/authz"
	"github.com/asadbekabdulboqiyev/sift/internal/config"
)

func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.snapshot)
}

func (s *Server) handleRunAPI(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.runState)
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.history)
}

func (s *Server) handleStartRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	// Simple-request CSRF defense: a browser cross-origin POST carries an
	// Origin header that will not match r.Host; non-browser clients (curl,
	// CLI tooling) send no Origin and stay allowed.
	if !sameOrigin(r) {
		http.Error(w, "cross-origin requests are not allowed", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAPIRequestBody)
	var runCfg RunConfig
	if err := json.NewDecoder(r.Body).Decode(&runCfg); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Server-side validation (not just frontend): an empty/invalid target
	// must never silently start a run against a default URL.
	if strings.TrimSpace(runCfg.TargetURL) == "" {
		http.Error(w, "target_url is required", http.StatusBadRequest)
		return
	}
	if u, err := url.Parse(runCfg.TargetURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		http.Error(w, "target_url must be an http(s) URL", http.StatusBadRequest)
		return
	}
	if runCfg.Users < 0 || runCfg.DurationSeconds < 0 || runCfg.RateLimit < 0 {
		http.Error(w, "users, duration_seconds, and rate_limit must be non-negative", http.StatusBadRequest)
		return
	}
	if runCfg.Users > config.MaxUsers || runCfg.DurationSeconds > config.MaxDurationSeconds || runCfg.RateLimit > config.MaxRPS {
		http.Error(w, "users, duration_seconds, or rate_limit exceeds allowed maximum", http.StatusBadRequest)
		return
	}
	// The browser is not a back door around the CLI's authorization layer. Every
	// other scan endpoint on this server goes through owaspGate; this one used to
	// hand the target to the engine unchecked, which let a dashboard client make
	// the host send arbitrary-method/header/body requests to the cloud instance
	// metadata service (169.254.169.254, metadata.google.internal) and read back
	// credentials. Metadata and link-local destinations are refused here.
	if class, host, refused := refuseRunTarget(runCfg.TargetURL); refused {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error": fmt.Sprintf(
				"refusing to send traffic to %s (%s): cloud instance metadata and link-local addresses are the credential-theft path and cannot be load-tested from the dashboard",
				host, class),
		})
		return
	}
	s.mu.RLock()
	running := s.runState != nil && s.runState.Status == "running"
	s.mu.RUnlock()
	if running {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "a run is already in progress"})
		return
	}
	if s.onCommand != nil {
		// The bridge decodes the config as a JSON object (map), not as a typed
		// struct. Round-trip through JSON so browser overrides (target url,
		// users, duration, method) survive the hand-off to the engine bridge.
		raw, _ := json.Marshal(runCfg)
		asMap := map[string]interface{}{}
		_ = json.Unmarshal(raw, &asMap)
		s.onCommand("start", map[string]interface{}{"config": asMap})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "started"})
}

// refuseRunTarget classifies a load-test target and reports whether the
// dashboard must refuse to send traffic to it. Instance metadata is always
// refused (the admin unlock does not open it); link-local is refused unless an
// operator deliberately unlocked the admin bypass, matching owaspGate.
//
// A resolution error is not treated as a refusal: an offline or unresolvable
// host is reported by the engine, and failing closed on every DNS hiccup would
// make the endpoint unusable. Literal addresses and the well-known metadata
// hostnames classify without DNS, so the credential-theft destinations are
// still caught.
func refuseRunTarget(raw string) (authz.Class, string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	tgt, err := authz.Classify(ctx, raw, nil)
	if err != nil {
		return authz.ClassPublic, "", false
	}
	switch tgt.Class() {
	case authz.ClassMetadata:
		return tgt.Class(), tgt.Host, true
	case authz.ClassLinkLocal:
		if adminlock.Active() {
			return tgt.Class(), tgt.Host, false
		}
		return tgt.Class(), tgt.Host, true
	}
	return tgt.Class(), tgt.Host, false
}

func (s *Server) handleStopRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	// Same CSRF defense as start: cross-origin browser POSTs are rejected.
	if !sameOrigin(r) {
		http.Error(w, "cross-origin requests are not allowed", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAPIRequestBody)
	if s.onCommand != nil {
		s.onCommand("stop", nil)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
}

// --- Demo store control plane ------------------------------------------------

// handleDemoStoreStatus reports whether the bundled VoltStore demo is up
// (and whether this dashboard spawned it).
func (s *Server) handleDemoStoreStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.store.Status())
}

// handleDemoStoreStart launches the VoltStore demo (VeriGate protection ON)
// if nothing is listening yet, then reports the URL. Non-browser clients
// (curl) and same-origin browser POSTs are allowed; cross-origin POSTs are
// rejected like every other mutating endpoint.
func (s *Server) handleDemoStoreStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin requests are not allowed", http.StatusForbidden)
		return
	}
	url, alreadyRunning, err := s.store.Start()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":              true,
		"url":             url,
		"already_running": alreadyRunning,
		"protection":      true,
	})
}

// handleDemoStoreStop shuts down the demo store only when this dashboard
// spawned it (a user-managed store is left running).
func (s *Server) handleDemoStoreStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin requests are not allowed", http.StatusForbidden)
		return
	}
	if err := s.store.Stop(); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}
