package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/asadbekabdulboqiyev/sift/internal/authz"
	"github.com/asadbekabdulboqiyev/sift/internal/scanner"
)

// --- Port scan dashboard -----------------------------------------------------
const (
	portscanMaxRequestBody = 32 << 10
	portscanMaxPorts       = 1024
)

// PortScanRequest is the POST body for /api/portscan.
type PortScanRequest struct {
	Target     string `json:"target"`
	Ports      []int  `json:"ports,omitempty"`
	Authorized string `json:"authorized,omitempty"`
}

// PortScanResult is the /api/portscan response.
type PortScanResult struct {
	OK       bool                `json:"ok"`
	Target   string              `json:"target"`
	Opened   int                 `json:"opened"`
	Closed   int                 `json:"closed"`
	Ports    []scanner.PortEntry `json:"ports,omitempty"`
	Duration float64             `json:"duration_seconds"`
	Notes    []string            `json:"notes,omitempty"`
}

func portscanGate(target, ticket string) (owaspGateOutcome, error) {
	return owaspGate(authz.OpScan, target, ticket)
}

func portscanAudit(e authz.Entry) error { return owaspAudit(e) }

func (s *Server) handlePortScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin requests are not allowed", http.StatusForbidden)
		return
	}
	select {
	case s.owaspSem <- struct{}{}:
	default:
		owaspWriteError(w, http.StatusConflict, "a scan is already running — wait for it to finish")
		return
	}
	defer func() { <-s.owaspSem }()

	r.Body = http.MaxBytesReader(w, r.Body, portscanMaxRequestBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req PortScanRequest
	if err := dec.Decode(&req); err != nil {
		owaspWriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	parsed, err := owaspValidateTarget(req.Target)
	if err != nil {
		owaspWriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	target := parsed.String()

	if len(req.Ports) > portscanMaxPorts {
		owaspWriteError(w, http.StatusBadRequest, fmt.Sprintf("at most %d ports, got %d", portscanMaxPorts, len(req.Ports)))
		return
	}
	ports := make([]int, 0, len(req.Ports))
	seenPort := make(map[int]bool, len(req.Ports))
	for _, p := range req.Ports {
		if p < 1 || p > 65535 {
			owaspWriteError(w, http.StatusBadRequest, fmt.Sprintf("port must be between 1 and 65535, got %d", p))
			return
		}
		if seenPort[p] {
			continue
		}
		seenPort[p] = true
		ports = append(ports, p)
	}

	decision, err := portscanGate(target, req.Authorized)
	if err != nil {
		owaspWriteError(w, http.StatusInternalServerError, "authorization policy error: "+err.Error())
		return
	}
	auditErr := portscanAudit(authz.Entry{Action: authz.OpScan.String(), Targets: []string{target}, IPs: decision.IPs, Class: decision.Class, Allowed: decision.Allowed, Rule: decision.Rule, Reason: decision.Reason, Argv: []string{"Sift dashboard", "POST /api/portscan"}})
	if !decision.Allowed {
		reason := decision.Reason
		if auditErr != nil {
			reason += " (audit log unavailable: " + auditErr.Error() + ")"
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "denied": true, "reason": reason})
		return
	}
	if auditErr != nil {
		owaspWriteError(w, http.StatusInternalServerError, "cannot record the authorization decision: "+auditErr.Error())
		return
	}

	// Build scope gate: default to the target hostname only (no Allow/AllowAll on this endpoint).
	gate, err := scanner.NewGuard(scanner.GuardConfig{
		Allow:       []string{owaspScopeHost(parsed)},
		AllowAll:    false,
		Intrusive:   false,
		RPS:         scanner.DefaultRPS,
		MaxRequests: scanner.DefaultMaxRequests,
		Timeout:     scanner.DefaultTimeout,
		DryRun:      false,
	})
	if err != nil {
		owaspWriteError(w, http.StatusBadRequest, "invalid probe policy: "+err.Error())
		return
	}

	result := scanner.ScanPorts(context.Background(), parsed.Hostname(), ports, gate)
	st := gate.Stats()
	var notes []string
	if st.RequestsRefused > 0 {
		notes = append(notes, fmt.Sprintf("Gate refused %d probe(s): out-of-scope=%d intrusive-off=%d budget=%d rate=%d dry-run=%d.", st.RequestsRefused, st.RefusedOutOfScope, st.RefusedIntrusive, st.RefusedBudget, st.RefusedRate, st.RefusedDryRun))
	}
	if st.RequestsSent == 0 && st.RequestsRefused > 0 && result.Opened == 0 && result.Closed == 0 {
		notes = append(notes, "No probes were sent; the reported result reflects refusals, not a clean target.")
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(PortScanResult{OK: true, Target: target, Opened: result.Opened, Closed: result.Closed, Ports: result.Ports, Duration: result.Duration.Seconds(), Notes: notes})
}
