package dashboard

import (
	"encoding/json"
	"log"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/audit360"
	"github.com/asadbekabdulboqiyev/sift/internal/demostore"
	"github.com/gorilla/websocket"
)

// --- Limits -----------------------------------------------------------------
//
// Defense-in-depth caps for the local dashboard control plane. The dashboard
// can start/stop real load runs, so the HTTP + WebSocket surface is hardened:
// bounded request bodies, bounded WebSocket frames, a connection cap, and
// read deadlines so a stalled peer cannot pin a goroutine forever.

const (
	// maxAPIRequestBody caps POST bodies (run config JSON) at 1 MiB.
	maxAPIRequestBody = 1 << 20

	// maxWSConnections caps simultaneous WebSocket peers (browser tabs).
	maxWSConnections = 32

	// wsReadLimit caps a single WebSocket control message at 4 KiB.
	wsReadLimit = 4096

	// wsIdleTimeout is the read deadline per message. It is refreshed on
	// every received message and kept alive by the ping/pong watchdog, so
	// idle dashboards stay connected while slow/stalled peers are dropped.
	wsIdleTimeout = 90 * time.Second

	// wsPingInterval keeps quiet connections alive (browsers answer pings
	// with pongs at the WebSocket protocol level).
	wsPingInterval = 30 * time.Second
)

// --- Dashboard Server -------------------------------------------------------

// Server is the local dashboard's HTTP server: it owns the WebSocket
// client set, live snapshot/run state, history and injected handlers.
type Server struct {
	upgrader websocket.Upgrader
	clients  map[*websocket.Conn]bool
	// wsWrites holds one mutex per live connection. gorilla/websocket allows
	// exactly one writer at a time per connection and panics otherwise, while
	// snapshot broadcasts, run-state broadcasts and the initial handshake can
	// all fire from different goroutines. Every write goes through writeWS, so
	// they serialize on the connection's own mutex instead of killing the
	// process. Guarded by mu.
	wsWrites  map[*websocket.Conn]*sync.Mutex
	wsSem     chan struct{} // caps simultaneous WebSocket connections
	mu        sync.RWMutex
	snapshot  *LiveSnapshot
	runState  *RunState
	history   []HistoryEntry
	onCommand func(cmd string, args map[string]interface{})
	store     *demostore.DemoStore // bundled VoltStore demo launcher/supervisor

	// Optional operations endpoints and auth, injected by the host binary.
	// They are plain http.Handler / middleware values so this package does not
	// depend on the metrics, health or auth packages (no import cycle) and the
	// CLI can wire exactly what it needs.
	metricsHandler   http.Handler
	livenessHandler  http.Handler
	readinessHandler http.Handler
	authMiddleware   func(http.Handler) http.Handler
	auth             *Auth

	attestMu   sync.RWMutex
	attestInfo AttestationInfo

	// version is the host binary's build version, stamped into certificates
	// issued from the browser. It is set through SetVersion; "dev" is honest
	// when a caller does not know better.
	version string

	// owaspSem serializes security scans: one at a time, so a second click
	// gets a 409 instead of a second set of probes racing the first.
	owaspSem chan struct{}

	// audit360 manages 1-click 360-degree audits (async jobs + status/SSE).
	audit360 *audit360.Manager

	// allowedHosts holds extra Host header names accepted on top of the
	// loopback names. It is guarded by mu and only read by hostAllowed
	// (see hostgate.go).
	allowedHosts map[string]struct{}
}

// NewServer creates a Server with empty state and a demo-store launcher.
func NewServer() *Server {
	return &Server{
		upgrader: websocket.Upgrader{
			// Only same-origin (or non-browser) clients may upgrade. See
			// sameOrigin below.
			CheckOrigin:     sameOrigin,
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		},
		clients:      make(map[*websocket.Conn]bool),
		wsWrites:     make(map[*websocket.Conn]*sync.Mutex),
		wsSem:        make(chan struct{}, maxWSConnections),
		owaspSem:     make(chan struct{}, 1),
		allowedHosts: make(map[string]struct{}),
		snapshot:     &LiveSnapshot{StatusCodes: make(map[int]uint64)},
		runState:     &RunState{Status: "idle"},
		history:      make([]HistoryEntry, 0),
		version:      "dev",
		// The dashboard always launches the store with VeriGate protection
		// ON: the whole point is to demo the WAF. Visitors can still flip it
		// OFF from the store's own /admin control plane.
		store: demostore.New(demostore.Options{ExtraArgs: []string{"-protect"}}),
	}
}

// SetCommandHandler installs the callback that receives dashboard commands.
func (s *Server) SetCommandHandler(handler func(cmd string, args map[string]interface{})) {
	s.onCommand = handler
}

// SetMetricsHandler wires the Prometheus exposition endpoint (/metrics).
func (s *Server) SetMetricsHandler(h http.Handler) { s.metricsHandler = h }

// SetVersion records the host binary's version. It is stamped into
// certificates issued from the browser so they match the CLI's.
func (s *Server) SetVersion(v string) {
	if strings.TrimSpace(v) != "" {
		s.version = v
	}
}

func (s *Server) versionOrDefault() string {
	if strings.TrimSpace(s.version) == "" {
		return "dev"
	}
	return s.version
}

// SetHealthHandlers wires the liveness (/healthz) and readiness (/readyz)
// endpoints. Either handler may be nil; the built-in default reports "ok".
func (s *Server) SetHealthHandlers(live, ready http.Handler) {
	s.livenessHandler = live
	s.readinessHandler = ready
}

// SetAuthMiddleware installs a middleware wrapped around every UI/API/WebSocket
// route. The operations endpoints (/healthz, /readyz, /metrics) are always
// exempt so orchestrators can probe a locked-down dashboard. A nil middleware
// leaves the server open, which is only appropriate on a loopback bind.
func (s *Server) SetAuthMiddleware(mw func(http.Handler) http.Handler) {
	s.authMiddleware = mw
}

// GetAttestationInfo returns the latest attestation state.
func (s *Server) GetAttestationInfo() AttestationInfo {
	s.attestMu.RLock()
	defer s.attestMu.RUnlock()
	return s.attestInfo
}

// SetAttestationInfo replaces the latest attestation state.
func (s *Server) SetAttestationInfo(info AttestationInfo) {
	s.attestMu.Lock()
	defer s.attestMu.Unlock()
	s.attestInfo = info
}

// UpdateSnapshot replaces the live snapshot and broadcasts it to clients.
func (s *Server) UpdateSnapshot(snap *LiveSnapshot) {
	s.mu.Lock()
	s.snapshot = snap
	s.mu.Unlock()
	s.broadcast()
}

// SetRunState replaces the current run state and broadcasts it to clients.
func (s *Server) SetRunState(state *RunState) {
	s.mu.Lock()
	s.runState = state
	s.mu.Unlock()
	s.broadcastRunState()
}

// AddHistoryEntry appends a completed run to the dashboard history.
func (s *Server) AddHistoryEntry(entry HistoryEntry) {
	s.mu.Lock()
	s.history = append(s.history, entry)
	s.mu.Unlock()
}

// --- HTTP Handlers ----------------------------------------------------------

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// The rebinding gate runs before anything else, including the operations
	// endpoints: a browser tricked into addressing this dashboard as
	// "evil.com:8888" must not reach any handler. It keys on the connection's
	// local address, so it is a no-op for network-exposed binds where the auth
	// middleware is the control. See hostgate.go.
	if !s.hostAllowed(r) {
		// 421 Misdirected Request: the request reached a server that is not
		// configured for the name it asked for.
		w.WriteHeader(http.StatusMisdirectedRequest)
		return
	}

	securityHeaders(w, r)

	// Operations endpoints are never behind auth: a locked-down dashboard must
	// still be probeable and scrapeable by the platform.
	switch r.URL.Path {
	case "/healthz":
		s.serveOps(w, r, s.livenessHandler, true)
		return
	case "/readyz":
		s.serveOps(w, r, s.readinessHandler, true)
		return
	case "/metrics":
		s.serveOps(w, r, s.metricsHandler, false)
		return
	}

	if s.authMiddleware != nil {
		s.authMiddleware(s.recoverMiddleware(http.HandlerFunc(s.serveApp))).ServeHTTP(w, r)
		return
	}
	s.recoverMiddleware(http.HandlerFunc(s.serveApp)).ServeHTTP(w, r)
}

// recoverMiddleware panics inside handler (e.g. nil-Requester deref) without
// killing the dashboard process. It returns 500 instead.
func (s *Server) recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("dashboard panic: %v\n%s", rec, debug.Stack())
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// writeJSON encodes v as the response body.
//
// By the time Encode runs the status line and headers are already committed, so
// an encoding failure can only be logged: the client cannot be told, and a
// second write would corrupt the body it already has. Logging it is the whole
// of what a handler can do — silently discarding the error is not.
func writeJSON(w http.ResponseWriter, v any) {
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("dashboard: encode response: %v", err)
	}
}

// serveOps dispatches an operations request to its handler. When no handler
// was injected, health endpoints answer a minimal 200 and /metrics answers 404,
// so the server is still useful without the optional packages wired in.
func (s *Server) serveOps(w http.ResponseWriter, r *http.Request, h http.Handler, defaultOK bool) {
	if h != nil {
		h.ServeHTTP(w, r)
		return
	}
	if defaultOK {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
		return
	}
	http.NotFound(w, r)
}

// serveApp now lives in routes.go: route registration is a declarative table
// so the dispatch order is visible in one place. The middleware chain and all
// handler bodies are unchanged.
