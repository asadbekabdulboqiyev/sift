package dashboard

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Cap concurrent sockets so a flood of tabs cannot exhaust descriptors,
	// memory or goroutines on the host running the dashboard.
	select {
	case s.wsSem <- struct{}{}:
	default:
		http.Error(w, "too many websocket connections", http.StatusServiceUnavailable)
		return
	}
	defer func() { <-s.wsSem }()

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	s.mu.Lock()
	s.clients[conn] = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.clients, conn)
		delete(s.wsWrites, conn)
		s.mu.Unlock()
		_ = conn.Close()
	}()

	// Bound the frame size so a malicious peer cannot stream an unbounded
	// message into memory.
	conn.SetReadLimit(wsReadLimit)

	// Ping watchdog: WriteControl is safe to call concurrently with the
	// read loop and the broadcast writer. Browser pongs keep the read
	// deadline rolling for idle-but-alive dashboards.
	done := make(chan struct{})
	defer close(done)
	go func() {
		ticker := time.NewTicker(wsPingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(10*time.Second)); err != nil {
					return
				}
			}
		}
	}()

	// Send initial state
	s.mu.RLock()
	initMsg, _ := json.Marshal(map[string]interface{}{
		"type":    "init",
		"state":   s.runState,
		"history": s.history,
	})
	s.mu.RUnlock()
	_ = s.writeWS(conn, initMsg)

	// The upgrade passed the normal auth middleware, so the request context
	// carries the principal and roles for this socket. Capture it once: the
	// command loop below authorizes start/stop against the same tests:run
	// permission the HTTP start endpoint requires.
	cmdCtx := r.Context()

	// Listen for commands
	for {
		// A stalled peer (partial frame, no pongs) is dropped after the
		// idle timeout; a live peer refreshes the deadline on every read.
		_ = conn.SetReadDeadline(time.Now().Add(wsIdleTimeout))
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var cmd struct {
			Type string                 `json:"type"`
			Args map[string]interface{} `json:"args,omitempty"`
		}
		if err := json.Unmarshal(msg, &cmd); err != nil {
			continue
		}
		// A WebSocket start is the same privileged operation as POST
		// /api/run/start, but the upgrade only required tests:view. Gate every
		// command before dispatch so a viewer cannot drive the engine against
		// internal or metadata targets, and so no audit decision is skipped.
		if err := s.authorizeRunCommand(cmdCtx, cmd.Type, cmd.Args); err != nil {
			frame, _ := json.Marshal(map[string]interface{}{
				"type":    "command_error",
				"command": cmd.Type,
				"error":   err.Error(),
			})
			_ = s.writeWS(conn, frame)
			continue
		}
		if s.onCommand != nil {
			s.onCommand(cmd.Type, cmd.Args)
		}
	}
}

// --- Broadcast --------------------------------------------------------------

// wsWriteLock returns the write mutex for one connection, creating it on
// first use. Callers must not hold s.mu when calling this.
func (s *Server) wsWriteLock(c *websocket.Conn) *sync.Mutex {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.wsWrites == nil {
		s.wsWrites = make(map[*websocket.Conn]*sync.Mutex)
	}
	mu, ok := s.wsWrites[c]
	if !ok {
		mu = &sync.Mutex{}
		s.wsWrites[c] = mu
	}
	return mu
}

// writeWS is the only path that writes a data frame to a dashboard client.
// gorilla/websocket panics on concurrent writes to one connection, and that
// panic happens in a broadcast goroutine, which takes the whole process down.
// Serializing here keeps one slow or contended writer from crashing the server.
func (s *Server) writeWS(c *websocket.Conn, msg []byte) error {
	mu := s.wsWriteLock(c)
	mu.Lock()
	defer mu.Unlock()
	// Bound every data write, including command_error frames sent after a
	// denied start. Without this a client that never reads could fill its
	// send buffer and wedge the read loop on the next denial, turning the
	// authorization feedback path into a new denial-of-service vector.
	// A timeout is treated like any other write error: broadcast drops the
	// client, and the command loop returns on its next read.
	if err := c.SetWriteDeadline(time.Now().Add(wsWriteTimeout)); err != nil {
		return err
	}
	return c.WriteMessage(websocket.TextMessage, msg)
}

func (s *Server) broadcast() {
	s.mu.RLock()
	snap := s.snapshot
	clients := make([]*websocket.Conn, 0, len(s.clients))
	for c := range s.clients {
		clients = append(clients, c)
	}
	s.mu.RUnlock()

	msg, err := json.Marshal(map[string]interface{}{
		"type": "snapshot",
		"data": snap,
	})
	if err != nil {
		return
	}

	var dead []*websocket.Conn
	for _, c := range clients {
		if err := s.writeWS(c, msg); err != nil {
			dead = append(dead, c)
		}
	}

	if len(dead) > 0 {
		s.mu.Lock()
		for _, c := range dead {
			_ = c.Close()
			delete(s.clients, c)
			delete(s.wsWrites, c)
		}
		s.mu.Unlock()
	}
}

func (s *Server) broadcastRunState() {
	s.mu.RLock()
	state := s.runState
	clients := make([]*websocket.Conn, 0, len(s.clients))
	for c := range s.clients {
		clients = append(clients, c)
	}
	s.mu.RUnlock()

	msg, err := json.Marshal(map[string]interface{}{
		"type": "run_state",
		"data": state,
	})
	if err != nil {
		return
	}

	var dead []*websocket.Conn
	for _, c := range clients {
		if err := s.writeWS(c, msg); err != nil {
			dead = append(dead, c)
		}
	}

	if len(dead) > 0 {
		s.mu.Lock()
		for _, c := range dead {
			_ = c.Close()
			delete(s.clients, c)
			delete(s.wsWrites, c)
		}
		s.mu.Unlock()
	}
}
