//go:build integration

package engine

import (
	"github.com/asadbekabdulboqiyev/sift/internal/config"
	"github.com/gorilla/websocket"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestWSOneShotDefaultIsBackwardCompatible verifies the default behavior:
// without session:true every iteration dials a fresh connection and performs
// exactly one exchange — matching the classic one-shot semantics.
func TestWSOneShotDefaultIsBackwardCompatible(t *testing.T) {
	var conns atomic.Int32
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conns.Add(1)
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		_, msg, err := c.ReadMessage()
		if err != nil {
			return
		}
		_ = c.WriteMessage(websocket.TextMessage, append([]byte("echo:"), msg...))
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	sc := &config.Scenario{
		Name:    "ws-oneshot",
		Profile: config.Profile{Type: config.ProfileSteady, Users: 1, Duration: 1, Timeout: 5},
		Steps: []config.Step{{
			Name: "ws", Type: "ws", URL: wsURL, Body: "ping",
		}},
	}
	tel := runScenario(t, sc, time.Second)
	if tel.TotalErrors() != 0 {
		t.Errorf("errors = %d, want 0: %v", tel.TotalErrors(), tel.Errors())
	}
	if tel.TotalRequests() < 2 {
		t.Errorf("requests = %d, want multiple one-shot iterations", tel.TotalRequests())
	}
}

// TestWSPersistentSession verifies that session:true keeps a single live
// WebSocket per virtual user across many message exchanges.
func TestWSPersistentSession(t *testing.T) {
	srv := newWSEchoServer(t)
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	sc := &config.Scenario{
		Name:    "ws-session",
		Profile: config.Profile{Type: config.ProfileSteady, Users: 2, Duration: 1, Timeout: 5},
		Steps: []config.Step{{
			Name: "ws-chat", Type: "ws", URL: wsURL,
			Body:    "hello {{user}}",
			Session: true,
			Assertions: []config.Assertion{
				{Type: "regex", Value: "echo:hello"},
			},
		}},
	}
	tel := runScenario(t, sc, time.Second)
	if tel.TotalRequests() < 10 {
		t.Errorf("requests = %d, want >=10 pooled exchanges", tel.TotalRequests())
	}
	if tel.TotalErrors() != 0 {
		t.Errorf("errors = %d, want 0: %v", tel.TotalErrors(), tel.Errors())
	}
}

// TestTCPPersistentSession verifies TCP session pooling across iterations.
func TestTCPPersistentSession(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					if _, err := c.Write(append([]byte("ack:"), buf[:n]...)); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	sc := &config.Scenario{
		Name:    "tcp-session",
		Profile: config.Profile{Type: config.ProfileSteady, Users: 2, Duration: 1, Timeout: 5},
		Steps: []config.Step{{
			Name: "tcp-echo", Type: "tcp", URL: ln.Addr().String(),
			Body:    "ping",
			Session: true,
			Assertions: []config.Assertion{
				{Type: "regex", Value: "ack:ping"},
			},
		}},
	}
	tel := runScenario(t, sc, time.Second)
	if tel.TotalRequests() < 10 {
		t.Errorf("requests = %d, want >=10 pooled exchanges", tel.TotalRequests())
	}
	if tel.TotalErrors() != 0 {
		t.Errorf("errors = %d, want 0: %v", tel.TotalErrors(), tel.Errors())
	}
}
