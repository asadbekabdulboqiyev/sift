package engine

import (
	"bufio"
	"context"
	"net"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/config"
)

// TestRawTCPSessionPoolKeyedByTarget pins the cross-target fix: a pooled
// socket is reused for its own target only, and a changed target re-dials
// through the gated path.
func TestRawTCPSessionPoolKeyedByTarget(t *testing.T) {
	targetA, acceptsA, closesA := newPoolEchoServer(t)
	targetB, acceptsB, _ := newPoolEchoServer(t)

	var controls atomic.Int64
	e := &Engine{
		keepAlive: true,
		dialControl: func(network, address string, c syscall.RawConn) error {
			if !strings.HasPrefix(network, "tcp") {
				t.Errorf("Control network = %q, want a tcp network", network)
			}
			if c == nil {
				t.Error("Control received a nil RawConn")
			}
			controls.Add(1)
			return nil
		},
	}
	t.Cleanup(func() { e.closeSessions() })

	step := config.Step{Session: true, Body: "PING\n"}
	ctx := context.Background()
	const timeout = 2 * time.Second

	for i, target := range []string{targetA, targetA, targetB} {
		_, body := e.rawClientForUser(0, ctx, "tcp", target, step, nil, timeout)
		if string(body) != "PING\n" {
			t.Fatalf("iteration %d to %s: body = %q, want PING", i, target, body)
		}
	}

	if got := controls.Load(); got != 2 {
		t.Errorf("Control called %d times, want 2 (one dial per distinct target)", got)
	}
	if got := acceptsA.Load(); got != 1 {
		t.Errorf("target A accepted %d sockets, want 1", got)
	}
	if got := acceptsB.Load(); got != 1 {
		t.Errorf("target B accepted %d sockets, want 1", got)
	}
	waitForPoolCount(t, closesA, 1) // old target A socket must be closed on mismatch

	e.sessMu.Lock()
	session, ok := e.tcpConns[0].(*tcpSession)
	e.sessMu.Unlock()
	if !ok || session.target != targetB {
		t.Errorf("pooled session target = %v, want %q", session, targetB)
	}
}

// TestRawTCPNonSessionUnaffected proves the non-session path still dials on
// every call and never populates the pool.
func TestRawTCPNonSessionUnaffected(t *testing.T) {
	target, accepts, _ := newPoolEchoServer(t)

	var controls atomic.Int64
	e := &Engine{
		dialControl: func(_, _ string, _ syscall.RawConn) error {
			controls.Add(1)
			return nil
		},
	}
	step := config.Step{Body: "PING\n"} // Session is false.
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		_, body := e.rawClientForUser(0, ctx, "tcp", target, step, nil, 2*time.Second)
		if string(body) != "PING\n" {
			t.Fatalf("iteration %d: body = %q, want PING", i, body)
		}
	}
	if got := controls.Load(); got != 2 {
		t.Errorf("Control called %d times, want 2 on the non-session path", got)
	}
	if got := accepts.Load(); got != 2 {
		t.Errorf("server accepted %d sockets, want 2", got)
	}
	e.sessMu.Lock()
	pooled := len(e.tcpConns)
	e.sessMu.Unlock()
	if pooled != 0 {
		t.Errorf("non-session path pooled %d sockets, want 0", pooled)
	}
}

// waitForPoolCount polls a server-side counter: the close is observed in a
// different goroutine, so an immediate read could race the EOF handling.
func waitForPoolCount(t *testing.T, counter *atomic.Int64, want int64) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for counter.Load() != want && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := counter.Load(); got != want {
		t.Errorf("server counter = %d, want %d", got, want)
	}
}

// newPoolEchoServer echoes one line per request and counts accepted sockets,
// which lets the tests distinguish reuse from a fresh dial.
func newPoolEchoServer(t *testing.T) (string, *atomic.Int64, *atomic.Int64) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	accepts, closes := &atomic.Int64{}, &atomic.Int64{}
	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			go func() {
				defer func() {
					_ = conn.Close()
					closes.Add(1)
				}()
				r := bufio.NewReader(conn)
				for {
					line, err := r.ReadString('\n')
					if line != "" {
						if _, err := conn.Write([]byte(line)); err != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() { _ = lis.Close() })
	return lis.Addr().String(), accepts, closes
}
