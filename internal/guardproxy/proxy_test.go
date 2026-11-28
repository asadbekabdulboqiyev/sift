package guardproxy

// proxy_test.go pins the security invariants of the guard proxy: a refusal
// happens before any dial, a dial targets a checked LITERAL IP, a failed dial
// is never reported as a successful CONNECT, and shutdown unblocks every
// tracked socket and in-flight dial.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func allowAll(_, _ string, _ syscall.RawConn) error { return nil }

// rawResponse sends a hand-written proxy request; http.Client turns a refusal
// into a transport error and hides the status code.
func rawResponse(t *testing.T, proxyAddr, raw string) *http.Response {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(conn, raw); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read proxy response: %v", err)
	}
	return resp
}

func TestRefusalHappensBeforeLiteralDial(t *testing.T) {
	var dials atomic.Int32
	p, err := New(Options{
		Control: func(_, address string, _ syscall.RawConn) error {
			return fmt.Errorf("authz: refusing %s", address)
		},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			dials.Add(1)
			return nil, errors.New("dial seam must not be reached")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	for _, raw := range []string{
		"GET http://203.0.113.9/x HTTP/1.1\r\nHost: 203.0.113.9\r\nConnection: close\r\n\r\n",
		"CONNECT 203.0.113.9:443 HTTP/1.1\r\nHost: 203.0.113.9:443\r\n\r\n",
	} {
		resp := rawResponse(t, p.Addr(), raw)
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status = %d, want 403 for a policy refusal", resp.StatusCode)
		}
		if !strings.Contains(string(body), "authz: refusing") {
			t.Errorf("body = %q, want the authz refusal reason", body)
		}
	}
	if got := dials.Load(); got != 0 {
		t.Fatalf("dial seam called %d times for refused destinations", got)
	}
}

func TestCONNECTDialsCheckedLiteralIPAndReports502OnFailure(t *testing.T) {
	var mu sync.Mutex
	var dialed []string
	p, err := New(Options{
		Control: allowAll,
		DialContext: func(_ context.Context, _, address string) (net.Conn, error) {
			mu.Lock()
			dialed = append(dialed, address)
			mu.Unlock()
			return nil, errors.New("simulated upstream failure")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	resp := rawResponse(t, p.Addr(), "CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n\r\n")
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 when the checked literal IP is unreachable", resp.StatusCode)
	}
	if !strings.Contains(string(body), "simulated upstream failure") {
		t.Fatalf("body = %q, want the dial failure", body)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(dialed) == 0 {
		t.Fatal("dial seam was never called")
	}
	var sawLoopback bool
	for _, address := range dialed {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			t.Fatalf("dial address %q is not host:port: %v", address, err)
		}
		if net.ParseIP(host) == nil {
			t.Fatalf("dial address %q uses a hostname; the checked literal IP was required", address)
		}
		if port != "443" {
			t.Fatalf("dial address %q has port %q, want 443", address, port)
		}
		if host == "127.0.0.1" || host == "::1" {
			sawLoopback = true
		}
	}
	if !sawLoopback {
		t.Fatalf("dial addresses = %v, want a checked loopback literal", dialed)
	}
}

func TestAbsoluteFormDialsCheckedLiteralIP(t *testing.T) {
	var mu sync.Mutex
	var dialed []string
	p, err := New(Options{
		Control: allowAll,
		DialContext: func(_ context.Context, _, address string) (net.Conn, error) {
			mu.Lock()
			dialed = append(dialed, address)
			mu.Unlock()
			return nil, errors.New("simulated upstream failure")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	resp := rawResponse(t, p.Addr(), "GET http://localhost/x HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 for a failed absolute-form dial", resp.StatusCode)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, address := range dialed {
		host, port, err := net.SplitHostPort(address)
		if err != nil || net.ParseIP(host) == nil || port != "80" {
			t.Fatalf("dial address = %q, want a checked literal IP on port 80", address)
		}
	}
}

// TestCONNECT200RequiresSuccessfulDial pins finding #6: the 200 must be sent
// only after the upstream socket exists. A dial failure produced 502 above;
// here the seam succeeds and the client must see the 200.
func TestCONNECT200RequiresSuccessfulDial(t *testing.T) {
	upstream, origin := net.Pipe()
	defer origin.Close()
	var dials atomic.Int32
	p, err := New(Options{
		Control: allowAll,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			dials.Add(1)
			return upstream, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	resp := rawResponse(t, p.Addr(), "CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 after a successful dial", resp.StatusCode)
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("dial seam calls = %d, want 1", got)
	}
	if _, closed := p.State(); closed {
		t.Fatal("proxy unexpectedly closed")
	}
}

func TestCloseCancelsInFlightDialAndUnblocksTunnel(t *testing.T) {
	dialStarted := make(chan struct{})
	dialCanceled := make(chan struct{})
	p, err := New(Options{
		Control: allowAll,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			close(dialStarted)
			<-ctx.Done()
			close(dialCanceled)
			return nil, ctx.Err()
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	client, err := net.DialTimeout("tcp", p.Addr(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, _ = io.WriteString(client, "CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n")
	<-dialStarted

	done := make(chan error, 1)
	go func() { done <- p.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("close: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close blocked on an in-flight dial")
	}
	select {
	case <-dialCanceled:
	default:
		t.Fatal("Close did not cancel the in-flight dial context")
	}
	if active, closed := p.State(); active != 0 || !closed {
		t.Fatalf("after close: active=%d closed=%v", active, closed)
	}
}

type failingListener struct {
	net.Listener
	err error
}

func (l *failingListener) Close() error {
	_ = l.Listener.Close()
	return l.err
}

func TestClosePropagatesListenerError(t *testing.T) {
	want := errors.New("listener close failed")
	p, err := New(Options{
		Control: allowAll,
		listen: func(network, address string) (net.Listener, error) {
			ln, err := net.Listen(network, address)
			if err != nil {
				return nil, err
			}
			return &failingListener{Listener: ln, err: want}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Close(); !errors.Is(got, want) {
		t.Fatalf("close error = %v, want %v", got, want)
	}
	// Idempotent even when the first close failed.
	if got := p.Close(); got != nil {
		t.Fatalf("second close = %v, want nil", got)
	}
}
