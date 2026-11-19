package scanner

// dialcontrol_test.go pins the M-1 fix: the authorization decision is re-applied
// to the address a socket actually connects to, not only to the name the gate
// resolved.
//
// Classify runs before a scan and resolves the target name. The dialer resolves
// the same name again, and DNS is allowed to answer differently: a name that
// resolved to a public address during the check can resolve to 169.254.169.254
// (cloud instance metadata) or an RFC1918 address a moment later. Every path
// that opens a socket therefore has to carry the approved class down to the
// dialer.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/authz"
	"github.com/asadbekabdulboqiyev/sift/internal/scanner/core"
)

// TestGuardCarriesTheDialControlToItsClient is the HTTP path: the Guard builds
// the client, so the hook has to be installed on it and be readable back for
// the scanners that dial on their own.
func TestGuardCarriesTheDialControlToItsClient(t *testing.T) {
	g := mustGuard(t, GuardConfig{
		AllowAll:    true,
		Timeout:     time.Second,
		DialControl: authz.DialControl(authz.ClassPublic),
	})
	if g.DialControl() == nil {
		t.Fatal("DialControl() = nil, want the configured hook")
	}
	if got := mustGuard(t, GuardConfig{}).DialControl(); got != nil {
		t.Error("DialControl() without configuration is not nil")
	}

	// A public approval that rebinds to loopback is refused at the socket.
	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:1/", nil)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := g.Do(req); err == nil {
		t.Fatal("request to a loopback address succeeded under a public approval")
	} else if !strings.Contains(err.Error(), "authz: refusing to connect") {
		t.Fatalf("error = %v, want the dial-time refusal", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("refusal took %s — the hook did not run before the connect", elapsed)
	}

	// The same guard still reaches an address the approval covers.
	g2 := mustGuard(t, GuardConfig{
		AllowAll:    true,
		Timeout:     time.Second,
		DialControl: authz.DialControl(authz.ClassLoopback),
	})
	if _, err := g2.Do(req); err == nil {
		t.Fatal("loopback request failed under a loopback approval")
	} else if strings.Contains(err.Error(), "authz: refusing to connect") {
		t.Fatalf("loopback approval was refused at the dial: %v", err)
	}
}

// TestScanPortsHonoursTheDialControl proves the port scanner's own dials — which
// never touch the Guard's HTTP client — carry the check. A listener that is up
// and accepting is reported closed when the approval does not cover loopback,
// and open when it does.
func TestScanPortsHonoursTheDialControl(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	port := ln.Addr().(*net.TCPAddr).Port

	// Accept and close so the banner grab returns immediately instead of
	// waiting out its read deadline.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	refused := ScanPortsWithControl(ctx, "127.0.0.1", []int{port}, nil, authz.DialControl(authz.ClassPublic))
	if refused.Opened != 0 {
		t.Errorf("opened = %d under a public approval, want 0: the dial-time check did not run", refused.Opened)
	}

	allowed := ScanPortsWithControl(ctx, "127.0.0.1", []int{port}, nil, authz.DialControl(authz.ClassLoopback))
	if allowed.Opened != 1 {
		t.Errorf("opened = %d under a loopback approval, want 1", allowed.Opened)
	}

	_ = ln.Close()
	<-done
}

// TestScanSSLHonoursTheDialControl covers the TLS handshake, which opens its own
// connection.
func TestScanSSLHonoursTheDialControl(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res := ScanSSLWithControl(ctx, "127.0.0.1:1", authz.DialControl(authz.ClassPublic))
	if len(res.Issues) == 0 || !strings.Contains(res.Issues[0], "authz: refusing to connect") {
		t.Fatalf("issues = %v, want the dial-time refusal", res.Issues)
	}

	// With the loopback approval the dial is attempted, so the failure is the
	// connection's, not the policy's.
	res = ScanSSLWithControl(ctx, "127.0.0.1:1", authz.DialControl(authz.ClassLoopback))
	if len(res.Issues) == 0 || strings.Contains(res.Issues[0], "authz: refusing to connect") {
		t.Fatalf("issues = %v, want a connection error rather than a policy refusal", res.Issues)
	}
}

// TestTestWebSocketHonoursTheDialControl covers the WebSocket client, which
// performs its own dial.
func TestTestWebSocketHonoursTheDialControl(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res := TestWebSocketWithControl(ctx, "ws://127.0.0.1:1/", nil, authz.DialControl(authz.ClassPublic))
	if len(res.Issues) == 0 || !strings.Contains(res.Issues[0], "authz: refusing to connect") {
		t.Fatalf("issues = %v, want the dial-time refusal", res.Issues)
	}
	if res.Connected {
		t.Fatal("connected to an address the approval did not cover")
	}
}

// TestDialControlStaysOffByDefault guards the compatibility promise: a caller
// that does not pass a hook keeps exactly the old behaviour.
func TestDialControlStaysOffByDefault(t *testing.T) {
	g := mustGuard(t, GuardConfig{AllowAll: true})
	if g.DialControl() != nil {
		t.Error("a default Guard installed a dial control")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// nil control means no hook, so a loopback port scan behaves as before.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	if res := ScanPortsWithControl(ctx, "127.0.0.1", []int{port}, nil, nil); res.Opened != 1 {
		t.Errorf("opened = %d with no control, want 1", res.Opened)
	}
}

// TestGuardChecksProxyTargetBeforeSending is the CWE-290 proxy case: the socket
// hook sees the proxy address, never the destination, so a destination that
// rebinds to a restricted class must be re-checked by Do() itself.
func TestGuardChecksProxyTargetBeforeSending(t *testing.T) {
	var proxyHits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyHits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("proxied"))
	}))
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	selector := func(*http.Request) (*url.URL, error) { return proxyURL, nil }

	// A public approval must refuse a loopback destination even though the
	// socket connects to the (loopback) proxy, which the hook alone would see.
	refusing := mustGuard(t, GuardConfig{
		AllowAll:    true,
		Timeout:     time.Second,
		DialControl: authz.DialControl(authz.ClassPublic),
		Proxy:       selector,
	})
	// Point the destination at loopback explicitly; the proxy is what the
	// socket would dial, so only the destination check can produce this error.
	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:1/probe", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := refusing.Do(req); err == nil {
		t.Fatal("proxied request to a restricted destination was sent")
	} else if !errors.Is(err, core.ErrOutOfScope) || !strings.Contains(err.Error(), "refusing proxy dial to target") {
		t.Fatalf("error = %v, want an out-of-scope refusal naming the proxy target check", err)
	}
	if got := proxyHits.Load(); got != 0 {
		t.Fatalf("proxy received %d requests, want 0: the refusal was not applied before sending", got)
	}

	// A loopback approval allows the destination, so the request really goes
	// through the configured proxy. This proves the check is not a blanket
	// refusal of every proxied request.
	allowing := mustGuard(t, GuardConfig{
		AllowAll:    true,
		Timeout:     2 * time.Second,
		DialControl: authz.DialControl(authz.ClassLoopback),
		Proxy:       selector,
	})
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("request reached the destination directly; the proxy was bypassed")
	}))
	defer dest.Close()
	req, err = http.NewRequest(http.MethodGet, dest.URL+"/probe", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := allowing.Do(req)
	if err != nil {
		t.Fatalf("allowed proxied request failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := proxyHits.Load(); got != 1 {
		t.Fatalf("proxy received %d requests, want 1", got)
	}
}

// TestGuardSkipsProxyTargetCheckWithoutAProxy documents the compatibility
// promise: a direct dial (no proxy) is covered by the socket hook alone, and a
// Guard with no DialControl has no address-level decision to re-apply.
func TestGuardSkipsProxyTargetCheckWithoutAProxy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	for name, cfg := range map[string]GuardConfig{
		"no proxy": {
			AllowAll:    true,
			Timeout:     2 * time.Second,
			DialControl: authz.DialControl(authz.ClassLoopback),
			Proxy:       func(*http.Request) (*url.URL, error) { return nil, nil },
		},
		"no dial control": {
			AllowAll: true,
			Timeout:  2 * time.Second,
			Proxy:    func(*http.Request) (*url.URL, error) { return url.Parse("http://127.0.0.1:1") },
		},
	} {
		t.Run(name, func(t *testing.T) {
			g := mustGuard(t, cfg)
			req, err := http.NewRequest(http.MethodGet, srv.URL+"/probe", nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := g.Do(req)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", resp.StatusCode)
			}
		})
	}
}

// TestGuardFailsClosedWhenProxySelectorErrors proves a broken proxy selector
// cannot silently skip the destination check when a proxy would apply.
func TestGuardFailsClosedWhenProxySelectorErrors(t *testing.T) {
	g := mustGuard(t, GuardConfig{
		AllowAll:    true,
		Timeout:     time.Second,
		DialControl: authz.DialControl(authz.ClassLoopback),
		Proxy: func(*http.Request) (*url.URL, error) {
			return nil, fmt.Errorf("proxy selector failed")
		},
	})
	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:1/probe", nil)
	if err != nil {
		t.Fatal(err)
	}
	// The client's transport will also fail on the selector error; the point
	// is that Do() returns an error rather than sending the request unchecked.
	if _, err := g.Do(req); err == nil {
		t.Fatal("request with a failing proxy selector succeeded")
	}
}
