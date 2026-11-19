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
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/authz"
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
