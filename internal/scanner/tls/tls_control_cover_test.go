package tls

// Priority-1 coverage for ScanTLSWithControl (tls.go:97): the dial-time control
// hook must be applied to every handshake and must be able to reject a
// restricted peer or abort quickly on a timeout-class error.

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/authz"
)

// controlTestTarget starts a TLS server on loopback and returns its host/port.
func controlTestTarget(t *testing.T) (string, int) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srv.Close)

	addr := strings.TrimPrefix(srv.URL, "https://")
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return host, port
}

func TestScanTLSWithControlRejectsRestrictivePeer(t *testing.T) {
	host, port := controlTestTarget(t)

	var calls atomic.Int64
	var seen []string
	var mu sync.Mutex
	control := authz.DialControl(authz.ClassPublic) // loopback is more restrictive
	wrapped := func(network, address string, c syscall.RawConn) error {
		calls.Add(1)
		err := control(network, address, c)
		mu.Lock()
		seen = append(seen, address)
		mu.Unlock()
		return err
	}

	info, err := ScanTLSWithControl(host, port, wrapped)
	if err != nil {
		t.Fatalf("ScanTLSWithControl: %v", err)
	}
	if info == nil {
		t.Fatal("ScanTLSWithControl returned nil info")
	}
	if len(info.SupportedVersions) != 0 {
		t.Fatalf("SupportedVersions = %v, want empty when every dial is refused", info.SupportedVersions)
	}
	if calls.Load() < 4 {
		t.Fatalf("control was called %d times, want at least 4 (one per version probe)", calls.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) == 0 || !strings.Contains(seen[0], host) {
		t.Fatalf("control received addresses %v, want the target socket address", seen)
	}
}

// TestScanTLSWithControlControlErrorSurfacesInDial proves the hook's error is
// actually applied by the scanner: a custom refusal produces the same empty
// result as an authorization refusal and no handshake completes.
func TestScanTLSWithControlControlErrorSurfacesInDial(t *testing.T) {
	host, port := controlTestTarget(t)

	var calls atomic.Int64
	control := func(network, address string, c syscall.RawConn) error {
		calls.Add(1)
		return errors.New("qa-control-refused")
	}

	info, err := ScanTLSWithControl(host, port, control)
	if err != nil {
		t.Fatalf("ScanTLSWithControl: %v", err)
	}
	if len(info.SupportedVersions) != 0 {
		t.Fatalf("SupportedVersions = %v, want empty when control refuses", info.SupportedVersions)
	}
	if calls.Load() < 4 {
		t.Fatalf("control was called %d times, want at least 4", calls.Load())
	}
}

// timeoutNetError is a net.Error with Timeout() true. Returning it from the
// dial hook simulates the timeout class without waiting for the scanner's 5s
// dial timeout across six handshake attempts.
type timeoutNetError struct{}

func (timeoutNetError) Error() string   { return "qa-control-timeout" }
func (timeoutNetError) Timeout() bool   { return true }
func (timeoutNetError) Temporary() bool { return true }

func TestScanTLSWithControlTimeoutErrorReturnsQuickly(t *testing.T) {
	host, port := controlTestTarget(t)

	var calls atomic.Int64
	control := func(network, address string, c syscall.RawConn) error {
		calls.Add(1)
		return timeoutNetError{}
	}

	start := time.Now()
	info, err := ScanTLSWithControl(host, port, control)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ScanTLSWithControl: %v", err)
	}
	if len(info.SupportedVersions) != 0 {
		t.Fatalf("SupportedVersions = %v, want empty on control timeout", info.SupportedVersions)
	}
	if calls.Load() < 4 {
		t.Fatalf("control was called %d times, want at least 4", calls.Load())
	}
	if elapsed > 2*time.Second {
		t.Fatalf("control timeout took %s, want a fast return", elapsed)
	}
}

func TestScanTLSWithControlAllowsApprovedClass(t *testing.T) {
	host, port := controlTestTarget(t)

	// The httptest server is self-signed, so pass TLS verification off
	// explicitly. ScanTLSWithOptions is the single implementation behind
	// ScanTLSWithControl; using it directly avoids mutating the package-level
	// Default, which would make this test unsafe to run in parallel.
	var calls atomic.Int64
	control := func(network, address string, c syscall.RawConn) error {
		calls.Add(1)
		return authz.DialControl(authz.ClassLoopback)(network, address, c)
	}
	info, err := ScanTLSWithOptions(host, port, control, Options{TLSVerify: false})
	if err != nil {
		t.Fatalf("ScanTLSWithControl: %v", err)
	}
	if len(info.SupportedVersions) == 0 {
		t.Fatal("approved loopback peer did not complete a TLS handshake")
	}
	if calls.Load() < 4 {
		t.Fatalf("control was called %d times, want at least 4", calls.Load())
	}
}
