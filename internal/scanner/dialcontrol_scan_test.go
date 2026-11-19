package scanner

// dialcontrol_scan_test.go pins the dial-time control on the full scan.
// ScanWithControl must thread the hook into every one of its four phases:
// TLS, HTTP, WAF and security. The HTTP-based phases are told apart by the
// address the hook sees: with a bare host target they dial host:80 while the
// TLS phase dials the supplied port. A refusing hook must therefore leave all
// four result sections empty and open no socket, and the authz policy hook
// must refuse a loopback target in the same way.

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/asadbekabdulboqiyev/sift/internal/authz"
)

// errScanRefused is the sentinel returned by a refusing dial hook.
var errScanRefused = errors.New("scan dial hook refused the connection")

// dialRecorder records every address the hook is handed. A mutex is used
// because a scan may dial from more than one goroutine.
type dialRecorder struct {
	mu        sync.Mutex
	addresses []string
}

func (r *dialRecorder) hook(err error) func(string, string, syscall.RawConn) error {
	return func(_ string, address string, _ syscall.RawConn) error {
		r.mu.Lock()
		r.addresses = append(r.addresses, address)
		r.mu.Unlock()
		return err
	}
}

func (r *dialRecorder) count(want string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, address := range r.addresses {
		if address == want {
			n++
		}
	}
	return n
}

func (r *dialRecorder) total() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.addresses)
}

// hostPortOf splits an httptest server URL into the bare host and numeric port
// that ScanWithControl expects as separate arguments.
func hostPortOf(t *testing.T, srv *httptest.Server) (string, int) {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	host, portText, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("split server host port: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse server port: %v", err)
	}
	return host, port
}

// TestScanWithControlRefusesEveryPhase proves all four phases dial through the
// hook: the TLS phase is seen on the supplied port and the HTTP, WAF and
// security phases are each seen on the default HTTP port. A refusal leaves
// every result section empty and the server untouched.
func TestScanWithControlRefusesEveryPhase(t *testing.T) {
	// Arrange
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	host, port := hostPortOf(t, srv)

	rec := &dialRecorder{}
	tlsPeer := net.JoinHostPort(host, strconv.Itoa(port))
	httpPeer := net.JoinHostPort(host, "80")

	// Act
	result, err := ScanWithControl(host, port, rec.hook(errScanRefused))

	// Assert
	if err != nil {
		t.Fatalf("ScanWithControl: %v", err)
	}
	if result == nil {
		t.Fatal("ScanWithControl returned a nil result")
	}
	if rec.total() < 4 {
		t.Errorf("control calls = %d, want at least 4 (one per phase)", rec.total())
	}
	if n := rec.count(tlsPeer); n < 1 {
		t.Errorf("control calls to TLS peer %q = %d, want at least 1", tlsPeer, n)
	}
	if n := rec.count(httpPeer); n < 3 {
		t.Errorf("control calls to HTTP peer %q = %d, want at least 3 (HTTP, WAF, security)", httpPeer, n)
	}
	if result.HTTP != nil {
		t.Error("HTTP data was populated even though the hook refused every dial")
	}
	if result.WAF != nil {
		t.Error("WAF data was populated even though the hook refused every dial")
	}
	if result.Security != nil {
		t.Error("security data was populated even though the hook refused every dial")
	}
	if result.TLS != nil && len(result.TLS.SupportedVersions) != 0 {
		t.Errorf("TLS versions = %v, want none when the hook refuses every dial", result.TLS.SupportedVersions)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("server hits = %d, want 0: a refused dial must not reach the server", n)
	}
}

// TestScanWithControlPermissiveReachesEveryPhase proves the hook is threaded
// without blocking: an allowing hook lets the HTTP, WAF and security probes
// complete and the server sees their requests.
func TestScanWithControlPermissiveReachesEveryPhase(t *testing.T) {
	// Arrange
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	host, port := hostPortOf(t, srv)

	rec := &dialRecorder{}
	// The target carries the port so the http:// probe reaches this server; the
	// TLS phase is verified separately by TestScanWithControlTLSDialUsesTheHook.
	hostPort := net.JoinHostPort(host, strconv.Itoa(port))
	httpPeer := hostPort

	// Act
	result, err := ScanWithControl(hostPort, port, rec.hook(nil))

	// Assert
	if err != nil {
		t.Fatalf("ScanWithControl: %v", err)
	}
	if result == nil {
		t.Fatal("ScanWithControl returned a nil result")
	}
	if result.HTTP == nil {
		t.Error("HTTP data is nil with an allowing hook")
	}
	if result.WAF == nil {
		t.Error("WAF data is nil with an allowing hook")
	}
	if result.Security == nil {
		t.Error("security data is nil with an allowing hook")
	}
	if n := rec.count(httpPeer); n < 3 {
		t.Errorf("control calls to %q = %d, want at least 3 (HTTP, WAF, security)", httpPeer, n)
	}
	if n := hits.Load(); n < 3 {
		t.Errorf("server hits = %d, want at least 3", n)
	}
}

// TestScanWithControlTLSDialUsesTheHook proves the TLS phase alone carries the
// hook: an allowing hook completes a real handshake against a TLS test server,
// while a refusing hook leaves the supported-version list empty.
func TestScanWithControlTLSDialUsesTheHook(t *testing.T) {
	// Arrange
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	host, port := hostPortOf(t, srv)

	// Act: permissive pass.
	var allowed atomic.Int64
	okResult, okErr := ScanWithControl(host, port, func(_ string, _ string, _ syscall.RawConn) error {
		allowed.Add(1)
		return nil
	})

	// Assert: permissive pass.
	if okErr != nil {
		t.Fatalf("ScanWithControl (allow): %v", okErr)
	}
	if okResult.TLS == nil || len(okResult.TLS.SupportedVersions) == 0 {
		t.Fatalf("TLS versions = %v, want at least one with an allowing hook", okResult.TLS)
	}
	if n := allowed.Load(); n < 1 {
		t.Errorf("control calls (allow) = %d, want at least 1", n)
	}

	// Act: refusing pass over the same live TLS server.
	var denied atomic.Int64
	blockedResult, deniedErr := ScanWithControl(host, port, func(_ string, _ string, _ syscall.RawConn) error {
		denied.Add(1)
		return errScanRefused
	})

	// Assert: refusing pass.
	if deniedErr != nil {
		t.Fatalf("ScanWithControl (deny): %v", deniedErr)
	}
	if blockedResult.TLS != nil && len(blockedResult.TLS.SupportedVersions) != 0 {
		t.Errorf("TLS versions = %v, want none with a refusing hook", blockedResult.TLS.SupportedVersions)
	}
	if n := denied.Load(); n < 1 {
		t.Errorf("control calls (deny) = %d, want at least 1", n)
	}
}

// TestScanWithControlPublicPolicyRefusesLoopback is the real SSRF scenario: a
// public-only approval applied at dial time must refuse a loopback target
// before any connection is made, in every phase of the scan.
func TestScanWithControlPublicPolicyRefusesLoopback(t *testing.T) {
	// Arrange
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	host, port := hostPortOf(t, srv)

	policy := authz.DialControl(authz.ClassPublic)
	var calls, refusals atomic.Int64
	control := func(network, address string, c syscall.RawConn) error {
		calls.Add(1)
		err := policy(network, address, c)
		if err != nil {
			refusals.Add(1)
		}
		return err
	}

	// Act
	result, err := ScanWithControl(host, port, control)

	// Assert
	if err != nil {
		t.Fatalf("ScanWithControl: %v", err)
	}
	if n := calls.Load(); n < 4 {
		t.Errorf("control calls = %d, want at least 4 (one per phase)", n)
	}
	if n := refusals.Load(); n < 4 {
		t.Errorf("policy refusals = %d, want at least 4 (one per phase)", n)
	}
	if result.HTTP != nil || result.WAF != nil || result.Security != nil {
		t.Errorf("HTTP/WAF/security data was populated for a loopback target under a public approval")
	}
	if result.TLS != nil && len(result.TLS.SupportedVersions) != 0 {
		t.Errorf("TLS versions = %v, want none for a loopback target under a public approval", result.TLS.SupportedVersions)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("server hits = %d, want 0: the loopback target must not be reached", n)
	}
}

// TestScanStillWorksWithoutControl keeps the compatibility promise: the old
// Scan wrapper still runs a scan and populates the HTTP-based sections with no
// hook installed.
func TestScanStillWorksWithoutControl(t *testing.T) {
	// Arrange
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	host, port := hostPortOf(t, srv)
	hostPort := net.JoinHostPort(host, strconv.Itoa(port))

	// Act
	result, err := Scan(hostPort, port)

	// Assert
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if result == nil {
		t.Fatal("Scan returned a nil result")
	}
	if result.HTTP == nil {
		t.Error("HTTP data is nil from the backward-compatible Scan")
	}
	if result.WAF == nil {
		t.Error("WAF data is nil from the backward-compatible Scan")
	}
	if result.Security == nil {
		t.Error("security data is nil from the backward-compatible Scan")
	}
	if n := hits.Load(); n < 3 {
		t.Errorf("server hits = %d, want at least 3", n)
	}
}
