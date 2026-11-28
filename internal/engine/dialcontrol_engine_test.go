package engine

// dialcontrol_engine_test.go pins the engine side of SEC-A360-01: every socket
// the engine opens must pass through the authorization hook supplied by the
// caller. The hook runs at dial time, after name resolution, so it can refuse
// an address that differs from the one the policy check originally approved.

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"

	"github.com/asadbekabdulboqiyev/sift/internal/config"
	"github.com/asadbekabdulboqiyev/sift/internal/fingerprint"
	"github.com/asadbekabdulboqiyev/sift/internal/guardproxy"
)

var errTestDialRefused = errors.New("test dial refused")

func allowDialControl(calls *atomic.Int32) func(string, string, syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		if network == "" || address == "" {
			return errors.New("dial control received empty network or address")
		}
		calls.Add(1)
		return nil
	}
}

func refuseDialControl(calls *atomic.Int32) func(string, string, syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		calls.Add(1)
		return errTestDialRefused
	}
}

func dialControlScenario(target string) *config.Scenario {
	return &config.Scenario{
		Steps: []config.Step{{Name: "r", Method: http.MethodGet, URL: target}},
	}
}

func newEngineForDialControl(t *testing.T, sc *config.Scenario, control func(string, string, syscall.RawConn) error) *Engine {
	t.Helper()
	e, err := NewWithControl(sc, control)
	if err != nil {
		t.Fatalf("NewWithControl: %v", err)
	}
	return e
}

// TestControlledTransportUsesLoopbackGuard pins the split-horizon fix at the
// engine boundary: the controlled transport's Proxy selector resolves to the
// local guard listener, the caller's Control still runs on every direct dial,
// and only that exact guard socket is exempt.
func TestControlledTransportUsesLoopbackGuard(t *testing.T) {
	var calls atomic.Int32
	e := newEngineForDialControl(t, dialControlScenario("http://127.0.0.1:1"), func(network, address string, c syscall.RawConn) error {
		calls.Add(1)
		return nil
	})
	defer e.Close()

	if e.transport.Proxy == nil {
		t.Fatal("controlled transport has no proxy selector")
	}
	req, err := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	u, err := e.transport.Proxy(req)
	if err != nil {
		t.Fatalf("proxy selector: %v", err)
	}
	if u == nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" {
		t.Fatalf("proxy = %v, want an ephemeral loopback guard listener", u)
	}

	// A non-guard dial still passes through the caller's hook.
	before := calls.Load()
	_, _ = e.transport.DialContext(context.Background(), "tcp", "127.0.0.1:1")
	if calls.Load() <= before {
		t.Fatal("caller Control was not installed on a direct dial")
	}

	// The socket to the guard itself is exempt; otherwise a public-only class
	// would refuse the loopback listener and no request could reach it.
	before = calls.Load()
	guardConn, err := e.transport.DialContext(context.Background(), "tcp", u.Host)
	if err != nil {
		t.Fatalf("dial guard listener %s: %v", u.Host, err)
	}
	_ = guardConn.Close()
	if calls.Load() != before {
		t.Fatal("guard socket was checked as a destination")
	}
}

// TestHTTPTransportDialControl verifies the plain HTTP dial path installed on
// the shared transport, and that a refusal aborts the request before connect.
func TestHTTPTransportDialControl(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var calls atomic.Int32
	e := newEngineForDialControl(t, dialControlScenario(srv.URL), allowDialControl(&calls))
	resp, err := e.client.Get(srv.URL)
	if err != nil {
		t.Fatalf("request through controlled transport: %v", err)
	}
	_ = resp.Body.Close()
	if got := calls.Load(); got < 1 {
		t.Fatalf("HTTP dial control called %d times, want at least 1", got)
	}
}

func TestHTTPTransportDialControlRejects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var calls atomic.Int32
	e := newEngineForDialControl(t, dialControlScenario(srv.URL), refuseDialControl(&calls))
	resp, err := e.client.Get(srv.URL)
	if err == nil {
		// A controlled transport is pinned to the local guard proxy. The
		// proxy refuses the destination with 403 instead of failing the
		// client's dial, so a refusal is observable as either outcome.
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("request returned %d although the dial control refused it", resp.StatusCode)
		}
	} else if !strings.Contains(err.Error(), errTestDialRefused.Error()) {
		t.Fatalf("error = %v, want the dial control refusal", err)
	}
	if got := calls.Load(); got < 1 {
		t.Fatalf("HTTP dial control called %d times, want at least 1", got)
	}
}

// TestUTLSTransportDialControl verifies the uTLS DialTLSContext path. The test
// server uses a self-signed certificate, so the handshake may fail, but the
// guard must still check the destination before that handshake and a refusal
// must surface as a guard CONNECT error.
func TestUTLSTransportDialControl(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sc := dialControlScenario(srv.URL)
	sc.Profile.TLSFingerprint = "chrome"
	var calls atomic.Int32
	e := newEngineForDialControl(t, sc, allowDialControl(&calls))
	if e.transport.DialTLSContext == nil {
		t.Fatal("fingerprint transport has no DialTLSContext")
	}
	_, _ = e.client.Get(srv.URL)
	if got := calls.Load(); got < 1 {
		t.Fatalf("uTLS dial control called %d times, want at least 1", got)
	}
}

func TestUTLSTransportDialControlRejects(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sc := dialControlScenario(srv.URL)
	sc.Profile.TLSFingerprint = "chrome"
	var calls atomic.Int32
	e := newEngineForDialControl(t, sc, refuseDialControl(&calls))
	_, err := e.client.Get(srv.URL)
	if err == nil {
		t.Fatal("uTLS request succeeded although the dial control refused it")
	}
	if !strings.Contains(err.Error(), errTestDialRefused.Error()) {
		t.Fatalf("error = %v, want the dial control refusal", err)
	}
	if got := calls.Load(); got < 1 {
		t.Fatalf("uTLS dial control called %d times, want at least 1", got)
	}
}

// TestControlledUTLSTransportUsesLoopbackGuard pins the split-horizon fix at
// the fingerprint boundary: Proxy must stay nil (Go would otherwise handshake
// with the proxy), and the guard must be owned by the transport so Engine.Close
// and engineWSDialer share one listener.
func TestControlledUTLSTransportUsesLoopbackGuard(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sc := dialControlScenario(srv.URL)
	sc.Profile.TLSFingerprint = "chrome"
	var calls atomic.Int32
	e := newEngineForDialControl(t, sc, allowDialControl(&calls))
	defer e.Close()

	if e.transport.Proxy != nil {
		t.Fatal("uTLS transport has a Proxy selector, want nil (CONNECT is done in the dial seam)")
	}
	if e.transport.DialTLSContext == nil {
		t.Fatal("fingerprint transport has no DialTLSContext")
	}
	closerValue, ok := guardedTransports.Load(e.transport)
	if !ok {
		t.Fatal("uTLS transport did not register a guard closer")
	}
	lazy, ok := closerValue.(*guardproxy.Lazy)
	if !ok {
		t.Fatalf("uTLS guard closer has type %T, want *guardproxy.Lazy", closerValue)
	}
	u, err := lazy.URL()
	if err != nil {
		t.Fatalf("guard URL: %v", err)
	}
	if u.Hostname() != "127.0.0.1" || u.Port() == "" {
		t.Fatalf("guard URL = %v, want an ephemeral loopback listener", u)
	}

	_, _ = e.client.Get(srv.URL) // self-signed cert: TLS may fail, guard must run
	if got := calls.Load(); got < 1 {
		t.Fatalf("guarded uTLS dial checked the destination %d times, want at least 1", got)
	}

	if err := e.Close(); err != nil {
		t.Fatalf("Engine.Close: %v", err)
	}
	if !lazy.Closed() {
		t.Fatal("Engine.Close did not close the uTLS guard listener")
	}
}

// TestControlledUTLSTransportCONNECTRefusesDestination proves the refusal is
// produced by the guard's CONNECT response, not by a socket-level dial error:
// the guard socket itself is exempt, while the destination is checked and
// refused with 403 before any ClientHello can reach the origin.
func TestControlledUTLSTransportCONNECTRefusesDestination(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sc := dialControlScenario(srv.URL)
	sc.Profile.TLSFingerprint = "chrome"
	var calls atomic.Int32
	var mu sync.Mutex
	var checked []string
	control := func(network, address string, c syscall.RawConn) error {
		calls.Add(1)
		mu.Lock()
		checked = append(checked, address)
		mu.Unlock()
		return errTestDialRefused
	}
	e := newEngineForDialControl(t, sc, control)
	defer e.Close()
	closerValue, ok := guardedTransports.Load(e.transport)
	if !ok {
		t.Fatal("uTLS transport did not register a guard closer")
	}
	u, err := closerValue.(*guardproxy.Lazy).URL()
	if err != nil {
		t.Fatalf("guard URL: %v", err)
	}

	_, err = e.client.Get(srv.URL)
	if err == nil {
		t.Fatal("uTLS request succeeded although the dial control refused it")
	}
	msg := err.Error()
	if !strings.Contains(msg, "403 Forbidden") || !strings.Contains(msg, "guard proxy") {
		t.Fatalf("error = %q, want a 403 guard CONNECT refusal", msg)
	}
	if !strings.Contains(msg, errTestDialRefused.Error()) {
		t.Fatalf("error = %q, want the dial control refusal in the guard body", msg)
	}
	if got := calls.Load(); got < 1 {
		t.Fatalf("uTLS dial control called %d times, want at least 1", got)
	}
	mu.Lock()
	seen := append([]string(nil), checked...)
	mu.Unlock()
	if len(seen) == 0 {
		t.Fatal("no address was checked by the caller's Control hook")
	}
	for _, address := range seen {
		if address == u.Host {
			t.Fatalf("guard socket %s was checked as a destination", address)
		}
	}
}

// TestGuardConnectDialContextCompletesUTLSHandshake drives the full authorized
// tunnel: loopback guard socket, CONNECT, then a real uTLS ClientHello to the
// origin. InsecureSkipVerify is used only here because the test server is
// self-signed; production engines keep certificate verification enabled.
func TestGuardConnectDialContextCompletesUTLSHandshake(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var calls atomic.Int32
	control := allowDialControl(&calls)
	lazy := guardproxy.NewLazy(guardproxy.Options{Control: control})
	defer func() { _ = lazy.Close() }()
	dialer, err := fingerprint.NewDialerChecked(fingerprint.Options{
		Fingerprint:        fingerprint.Chrome,
		DialContext:        guardConnectDialContext(lazy, control),
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
	})
	if err != nil {
		t.Fatalf("uTLS dialer: %v", err)
	}
	client := &http.Client{Transport: &http.Transport{
		DialTLSContext: dialer,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true,
		},
	}}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("request through guarded uTLS tunnel: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := calls.Load(); got < 1 {
		t.Fatalf("guarded uTLS dial checked the destination %d times, want at least 1", got)
	}
}

// TestRawAndWebSocketDialControl covers the non-HTTP protocols that open their
// own sockets instead of using the shared HTTP transport.
func TestRawDialControl(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		c, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = c.Close() }()
		buf := make([]byte, 16)
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte("pong"))
	}()

	var calls atomic.Int32
	e := newEngineForDialControl(t, dialControlScenario("http://"+ln.Addr().String()), allowDialControl(&calls))
	res, _ := e.rawClient(context.Background(), "tcp", ln.Addr().String(), config.Step{Body: "ping"}, nil, time.Second)
	if res.errName != "" {
		t.Fatalf("raw exchange errName = %q, want success", res.errName)
	}
	if got := calls.Load(); got < 1 {
		t.Fatalf("raw dial control called %d times, want at least 1", got)
	}
}

func TestWebSocketDialControl(t *testing.T) {
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_, msg, err := c.ReadMessage()
		if err != nil {
			return
		}
		_ = c.WriteMessage(websocket.TextMessage, append([]byte("echo:"), msg...))
	}))
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	var calls atomic.Int32
	e := newEngineForDialControl(t, dialControlScenario(srv.URL), allowDialControl(&calls))
	res, body := e.wsClient(context.Background(), wsURL, config.Step{Body: "ping"}, nil, time.Second)
	if res.errName != "" {
		t.Fatalf("websocket exchange errName = %q, want success", res.errName)
	}
	if string(body) != "echo:ping" {
		t.Fatalf("websocket body = %q, want %q", body, "echo:ping")
	}
	if got := calls.Load(); got < 1 {
		t.Fatalf("websocket dial control called %d times, want at least 1", got)
	}
}

// TestPrewarmDialControl covers both pre-warm sockets: the reachability probe
// and the per-client transports used for the warm-up HEAD requests.
func TestPrewarmDialControl(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var calls atomic.Int32
	sc := dialControlScenario(srv.URL)
	sc.PreWarm = true
	sc.PreWarmConnections = 1
	e := newEngineForDialControl(t, sc, allowDialControl(&calls))
	defer e.prewarmed.closeAll()
	e.preWarmConnections(1)
	if got := calls.Load(); got < 2 {
		t.Fatalf("pre-warm dial control called %d times, want at least 2", got)
	}
}

func TestPrewarmDialControlRejects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var calls atomic.Int32
	sc := dialControlScenario(srv.URL)
	sc.PreWarm = true
	sc.PreWarmConnections = 1
	e := newEngineForDialControl(t, sc, refuseDialControl(&calls))
	e.preWarmConnections(1)
	if len(e.prewarmed.clients) != 0 {
		t.Fatalf("pre-warm installed %d clients under a refusal, want 0", len(e.prewarmed.clients))
	}
	if got := calls.Load(); got < 1 {
		t.Fatalf("pre-warm dial control called %d times, want at least 1", got)
	}
}

// TestGRPCDialControl covers the custom gRPC dialer installed when a hook is
// present. gRPC dials lazily, so the health check trigger is required.
func TestGRPCDialControl(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	grpc_health_v1.RegisterHealthServer(server, dialControlHealthServer{})
	go func() { _ = server.Serve(lis) }()
	defer server.Stop()

	var calls atomic.Int32
	e := newEngineForDialControl(t, dialControlScenario("http://"+lis.Addr().String()), allowDialControl(&calls))
	res, _ := e.grpcClient(context.Background(), lis.Addr().String(), time.Second)
	if res.status != http.StatusOK {
		t.Fatalf("grpc health status = %d, want 200", res.status)
	}
	if got := calls.Load(); got < 1 {
		t.Fatalf("gRPC dial control called %d times, want at least 1", got)
	}
}

type dialControlHealthServer struct {
	grpc_health_v1.UnimplementedHealthServer
}

func (dialControlHealthServer) Check(context.Context, *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	return &grpc_health_v1.HealthCheckResponse{Status: grpc_health_v1.HealthCheckResponse_SERVING}, nil
}

// TestNewDelegatesDialControl verifies the backward-compatible constructors:
// New must still work, and the stored hook must be the one passed in.
func TestNewDelegatesDialControl(t *testing.T) {
	sc := dialControlScenario("http://127.0.0.1:1")
	plain, err := New(sc)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if plain.dialControl != nil {
		t.Fatal("New installed a dial control")
	}

	control := allowDialControl(&atomic.Int32{})
	controlled, err := NewWithControl(dialControlScenario("http://127.0.0.1:1"), control)
	if err != nil {
		t.Fatalf("NewWithControl: %v", err)
	}
	if controlled.dialControl == nil {
		t.Fatal("NewWithControl did not store the dial control")
	}
}
