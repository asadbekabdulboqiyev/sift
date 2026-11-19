package engine

// dialcontrol_engine_test.go pins the engine side of SEC-A360-01: every socket
// the engine opens must pass through the authorization hook supplied by the
// caller. The hook runs at dial time, after name resolution, so it can refuse
// an address that differs from the one the policy check originally approved.

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"

	"github.com/asadbekabdulboqiyev/sift/internal/config"
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
	_, err := e.client.Get(srv.URL)
	if err == nil {
		t.Fatal("request succeeded although the dial control refused it")
	}
	if !strings.Contains(err.Error(), errTestDialRefused.Error()) {
		t.Fatalf("error = %v, want the dial control refusal", err)
	}
	if got := calls.Load(); got < 1 {
		t.Fatalf("HTTP dial control called %d times, want at least 1", got)
	}
}

// TestUTLSTransportDialControl verifies the uTLS DialTLSContext path. The test
// server uses a self-signed certificate, so the handshake may fail, but the
// socket-level hook must still run before that handshake and a refusal must
// surface as the request error.
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
