package engine

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/asadbekabdulboqiyev/sift/internal/config"
)

// newWSEchoServer returns a WebSocket server echoing every frame back with an
// "echo:" prefix until the client disconnects.
func newWSEchoServer(t *testing.T) *httptest.Server {
	t.Helper()
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		for {
			mt, msg, err := c.ReadMessage()
			if err != nil {
				return
			}
			if err := c.WriteMessage(mt, append([]byte("echo:"), msg...)); err != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestWSBinaryFrame checks frame_type: binary round-trips binary payloads.
func TestWSBinaryFrame(t *testing.T) {
	srv := newWSEchoServer(t)
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	e := &Engine{}
	step := config.Step{Body: "\x00\x01\x02bin", FrameType: "binary"}
	res, body := e.wsClient(context.Background(), wsURL, step, map[string]string{}, 5*time.Second)
	if res.errName != "" {
		t.Fatalf("ws error: %s", res.errName)
	}
	if !strings.Contains(string(body), "\x00\x01\x02bin") {
		t.Errorf("body = %q, want echoed binary payload", string(body))
	}
}

// TestUDPAwaitResponse covers the UDP request-response mode.
func TestUDPAwaitResponse(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 1024)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := pc.WriteTo(append([]byte("resp:"), buf[:n]...), addr); err != nil {
				return
			}
		}
	}()

	step := config.Step{Body: "dgram", AwaitResponse: true}
	res, body := (&Engine{}).rawClient(context.Background(), "udp", pc.LocalAddr().String(), step, map[string]string{}, 5*time.Second)
	if res.errName != "" {
		t.Fatalf("udp error: %s", res.errName)
	}
	if !strings.Contains(string(body), "resp:dgram") {
		t.Errorf("body = %q, want resp:dgram", string(body))
	}
}

// TestGrpcCustomMethodInvoke exercises the generic unary invoke path against
// a live gRPC server using an unknown full method name; the server must reply
// Unimplemented, which the client maps into the 4xx family.
func TestGrpcCustomMethodInvoke(t *testing.T) {
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	grpcServer := grpc.NewServer()
	healthpb.RegisterHealthServer(grpcServer, healthServer)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(grpcServer.GracefulStop)

	target := "grpc://" + lis.Addr().String()
	e := &Engine{}
	step := config.Step{
		GrpcMethod: "/unknown.pkg.Service/DoThing",
		Headers:    map[string]string{"x-test": "1"},
		Body:       `{"ping":"pong"}`,
	}
	res, _ := e.grpcMethodClient(context.Background(), target, step, map[string]string{}, 5*time.Second)
	if res.errName == "" {
		t.Fatal("expected an error for an unimplemented method")
	}
	if res.errName != errStatus4xx {
		t.Errorf("errName = %q, want %q (Unimplemented mapped to 4xx)", res.errName, errStatus4xx)
	}
}

// TestGrpcSharedConnReuse verifies that repeated calls reuse one pooled
// ClientConn instead of dialing per call.
func TestGrpcSharedConnReuse(t *testing.T) {
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	grpcServer := grpc.NewServer()
	healthpb.RegisterHealthServer(grpcServer, healthServer)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(grpcServer.GracefulStop)

	host, _, err := splitGRPCTarget(lis.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{keepAlive: true}
	for i := 0; i < 5; i++ {
		if res, _ := e.grpcClient(context.Background(), lis.Addr().String(), 5*time.Second); res.errName != "" {
			t.Fatalf("call %d failed: %s", i, res.errName)
		}
	}
	e.sessMu.Lock()
	n := len(e.grpcConns)
	e.sessMu.Unlock()
	if n != 1 {
		t.Errorf("pooled connections = %d, want exactly 1 after 5 calls", n)
	}
	_ = host // silence unused in case of refactors
}

// TestHTTP2TransportEnabled asserts the transport still attempts HTTP/2 so
// h2-capable targets benefit from multiplexing.
func TestHTTP2TransportEnabled(t *testing.T) {
	tr := newTransport(true, 256, "")
	if !tr.ForceAttemptHTTP2 {
		t.Error("ForceAttemptHTTP2 = false, want true")
	}
	if tr.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("TLS MinVersion = %x, want 0303 (TLS 1.2)", tr.TLSClientConfig.MinVersion)
	}
	//nolint:staticcheck // Deliberate no-op: keeps x/net/http2 linked for h2 upgrades; net/http.Transport would not.
	_ = http2.Transport{} // ensure dependency stays linked for h2 upgrades
}

// TestFingerprintTransportConfiguresDialer asserts that requesting a TLS
// fingerprint swaps the standard dialer for a uTLS-backed one, and that a
// plain (default) profile keeps the built-in dialer — so the extra layer only
// exists when explicitly asked for.
func TestFingerprintTransportConfiguresDialer(t *testing.T) {
	plain := newTransport(true, 256, "")
	if plain.DialTLSContext != nil {
		t.Fatal("default profile must not install a custom DialTLSContext")
	}
	fp := newTransport(true, 256, "chrome")
	if fp.DialTLSContext == nil {
		t.Fatal("chrome profile must install a uTLS-backed DialTLSContext")
	}
	if fp.ForceAttemptHTTP2 {
		t.Fatal("fingerprinted transport must pin HTTP/1.1 so Go's transport cannot misread the negotiated protocol")
	}
}
