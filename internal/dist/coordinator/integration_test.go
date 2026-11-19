package coordinator

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/asadbekabdulboqiyev/sift/internal/config"
	distproto "github.com/asadbekabdulboqiyev/sift/internal/dist/proto"
)

func startWorker(t *testing.T, cfg WorkerConfig) (string, *grpc.Server) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer(ServerOptions(cfg.Token)...)
	distproto.RegisterMasterWorkerServer(srv, NewWorker(cfg))
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	addr := lis.Addr().String()
	// Serve starts accepting asynchronously; wait until Ping succeeds so
	// callers (and Connect in tests) don't race a not-yet-ready server,
	// which can flake as "no reachable workers" under load/port churn.
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := grpc.NewClient(addr, append([]grpc.DialOption{
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		}, ClientOptions(cfg.Token)...)...)
		if err == nil {
			client := distproto.NewMasterWorkerClient(conn)
			ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
			_, pingErr := client.Ping(ctx, &distproto.PingRequest{})
			cancel()
			_ = conn.Close()
			if pingErr == nil {
				break
			}
			err = pingErr
		}
		if time.Now().After(deadline) {
			t.Fatalf("worker %s not ready: %v", addr, err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	return addr, srv
}

func tinyScenario(t *testing.T, url string, users, duration int) *config.Scenario {
	t.Helper()
	sc := &config.Scenario{
		Name: "it",
		Profile: config.Profile{
			Type:     "steady",
			Users:    users,
			Duration: duration,
			Timeout:  5,
			// Paced on purpose. These tests assert coordinator semantics
			// (aggregation, timeout grace, worker loss), not throughput. An
			// unpaced loopback run opens tens of thousands of connections in
			// ~10 s, exhausts this host's 16 384-port ephemeral range
			// (measured), and then every test on the host — including
			// unrelated packages — fails at connect(2) with EADDRNOTAVAIL.
			// 100 req/s keeps real concurrency and in-flight requests while
			// staying far below that ceiling.
			RPS: 100,
		},
		Steps: []config.Step{{Name: "req", Method: "GET", URL: url}},
	}
	if err := sc.Normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	return sc
}

func TestMasterAutoDiscovery(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	addr, _ := startWorker(t, WorkerConfig{ID: "auto1", MaxUsers: 100})

	// Worker registers itself with the master via the Register RPC.
	master := NewMaster(MasterConfig{
		Scenario:        tinyScenario(t, target.URL, 2, 1),
		AutoWorkers:     1,
		RegisterTimeout: 5 * time.Second,
	})
	defer master.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := grpc.NewClient(addr, append([]grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}, ClientOptions("")...)...)
	if err != nil {
		t.Fatalf("dial worker: %v", err)
	}
	defer conn.Close()

	// Register through a directly constructed master server.
	serverLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer(ServerOptions("")...)
	distproto.RegisterMasterWorkerServer(srv, master)
	go func() { _ = srv.Serve(serverLis) }()
	defer srv.Stop()

	mconn, err := grpc.NewClient(serverLis.Addr().String(), append([]grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}, ClientOptions("")...)...)
	if err != nil {
		t.Fatalf("dial master: %v", err)
	}
	defer mconn.Close()
	if _, err := distproto.NewMasterWorkerClient(mconn).Register(ctx, &distproto.RegisterRequest{
		WorkerId: "auto1",
		Address:  addr,
	}); err != nil {
		t.Fatalf("register: %v", err)
	}

	resolved, err := master.ResolveWorkers(ctx)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(resolved) != 1 || resolved[0] != addr {
		t.Fatalf("expected [%s], got %v", addr, resolved)
	}
}

func TestAuthTokenEnforced(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer target.Close()

	addr, _ := startWorker(t, WorkerConfig{ID: "secured", Token: "s3cr3t"})

	// Wrong token: worker rejects Ping, so Connect reports no reachable workers.
	wrong := NewMaster(MasterConfig{Scenario: tinyScenario(t, target.URL, 1, 1), Workers: []string{addr}, Token: "wrong"})
	defer wrong.Close()
	if _, err := wrong.Connect(context.Background(), []string{addr}); err == nil {
		t.Fatal("expected connect to fail with wrong token")
	}

	// Correct token succeeds.
	right := NewMaster(MasterConfig{Scenario: tinyScenario(t, target.URL, 1, 1), Workers: []string{addr}, Token: "s3cr3t"})
	defer right.Close()
	if _, err := right.Connect(context.Background(), []string{addr}); err != nil {
		t.Fatalf("connect with correct token: %v", err)
	}
}
