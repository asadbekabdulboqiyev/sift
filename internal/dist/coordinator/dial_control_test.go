package coordinator

// dial_control_test.go — DNS-rebinding coverage for discovered-worker dials.
//
// The registration check and gatedDialWorker's re-check are snapshots: DNS can
// answer differently when connect(2) actually runs. The socket-level Control
// hook is the enforcement point. These tests pin that the hook is installed on
// every retry, that it sees the real connected peer (not the pre-check answer),
// and that static --workers entries deliberately keep the plain dial.

import (
	"context"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc"

	distproto "github.com/asadbekabdulboqiyev/sift/internal/dist/proto"
)

// TestGatedDialInstallsPolicyControlOnEveryAttempt proves the controlled seam
// is used for every retry and that the hook being installed is the worker
// address policy's own hook (not an arbitrary non-nil function).
func TestGatedDialInstallsPolicyControlOnEveryAttempt(t *testing.T) {
	prevControlled, prevBudget, prevDelay, prevAttempt := dialTCPWithControl, dialRetryBudget, dialRetryDelay, dialAttemptTimeout
	t.Cleanup(func() {
		dialTCPWithControl, dialRetryBudget, dialRetryDelay, dialAttemptTimeout = prevControlled, prevBudget, prevDelay, prevAttempt
	})
	dialRetryBudget = time.Second
	dialRetryDelay = time.Millisecond
	dialAttemptTimeout = 50 * time.Millisecond

	var mu sync.Mutex
	var controls []dialControlFunc
	dialTCPWithControl = func(_ context.Context, _ string, control dialControlFunc) (net.Conn, error) {
		mu.Lock()
		controls = append(controls, control)
		n := len(controls)
		mu.Unlock()
		if n < 3 {
			return nil, dialError(syscall.EADDRNOTAVAIL)
		}
		c1, c2 := net.Pipe()
		_ = c2.Close()
		return c1, nil
	}

	// A private literal needs the opt-in to get past the snapshot check.
	master := NewMaster(MasterConfig{AllowPrivateWorkers: true})
	conn, err := master.gatedDialWorker(context.Background(), "10.0.0.1:50051")
	if err != nil {
		t.Fatalf("gatedDialWorker: %v", err)
	}
	_ = conn.Close()

	mu.Lock()
	defer mu.Unlock()
	if len(controls) != 3 {
		t.Fatalf("expected 3 controlled attempts, got %d", len(controls))
	}
	for i, control := range controls {
		if control == nil {
			t.Fatalf("attempt %d installed a nil control", i)
		}
	}
	if err := controls[0]("tcp", "169.254.169.254:443", nil); err == nil {
		t.Fatal("installed control accepts metadata even though the policy denies it")
	}
	if err := controls[0]("tcp", "8.8.8.8:443", nil); err != nil {
		t.Fatalf("installed control rejects an approved public peer: %v", err)
	}
}

// stubRebindTarget makes the dial land on listener while the policy check saw
// the approved literal. It is the injectable "DNS changed" seam; production
// leaves workerDialTarget nil and net.Dialer resolves normally.
func stubRebindTarget(t *testing.T, listener net.Listener) {
	t.Helper()
	prev := workerDialTarget
	workerDialTarget = func(context.Context, string) (string, error) {
		return listener.Addr().String(), nil
	}
	t.Cleanup(func() { workerDialTarget = prev })
}

// TestGatedDialRebindToBlockedPeerRefused is the regression test for the
// documented CWE-290 residual: the approved host is rebound to loopback between
// check() and connect(), and the socket hook must refuse it before connect(2).
func TestGatedDialRebindToBlockedPeerRefused(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split listener address: %v", err)
	}
	stubRebindTarget(t, listener)

	// A public literal passes check() with the default policy. The dial seam
	// then resolves it to loopback, which the default policy denies.
	approved := net.JoinHostPort("8.8.8.8", port)
	master := NewMaster(MasterConfig{})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = master.gatedDialWorker(ctx, approved)
	if err == nil {
		t.Fatal("rebound dial to a blocked peer succeeded")
	}
	if !strings.Contains(err.Error(), "refusing to connect") || !strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("socket hook did not refuse the real connected peer: %v", err)
	}

	// The hook ran before connect(2), so the listener must see no connection.
	accepted := make(chan struct{}, 1)
	go func() {
		conn, aerr := listener.Accept()
		if aerr == nil {
			_ = conn.Close()
			accepted <- struct{}{}
		}
	}()
	select {
	case <-accepted:
		t.Fatal("connection reached the listener despite the refused control")
	case <-time.After(50 * time.Millisecond):
	}
}

// TestGatedDialRebindToLoopbackAllowedWithOptIn guards the other half: with the
// private-address opt-in the same rebind reaches the listener, proving the
// refusal above comes from the socket hook and not from an unrelated failure.
func TestGatedDialRebindToLoopbackAllowedWithOptIn(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split listener address: %v", err)
	}
	stubRebindTarget(t, listener)

	master := NewMaster(MasterConfig{AllowPrivateWorkers: true})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := master.gatedDialWorker(ctx, net.JoinHostPort("8.8.8.8", port))
	if err != nil {
		t.Fatalf("rebound dial to an opted-in peer failed: %v", err)
	}
	_ = conn.Close()
}

// TestConnectControlSelection pins the split in Master.Connect: discovered
// workers get the policy Control hook, static --workers entries keep the plain
// dial (nil control) even when their address would fail the policy.
func TestConnectControlSelection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := grpc.NewServer(ServerOptions("")...)
	distproto.RegisterMasterWorkerServer(server, NewWorker(WorkerConfig{ID: "control-selection"}))
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()
	addr := listener.Addr().String()

	deadline := time.Now().Add(5 * time.Second)
	for {
		probe, derr := net.DialTimeout("tcp", addr, 250*time.Millisecond)
		if derr == nil {
			_ = probe.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("test worker not ready: %v", derr)
		}
		time.Sleep(10 * time.Millisecond)
	}

	prevControlled := dialTCPWithControl
	t.Cleanup(func() { dialTCPWithControl = prevControlled })
	var mu sync.Mutex
	var controls []dialControlFunc
	dialTCPWithControl = func(ctx context.Context, target string, control dialControlFunc) (net.Conn, error) {
		mu.Lock()
		controls = append(controls, control)
		mu.Unlock()
		return prevControlled(ctx, target, control)
	}

	assertSelection := func(name string, wantControl bool) {
		t.Helper()
		mu.Lock()
		got := append([]dialControlFunc(nil), controls...)
		controls = nil
		mu.Unlock()
		if len(got) == 0 {
			t.Fatalf("%s: no dial was attempted", name)
		}
		for i, control := range got {
			if (control != nil) != wantControl {
				t.Fatalf("%s: attempt %d control present = %v, want %v", name, i, control != nil, wantControl)
			}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	static := NewMaster(MasterConfig{Workers: []string{addr}, Logf: func(string, ...any) {}})
	defer static.Close()
	if healthy, cerr := static.Connect(ctx, []string{addr}); cerr != nil || len(healthy) != 1 {
		t.Fatalf("static connect: healthy=%v err=%v", healthy, cerr)
	}
	assertSelection("static worker", false)

	discovered := NewMaster(MasterConfig{AllowPrivateWorkers: true, Logf: func(string, ...any) {}})
	defer discovered.Close()
	if healthy, cerr := discovered.Connect(ctx, []string{addr}); cerr != nil || len(healthy) != 1 {
		t.Fatalf("discovered connect: healthy=%v err=%v", healthy, cerr)
	}
	assertSelection("discovered worker", true)
}
