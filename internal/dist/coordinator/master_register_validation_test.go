package coordinator

// master_register_validation_test.go — the control-plane registration gate.
//
// Register is an unauthenticated gRPC method when no token is configured, and
// its Address used to flow unchecked into the master's dial list. These tests
// pin both halves of the fix: where a worker may live, and whether Register is
// allowed at all without an authentication anchor.

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/asadbekabdulboqiyev/sift/internal/attest"
	distproto "github.com/asadbekabdulboqiyev/sift/internal/dist/proto"
)

func registerCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// TestRegisterRejectsUnsafeAddressesByDefault proves the default deny list.
// A token is configured so the address policy, not the auth gate, is under
// test; without it every case would be rejected for an unrelated reason.
func TestRegisterRejectsUnsafeAddressesByDefault(t *testing.T) {
	cases := []struct {
		name    string
		addr    string
		wantMsg string
	}{
		{"loopback", "127.0.0.1:50051", "loopback"},
		{"rfc1918", "10.0.0.7:50051", "private"},
		{"link-local", "169.254.10.20:50051", "link-local"},
		{"metadata", "169.254.169.254:50051", "metadata"},
		{"cgnat", "100.64.0.1:50051", "cgnat"},
		{"multicast", "224.0.0.1:50051", "multicast"},
		{"reserved", "192.0.2.1:50051", "reserved"},
		{"missing port", "8.8.8.8", "host:port"},
		{"empty host", ":50051", "empty host"},
		{"empty port", "8.8.8.8:", "no port"},
		{"nonnumeric port", "8.8.8.8:http", "invalid port"},
		{"zero port", "8.8.8.8:0", "invalid port"},
	}
	master := NewMaster(MasterConfig{Token: "test-token"})
	ctx := registerCtx(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := master.Register(ctx, &distproto.RegisterRequest{WorkerId: "bad-" + tc.name, Address: tc.addr})
			if err != nil {
				t.Fatalf("Register: %v", err)
			}
			if resp.GetAccepted() {
				t.Fatalf("unsafe address %q was accepted", tc.addr)
			}
			if !strings.Contains(resp.GetMessage(), tc.wantMsg) {
				t.Fatalf("message %q does not explain %s rejection", resp.GetMessage(), tc.wantMsg)
			}
			if got := master.RegisteredWorkers(); len(got) != 0 {
				t.Fatalf("rejected registration was stored: %v", got)
			}
		})
	}
}

// TestRegisterAcceptsPublicAddressByDefault keeps the ordinary deployment
// working: a publicly reachable worker needs no operator opt-in.
func TestRegisterAcceptsPublicAddressByDefault(t *testing.T) {
	master := NewMaster(MasterConfig{Token: "test-token"})
	resp, err := master.Register(registerCtx(t), &distproto.RegisterRequest{
		WorkerId: "public-w1",
		Address:  "8.8.8.8:50051",
	})
	if err != nil || !resp.GetAccepted() {
		t.Fatalf("public registration rejected: accepted=%v err=%v msg=%s", resp.GetAccepted(), err, resp.GetMessage())
	}
	if got := master.RegisteredWorkers(); len(got) != 1 || got[0] != "8.8.8.8:50051" {
		t.Fatalf("registered workers = %v", got)
	}
}

// TestRegisterPrivateRequiresOptIn pins the behavior change: loopback and
// RFC1918 are refused by default, and only --allow-private-workers (surfaced
// as AllowPrivateWorkers) makes them acceptable.
func TestRegisterPrivateRequiresOptIn(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:50051", "10.20.30.40:50051"} {
		t.Run(addr, func(t *testing.T) {
			closed := NewMaster(MasterConfig{Token: "test-token"})
			resp, err := closed.Register(registerCtx(t), &distproto.RegisterRequest{WorkerId: "closed", Address: addr})
			if err != nil || resp.GetAccepted() {
				t.Fatalf("private address accepted by default: accepted=%v err=%v", resp.GetAccepted(), err)
			}
			if !strings.Contains(resp.GetMessage(), "--allow-private-workers") {
				t.Fatalf("message should name the opt-in flag: %q", resp.GetMessage())
			}

			open := NewMaster(MasterConfig{Token: "test-token", AllowPrivateWorkers: true})
			resp, err = open.Register(registerCtx(t), &distproto.RegisterRequest{WorkerId: "opted-in", Address: addr})
			if err != nil || !resp.GetAccepted() {
				t.Fatalf("opted-in registration rejected: accepted=%v err=%v msg=%s", resp.GetAccepted(), err, resp.GetMessage())
			}
		})
	}
}

// TestRegisterFailsClosedWithoutAuthAnchor removes the original anonymous
// arbitrary-address path: no token, no pins and no attestation means no self
// registration at all, even for a public address.
func TestRegisterFailsClosedWithoutAuthAnchor(t *testing.T) {
	const addr = "8.8.8.8:50051"

	resp, err := NewMaster(MasterConfig{}).Register(registerCtx(t), &distproto.RegisterRequest{WorkerId: "anon", Address: addr})
	if err != nil || resp.GetAccepted() {
		t.Fatalf("unauthenticated registration accepted: accepted=%v err=%v", resp.GetAccepted(), err)
	}
	if !strings.Contains(resp.GetMessage(), "registration is disabled") {
		t.Fatalf("message should explain the fail-closed default: %q", resp.GetMessage())
	}

	// Requiring attestation without pinning any key is not a usable anchor:
	// there is no public key to verify a proof against, so this must also fail.
	resp, err = NewMaster(MasterConfig{RequireWorkerAttestation: true}).Register(registerCtx(t), &distproto.RegisterRequest{WorkerId: "anon", Address: addr})
	if err != nil || resp.GetAccepted() {
		t.Fatalf("unverifiable attestation accepted registration: accepted=%v err=%v", resp.GetAccepted(), err)
	}
}

// TestRegisterPinnedAttestedWorkerStillRegisters proves the legitimate
// attested path survives both new gates: a challenge is issued, the pinned key
// signs it, and the public endpoint is stored.
func TestRegisterPinnedAttestedWorkerStillRegisters(t *testing.T) {
	const id = "w1"
	const addr = "8.8.8.8:50051"
	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	master := NewMaster(MasterConfig{AuthorizedWorkers: map[string]string{id: attest.PublicKeyHex(kp.Public)}})
	ctx := registerCtx(t)

	first, err := master.Register(ctx, &distproto.RegisterRequest{WorkerId: id, Address: addr})
	if err != nil || first.GetAccepted() || len(first.GetChallenge()) == 0 {
		t.Fatalf("expected a challenge: accepted=%v challenge=%d err=%v", first.GetAccepted(), len(first.GetChallenge()), err)
	}
	sig, err := SignRegistration(kp, id, addr, first.GetChallenge())
	if err != nil {
		t.Fatalf("sign challenge: %v", err)
	}
	resp, err := master.Register(ctx, &distproto.RegisterRequest{WorkerId: id, Address: addr, Signature: sig})
	if err != nil || !resp.GetAccepted() {
		t.Fatalf("attested worker rejected: accepted=%v err=%v msg=%s", resp.GetAccepted(), err, resp.GetMessage())
	}
	if got := master.RegisteredWorkers(); len(got) != 1 || got[0] != addr {
		t.Fatalf("registered workers = %v", got)
	}
}

// TestStaticWorkersDialPathUnaffected guards the operator-configured fleet:
// a static loopback worker is still dialed with no token, no pins and no
// private-address opt-in, because that address was chosen by the operator.
func TestStaticWorkersDialPathUnaffected(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer(ServerOptions("")...)
	distproto.RegisterMasterWorkerServer(srv, NewWorker(WorkerConfig{ID: "static"}))
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()
	addr := lis.Addr().String()

	deadline := time.Now().Add(5 * time.Second)
	for {
		probe, derr := net.DialTimeout("tcp", addr, 250*time.Millisecond)
		if derr == nil {
			_ = probe.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("static worker not ready: %v", derr)
		}
		time.Sleep(10 * time.Millisecond)
	}

	master := NewMaster(MasterConfig{
		Workers: []string{addr},
		Logf:    func(string, ...any) {},
	})
	defer master.Close()
	healthy, err := master.Connect(registerCtx(t), []string{addr})
	if err != nil || len(healthy) != 1 || healthy[0] != addr {
		t.Fatalf("static worker dial broken: healthy=%v err=%v", healthy, err)
	}
}

// TestReregistrationReplacesEntry keeps the worker-restart contract: the new
// address replaces the old one and auto-discovery still sees a single worker.
func TestReregistrationReplacesEntry(t *testing.T) {
	master := NewMaster(MasterConfig{Token: "test-token", AllowPrivateWorkers: true})
	ctx := registerCtx(t)
	for _, addr := range []string{"10.0.0.1:50051", "10.0.0.9:50052"} {
		resp, err := master.Register(ctx, &distproto.RegisterRequest{WorkerId: "w1", Address: addr})
		if err != nil || !resp.GetAccepted() {
			t.Fatalf("register %s: accepted=%v err=%v msg=%s", addr, resp.GetAccepted(), err, resp.GetMessage())
		}
	}
	if got := master.RegisteredWorkers(); len(got) != 1 || got[0] != "10.0.0.9:50052" {
		t.Fatalf("re-registration did not replace entry: %v", got)
	}
}

// TestRegisterRateLimitedPerSource checks the flood brake is real and scoped:
// one source exhausts its window while a different worker id gets its own.
func TestRegisterRateLimitedPerSource(t *testing.T) {
	master := NewMaster(MasterConfig{Token: "test-token"})
	ctx := registerCtx(t)
	for i := 0; i < registerRateLimit; i++ {
		resp, err := master.Register(ctx, &distproto.RegisterRequest{WorkerId: "flood", Address: "8.8.8.8:50051"})
		if err != nil || !resp.GetAccepted() {
			t.Fatalf("attempt %d unexpectedly rejected: accepted=%v err=%v msg=%s", i, resp.GetAccepted(), err, resp.GetMessage())
		}
	}
	resp, err := master.Register(ctx, &distproto.RegisterRequest{WorkerId: "flood", Address: "8.8.8.8:50051"})
	if err != nil || resp.GetAccepted() || !strings.Contains(resp.GetMessage(), "too many registration attempts") {
		t.Fatalf("flood not limited: accepted=%v err=%v msg=%s", resp.GetAccepted(), err, resp.GetMessage())
	}
	resp, err = master.Register(ctx, &distproto.RegisterRequest{WorkerId: "other", Address: "8.8.8.8:50051"})
	if err != nil || !resp.GetAccepted() {
		t.Fatalf("separate source should have its own budget: accepted=%v err=%v msg=%s", resp.GetAccepted(), err, resp.GetMessage())
	}
}

// TestGatedDialWorkerRechecksAtConnectTime proves the defense in depth: a
// blocked address reaching Connect through a race is refused before any
// socket is created, and the opt-in lets the same address through.
func TestGatedDialWorkerRechecksAtConnectTime(t *testing.T) {
	calls := stubDial(t, func(context.Context, string) (net.Conn, error) {
		return nil, errors.New("stub dial reached")
	})

	closed := NewMaster(MasterConfig{})
	_, err := closed.gatedDialWorker(context.Background(), "10.0.0.1:50051")
	if err == nil || !strings.Contains(err.Error(), "private") {
		t.Fatalf("blocked address should fail the policy: %v", err)
	}
	if got := atomic.LoadInt32(calls); got != 0 {
		t.Fatalf("blocked address reached the socket dialer %d time(s)", got)
	}

	open := NewMaster(MasterConfig{AllowPrivateWorkers: true})
	_, err = open.gatedDialWorker(context.Background(), "10.0.0.1:50051")
	if err == nil || err.Error() != "stub dial reached" {
		t.Fatalf("opted-in address should reach the dialer, got %v", err)
	}
	if got := atomic.LoadInt32(calls); got != 1 {
		t.Fatalf("expected one dial after opt-in, got %d", got)
	}
}
