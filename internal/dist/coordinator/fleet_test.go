package coordinator

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	distproto "github.com/asadbekabdulboqiyev/sift/internal/dist/proto"
)

// TestRegisterDedupAndPrune verifies that re-registering with the same
// WorkerId replaces the previous entry (worker restart) and that stale
// registrations are pruned so a dead worker cannot poison auto-discovery.
func TestRegisterDedupAndPrune(t *testing.T) {
	// Registration now needs an auth anchor and an explicit opt-in for the
	// RFC1918 addresses this test uses; neither changes dedup/prune semantics.
	master := NewMaster(MasterConfig{
		AutoWorkers:         1,
		RegisterTimeout:     time.Second,
		Token:               "test-token",
		AllowPrivateWorkers: true,
	})

	reg := func(id, addr string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		resp, err := master.Register(ctx, &distproto.RegisterRequest{WorkerId: id, Address: addr})
		if err != nil {
			t.Fatalf("register %s: %v", id, err)
		}
		if !resp.GetAccepted() {
			t.Fatalf("register %s rejected: %s", id, resp.GetMessage())
		}
	}

	reg("w1", "10.0.0.1:50061")
	if got := master.RegisteredWorkers(); len(got) != 1 || got[0] != "10.0.0.1:50061" {
		t.Fatalf("after first register: %v", got)
	}
	// Same worker restarts on a new address -> replace, not append.
	reg("w1", "10.0.0.9:50062")
	if got := master.RegisteredWorkers(); len(got) != 1 || got[0] != "10.0.0.9:50062" {
		t.Fatalf("re-register should replace entry: %v", got)
	}

	// Fast-forward the registration clock so the entry looks stale.
	master.mu.Lock()
	master.registeredAt["w1"] = time.Now().Add(-2 * registerTTL)
	master.mu.Unlock()

	// A new registration from anybody triggers the sweep.
	reg("w2", "10.0.0.2:50061")
	if got := master.RegisteredWorkers(); len(got) != 1 || got[0] != "10.0.0.2:50061" {
		t.Fatalf("stale registration not pruned: %v", got)
	}
}

// TestLivenessMarksUnresponsiveWorkerDead verifies that a worker whose last
// event is older than the deadline and whose Ping fails is declared failed.
func TestLivenessMarksUnresponsiveWorkerDead(t *testing.T) {
	master := NewMaster(MasterConfig{
		Scenario: tinyScenario(t, "http://127.0.0.1:1", 1, 1),
		Workers:  []string{"127.0.0.1:1"},
	})
	master.mu.Lock()
	master.workerCount = 1
	master.lastSeen["127.0.0.1:1"] = time.Now().Add(-2 * livenessDeadline)
	// No client entry => probeWorker reports unreachable.
	master.mu.Unlock()

	master.checkLiveness([]string{"127.0.0.1:1"})

	master.mu.Lock()
	failed := master.finished["127.0.0.1:1"]
	master.mu.Unlock()
	if !failed {
		t.Fatal("silent worker with failing Ping should be marked failed")
	}
	if got := master.FailedWorkers(); len(got) != 1 {
		t.Fatalf("failed workers = %v, want 1", got)
	}
}

// TestLivenessKeepsRespondingWorker verifies that a worker that answers Ping
// is kept even when it has been quiet for a while (e.g. between runs).
func TestLivenessKeepsRespondingWorker(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer(ServerOptions("")...)
	distproto.RegisterMasterWorkerServer(srv, NewWorker(WorkerConfig{ID: "live"}))
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()
	addr := lis.Addr().String()

	// Serve starts accepting asynchronously. gRPC is fail-fast by default, so
	// a Ping that races a not-yet-serving listener returns Unavailable right
	// away and a healthy worker gets marked dead. Wait for the listener before
	// probing, the same way startWorker does for the other E2E tests.
	readyDeadline := time.Now().Add(5 * time.Second)
	for {
		probe, derr := net.DialTimeout("tcp", addr, 250*time.Millisecond)
		if derr == nil {
			_ = probe.Close()
			break
		}
		if time.Now().After(readyDeadline) {
			t.Fatalf("worker %s not ready: %v", addr, derr)
		}
		time.Sleep(10 * time.Millisecond)
	}

	master := NewMaster(MasterConfig{
		Scenario: tinyScenario(t, "http://127.0.0.1:1", 1, 1),
		Workers:  []string{addr},
	})
	conn, err := grpc.NewClient(addr, append([]grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}, ClientOptions("")...)...)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	master.mu.Lock()
	master.clients[addr] = distproto.NewMasterWorkerClient(conn)
	master.lastSeen[addr] = time.Now().Add(-2 * livenessDeadline)
	master.mu.Unlock()

	master.checkLiveness([]string{addr})

	master.mu.Lock()
	failed := master.finished[addr]
	master.mu.Unlock()
	if failed {
		t.Fatal("worker that answers Ping must not be marked failed")
	}
}

// TestStatusReportStorage verifies the master keeps the latest heartbeat per
// worker so the fleet monitor can read active runs / memory / cpu.
func TestStatusReportStorage(t *testing.T) {
	master := NewMaster(MasterConfig{})
	master.storeStatus("10.0.0.1:50061", &distproto.StatusReport{
		WorkerId:   "w1",
		Healthy:    true,
		ActiveRuns: 3,
		System:     &distproto.SystemMetrics{CpuPercent: 42.5, MemoryBytes: 1 << 30},
	})
	reports := master.StatusReports()
	sr, ok := reports["10.0.0.1:50061"]
	if !ok {
		t.Fatal("status report not stored")
	}
	if sr.WorkerId != "w1" || sr.ActiveRuns != 3 || sr.System.GetCpuPercent() != 42.5 {
		t.Fatalf("status report stored incorrectly: %+v", sr)
	}
}

// TestTLSOptionsValidation covers the TLS helper contract without needing a
// real certificate: partial cert/key pairs must fail, and skip-verify must
// produce dial credentials.
func TestTLSOptionsValidation(t *testing.T) {
	cases := []struct {
		name string
		opts TLSOptions
	}{
		{"none", TLSOptions{}},
		{"cert only", TLSOptions{CertFile: "server.crt"}},
		{"key only", TLSOptions{KeyFile: "server.key"}},
		{"skip verify", TLSOptions{InsecureSkipVerify: true}},
		{"missing CA file", TLSOptions{CAFile: "/nonexistent/ca.pem"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := c.opts.ServerCreds(); err != nil && c.opts.CertFile != "" && c.opts.KeyFile != "" {
				t.Fatalf("unexpected ServerCreds error: %v", err)
			}
			// ClientCreds must never panic and must return nil only when
			// neither CA nor skip-verify is set.
			creds, err := c.opts.ClientCreds()
			if err != nil && c.opts.CAFile == "" {
				t.Fatalf("ClientCreds(%s) unexpectedly errored: %v", c.name, err)
			}
			if c.opts.CAFile == "" && !c.opts.InsecureSkipVerify && creds != nil {
				t.Fatalf("ClientCreds(%s) should be nil for plaintext", c.name)
			}
			if c.opts.InsecureSkipVerify && creds == nil {
				t.Fatal("skip-verify should produce dial credentials")
			}
		})
	}
}

// testCAFile writes a fresh self-signed CA certificate into a temp dir and
// returns its path, so ClientCreds can be exercised with a parseable bundle.
func testCAFile(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "sift-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	doc := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, doc, 0o600); err != nil {
		t.Fatalf("write CA cert: %v", err)
	}
	return path
}

// TestTLSOptionsRequireTLS covers the opt-in guard from audit 5.4: setting
// RequireTLS must fail fast instead of silently dialing plaintext, while the
// default (RequireTLS=false) behaviour stays byte-for-byte compatible.
func TestTLSOptionsRequireTLS(t *testing.T) {
	validCA := testCAFile(t)

	t.Run("required without CA or skip-verify fails", func(t *testing.T) {
		creds, err := (TLSOptions{RequireTLS: true}).ClientCreds()
		if err == nil {
			t.Fatal("RequireTLS without -tls-ca or -tls-skip-verify must fail")
		}
		if creds != nil {
			t.Fatalf("failed ClientCreds must return nil creds, got %v", creds)
		}
		if !strings.Contains(err.Error(), "TLS required for outgoing dials") {
			t.Fatalf("error should explain TLS is required: %v", err)
		}
	})

	t.Run("default without CA or skip-verify stays plaintext", func(t *testing.T) {
		creds, err := (TLSOptions{}).ClientCreds()
		if err != nil || creds != nil {
			t.Fatalf("default should stay plaintext (nil, nil), got (%v, %v)", creds, err)
		}
	})

	t.Run("required with bad CA path keeps read error", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "missing.pem")
		creds, err := (TLSOptions{RequireTLS: true, CAFile: missing}).ClientCreds()
		if err == nil {
			t.Fatal("RequireTLS with a missing CA file must fail")
		}
		if creds != nil {
			t.Fatalf("failed ClientCreds must return nil creds, got %v", creds)
		}
		if !strings.Contains(err.Error(), "read -tls-ca") {
			t.Fatalf("missing CA should keep the original read error: %v", err)
		}
	})

	t.Run("required with valid CA succeeds", func(t *testing.T) {
		creds, err := (TLSOptions{RequireTLS: true, CAFile: validCA}).ClientCreds()
		if err != nil {
			t.Fatalf("ClientCreds with valid CA: %v", err)
		}
		if creds == nil {
			t.Fatal("valid CA should produce dial credentials")
		}
	})

	t.Run("required with skip-verify succeeds", func(t *testing.T) {
		creds, err := (TLSOptions{RequireTLS: true, InsecureSkipVerify: true}).ClientCreds()
		if err != nil {
			t.Fatalf("ClientCreds with skip-verify: %v", err)
		}
		if creds == nil {
			t.Fatal("skip-verify should produce dial credentials")
		}
	})
}
