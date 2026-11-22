package coordinator

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/attest"

	distproto "github.com/asadbekabdulboqiyev/sift/internal/dist/proto"
)

// TestRegisterFailsClosedWhenPinned verifies the identity gate of the worker
// allowlist: when the coordinator has pinned worker identities, self-registration
// from an unpinned worker id must be rejected (fail closed), while a pinned id
// is accepted. An empty allowlist keeps the coordinator open (single-tenant /
// local development mode) and is therefore not a failure here.
func TestRegisterFailsClosedWhenPinned(t *testing.T) {
	const pinnedID = "w1"
	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	master := NewMaster(MasterConfig{AuthorizedWorkers: map[string]string{pinnedID: attest.PublicKeyHex(kp.Public)}})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if resp, err := master.Register(ctx, &distproto.RegisterRequest{WorkerId: "w2", Address: "10.0.0.9:50061"}); err != nil || resp.GetAccepted() {
		t.Fatalf("unpinned worker w2 must be rejected: accepted=%v err=%v", resp.GetAccepted(), err)
	}

	// Attested registration is a two-step handshake: an unsigned call only
	// obtains a challenge, and the pinned key must sign it to be accepted.
	first, err := master.Register(ctx, &distproto.RegisterRequest{WorkerId: pinnedID, Address: "10.0.0.1:50061"})
	if err != nil || first.GetAccepted() || len(first.GetChallenge()) == 0 {
		t.Fatalf("pinned worker must receive a challenge first: accepted=%v challenge=%d err=%v", first.GetAccepted(), len(first.GetChallenge()), err)
	}
	sig, err := coordinatorSignRegistrationForTest(kp, pinnedID, "10.0.0.1:50061", first.GetChallenge())
	if err != nil {
		t.Fatalf("sign challenge: %v", err)
	}
	resp, err := master.Register(ctx, &distproto.RegisterRequest{WorkerId: pinnedID, Address: "10.0.0.1:50061", Signature: sig})
	if err != nil || !resp.GetAccepted() {
		t.Fatalf("pinned worker %s must be accepted after proving key possession: accepted=%v err=%v msg=%s", pinnedID, resp.GetAccepted(), err, resp.GetMessage())
	}
}

// coordinatorSignRegistrationForTest builds the exact registration statement
// the worker signs (kept here so these tests mirror cmd/sift-worker).
func coordinatorSignRegistrationForTest(kp *attest.Keypair, id, addr string, challenge []byte) ([]byte, error) {
	return SignRegistration(kp, id, addr, challenge)
}

// TestRegisterAcceptsUnpinnedWhenAllowlistEmpty verifies the dev-mode default:
// with no allowlist configured, registration is open (the fleet is opted into
// pinning explicitly).
func TestRegisterAcceptsUnpinnedWhenAllowlistEmpty(t *testing.T) {
	master := NewMaster(MasterConfig{})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp, err := master.Register(ctx, &distproto.RegisterRequest{WorkerId: "w1", Address: "10.0.0.1:50061"})
	if err != nil || !resp.GetAccepted() {
		t.Fatalf("open mode must accept registration: accepted=%v err=%v", resp.GetAccepted(), err)
	}
}

// TestRegisterChallengeProofIsBoundAndOneTime pins the registration proof-of-
// possession hardening (F-1): a challenge may only be answered by the pinned
// key, only for the bound worker_id+address, before expiry, and only once.
func TestRegisterChallengeProofIsBoundAndOneTime(t *testing.T) {
	const id = "w1"
	const addr = "10.0.0.1:50061"
	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	other, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("other keypair: %v", err)
	}
	master := NewMaster(MasterConfig{AuthorizedWorkers: map[string]string{id: attest.PublicKeyHex(kp.Public)}})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	issue := func() []byte {
		t.Helper()
		resp, err := master.Register(ctx, &distproto.RegisterRequest{WorkerId: id, Address: addr})
		if err != nil || len(resp.GetChallenge()) == 0 {
			t.Fatalf("challenge issue failed: accepted=%v err=%v", resp.GetAccepted(), err)
		}
		return resp.GetChallenge()
	}

	// Wrong private key cannot satisfy the challenge.
	ch := issue()
	badSig, _ := SignRegistration(other, id, addr, ch)
	if resp, err := master.Register(ctx, &distproto.RegisterRequest{WorkerId: id, Address: addr, Signature: badSig}); err != nil || resp.GetAccepted() {
		t.Fatalf("forged registration proof accepted: %v err=%v", resp.GetAccepted(), err)
	}

	// Right key but a different address cannot reuse the challenge to register
	// a second endpoint.
	ch = issue()
	addrSig, _ := SignRegistration(kp, id, "10.9.9.9:50061", ch)
	if resp, err := master.Register(ctx, &distproto.RegisterRequest{WorkerId: id, Address: addr, Signature: addrSig}); err != nil || resp.GetAccepted() {
		t.Fatalf("registration proof not bound to address: accepted=%v err=%v", resp.GetAccepted(), err)
	}

	// An expired challenge is refused.
	ch = issue()
	master.mu.Lock()
	master.registerChallenges[id].expires = time.Now().Add(-time.Second)
	master.mu.Unlock()
	expSig, _ := SignRegistration(kp, id, addr, ch)
	if resp, err := master.Register(ctx, &distproto.RegisterRequest{WorkerId: id, Address: addr, Signature: expSig}); err != nil || resp.GetAccepted() {
		t.Fatalf("expired registration challenge accepted: accepted=%v err=%v", resp.GetAccepted(), err)
	}

	// A valid proof is accepted once, then cannot be replayed.
	ch = issue()
	goodSig, _ := SignRegistration(kp, id, addr, ch)
	if resp, err := master.Register(ctx, &distproto.RegisterRequest{WorkerId: id, Address: addr, Signature: goodSig}); err != nil || !resp.GetAccepted() {
		t.Fatalf("valid registration proof rejected: accepted=%v msg=%s err=%v", resp.GetAccepted(), resp.GetMessage(), err)
	}
	if resp, err := master.Register(ctx, &distproto.RegisterRequest{WorkerId: id, Address: addr, Signature: goodSig}); err != nil || resp.GetAccepted() {
		t.Fatalf("replayed registration proof accepted: accepted=%v err=%v", resp.GetAccepted(), err)
	}
}

// TestRunFailedRequiresAttestation pins failure-event hardening (F-2): in an
// attested fleet an unsigned, cross-run or forged failure must not terminate a
// run, while a correctly signed failure from the pinned identity is accepted.
func TestRunFailedRequiresAttestation(t *testing.T) {
	const id = "w1"
	const addr = "10.0.0.1:50061"
	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	other, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("other keypair: %v", err)
	}
	master := NewMaster(MasterConfig{AuthorizedWorkers: map[string]string{id: attest.PublicKeyHex(kp.Public)}})
	master.mu.Lock()
	master.runID = "run-1"
	master.mu.Unlock()
	const ts = int64(1700000000000)

	unsigned := &distproto.RunFailed{RunId: "run-1", Timestamp: ts, Error: "boom"}
	if master.handleRunFailed(addr, unsigned, nil) {
		t.Fatal("unsigned failure was accepted")
	}
	unsigned.WorkerId = id
	if master.handleRunFailed(addr, unsigned, nil) {
		t.Fatal("unsigned failure with a worker_id was accepted")
	}

	wrongRun := &distproto.RunFailed{RunId: "run-old", Timestamp: ts, Error: "boom", WorkerId: id}
	wrongRun.Signature, _ = SignFailure(kp, id, "run-old", ts, "boom")
	if master.handleRunFailed(addr, wrongRun, nil) {
		t.Fatal("signed failure from a different run was accepted")
	}

	forged := &distproto.RunFailed{RunId: "run-1", Timestamp: ts, Error: "boom", WorkerId: id}
	forged.Signature, _ = SignFailure(other, id, "run-1", ts, "boom")
	if master.handleRunFailed(addr, forged, nil) {
		t.Fatal("failure signed by the wrong key was accepted")
	}

	good := &distproto.RunFailed{RunId: "run-1", Timestamp: ts, Error: "boom", WorkerId: id}
	good.Signature, _ = SignFailure(kp, id, "run-1", ts, "boom")
	if !master.handleRunFailed(addr, good, nil) {
		t.Fatal("valid signed failure was rejected")
	}
	if bound, ok := master.boundWorkerID(addr); !ok || bound != id {
		t.Fatalf("accepted failure did not bind the worker identity: %q %v", bound, ok)
	}
}

// TestVerifyWorkerAttestation checks the Ed25519 half of worker attestation:
// a genuine signature from the pinned worker verifies, while a missing pin, a
// mismatched key or a tampered signature does not.
func TestVerifyWorkerAttestation(t *testing.T) {
	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	pub, priv := kp.Public, kp.Private
	pubHex := attest.PublicKeyHex(pub)
	master := NewMaster(MasterConfig{})
	if err := master.SetWorkerKey("w1", pubHex); err != nil {
		t.Fatalf("set worker key: %v", err)
	}

	msg := []byte("sift/worker-attest/v1\nworker=w1\nrun=demo\nreport=abc")
	sig, err := attest.Sign(&attest.Keypair{Private: priv}, msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if !master.VerifyWorkerAttestation("w1", pub, msg, sig) {
		t.Fatal("genuine worker attestation must verify against the pinned key")
	}

	if master.VerifyWorkerAttestation("w2", pub, msg, sig) {
		t.Fatal("unknown worker must not verify")
	}

	otherKP, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	otherPub := otherKP.Public
	otherSig, err := attest.Sign(otherKP, msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if master.VerifyWorkerAttestation("w1", otherPub, msg, otherSig) {
		t.Fatal("signature from a different key must not verify against the pinned worker")
	}

	tampered := append([]byte(nil), sig...)
	tampered[0] ^= 0xff
	if master.VerifyWorkerAttestation("w1", pub, msg, tampered) {
		t.Fatal("tampered signature must not verify")
	}

	if err := master.SetWorkerKey("w1", ""); err != nil {
		t.Fatalf("clear worker key: %v", err)
	}
	if master.VerifyWorkerAttestation("w1", pub, msg, sig) {
		t.Fatal("cleared pin must not verify")
	}
}

// TestSetWorkerKeyRejectsMalformedPin verifies that an operator-supplied
// malformed pin is rejected instead of poisoning the allowlist.
func TestSetWorkerKeyRejectsMalformedPin(t *testing.T) {
	master := NewMaster(MasterConfig{})
	if err := master.SetWorkerKey("w1", "not-hex"); err == nil {
		t.Fatal("malformed pin must be rejected")
	}
}

// TestWorkerAttestationKeySize is a guard on the stable attest key surface used
// by the coordinator's worker attestation path.
func TestWorkerAttestationKeySize(t *testing.T) {
	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	pub := kp.Public
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("ed25519 public key size = %d, want %d", len(pub), ed25519.PublicKeySize)
	}
}

// --- signature half of worker attestation -------------------------------
//
// The tests below drive the exact handler recvLoop uses (handleRunProgress /
// handleRunCompleted), so they cover the accept/reject decision without needing
// a fake gRPC stream. The two *_E2E tests at the bottom run the whole path over
// real gRPC streams.

// attestationTestMaster returns a master that requires signed telemetry and has
// kp's public key pinned under workerID.
func attestationTestMaster(t *testing.T, workerID string, kp *attest.Keypair) *Master {
	t.Helper()
	m := NewMaster(MasterConfig{
		RequireWorkerAttestation: true,
		Logf:                     func(string, ...any) {},
	})
	if err := m.SetWorkerKey(workerID, attest.PublicKeyHex(kp.Public)); err != nil {
		t.Fatalf("pin worker key: %v", err)
	}
	m.mu.Lock()
	m.workerCount = 1
	m.mu.Unlock()
	return m
}

// attestationTestSnapshot is a fully populated snapshot: maps, floats and steps
// all exercise the deterministic digest path, not just scalar fields.
func attestationTestSnapshot() *distproto.TelemetrySnapshot {
	return &distproto.TelemetrySnapshot{
		Timestamp:     1_700_000_000_000,
		ElapsedMs:     2_000,
		TotalRequests: 42,
		TotalErrors:   1,
		Rps:           21,
		ActiveUsers:   4,
		StatusCodes:   map[int32]int64{200: 41, 500: 1},
		ErrorTypes:    map[string]int64{"timeout": 1},
		Latency:       &distproto.LatencyPercentiles{P50Ms: 3, P95Ms: 9, P99Ms: 12, AvgMs: 5, MinMs: 1, MaxMs: 20},
		Steps:         []*distproto.StepTelemetry{{Name: "req", Requests: 42, Errors: 1}},
	}
}

// signedProgress builds the event a worker with kp emits for workerID.
func signedProgress(t *testing.T, kp *attest.Keypair, workerID, runID string, snap *distproto.TelemetrySnapshot) *distproto.RunProgress {
	t.Helper()
	ts := time.Now().UnixMilli()
	sig, err := SignProgress(kp, workerID, runID, ts, snap)
	if err != nil {
		t.Fatalf("sign progress: %v", err)
	}
	return &distproto.RunProgress{
		RunId:     runID,
		Timestamp: ts,
		Telemetry: snap,
		WorkerId:  workerID,
		Signature: sig,
	}
}

// TestAttestationRejectsFrameFromInactiveRun pins the replay-context guard: a
// correctly signed frame captured from an earlier run must not be accepted as
// this run's telemetry or final report.
func TestAttestationRejectsFrameFromInactiveRun(t *testing.T) {
	const (
		activeRun = "run-active"
		staleRun  = "run-stale"
	)

	t.Run("progress", func(t *testing.T) {
		kp, err := attest.GenerateKeypair()
		if err != nil {
			t.Fatalf("keypair: %v", err)
		}
		master := attestationTestMaster(t, "w1", kp)
		master.mu.Lock()
		master.runID = activeRun
		master.mu.Unlock()

		const staleAddr = "10.0.0.31:50061"
		stale := signedProgress(t, kp, "w1", staleRun, attestationTestSnapshot())
		if master.handleRunProgress(staleAddr, stale, nil) {
			t.Fatal("progress signed for an inactive run must be rejected")
		}
		if got := master.RejectedWorkers(); got[staleAddr] == "" {
			t.Fatalf("stale-run progress not recorded as rejected: %v", got)
		}

		const freshAddr = "10.0.0.32:50061"
		fresh := signedProgress(t, kp, "w1", activeRun, attestationTestSnapshot())
		if !master.handleRunProgress(freshAddr, fresh, nil) {
			t.Fatalf("progress signed for the active run must be accepted (rejected: %v)", master.RejectedWorkers())
		}
	})

	t.Run("report", func(t *testing.T) {
		kp, err := attest.GenerateKeypair()
		if err != nil {
			t.Fatalf("keypair: %v", err)
		}
		master := attestationTestMaster(t, "w1", kp)
		master.mu.Lock()
		master.runID = activeRun
		master.mu.Unlock()

		ts := time.Now().UnixMilli()
		staleReport := &distproto.Report{Name: "stale", TotalRequests: 10, Rps: 5}
		staleSig, err := SignReport(kp, "w1", staleRun, ts, staleReport)
		if err != nil {
			t.Fatalf("sign stale report: %v", err)
		}
		const staleAddr = "10.0.0.33:50061"
		stale := &distproto.RunCompleted{RunId: staleRun, Timestamp: ts, Report: staleReport, WorkerId: "w1", Signature: staleSig}
		if master.handleRunCompleted(staleAddr, stale, nil) {
			t.Fatal("final report signed for an inactive run must be rejected")
		}
		if got := master.RejectedWorkers(); got[staleAddr] == "" {
			t.Fatalf("stale-run report not recorded as rejected: %v", got)
		}

		freshReport := &distproto.Report{Name: "fresh", TotalRequests: 20, Rps: 10}
		freshSig, err := SignReport(kp, "w1", activeRun, ts, freshReport)
		if err != nil {
			t.Fatalf("sign active report: %v", err)
		}
		const freshAddr = "10.0.0.34:50061"
		fresh := &distproto.RunCompleted{RunId: activeRun, Timestamp: ts, Report: freshReport, WorkerId: "w1", Signature: freshSig}
		if !master.handleRunCompleted(freshAddr, fresh, nil) {
			t.Fatalf("final report signed for the active run must be accepted (rejected: %v)", master.RejectedWorkers())
		}
	})
}

// TestSignedProgressAccepted is the happy path: a snapshot signed by the pinned
// worker key is aggregated, the connection is bound to that identity, and
// nothing is marked failed or rejected.
func TestSignedProgressAccepted(t *testing.T) {
	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	master := attestationTestMaster(t, "w1", kp)
	const addr = "10.0.0.1:50061"

	rp := signedProgress(t, kp, "w1", "run-1", attestationTestSnapshot())
	if !master.handleRunProgress(addr, rp, nil) {
		t.Fatalf("signed progress must be accepted (rejected: %v)", master.RejectedWorkers())
	}

	agg := master.Aggregator().Snapshot()
	if agg.Workers != 1 || agg.TotalRequests != 42 || agg.TotalErrors != 1 {
		t.Fatalf("signed snapshot was not aggregated: %+v", agg)
	}
	if id, ok := master.WorkerIDForAddr(addr); !ok || id != "w1" {
		t.Fatalf("connection binding = (%q,%v), want (w1,true)", id, ok)
	}
	if got := master.RejectedWorkers(); len(got) != 0 {
		t.Fatalf("no rejection expected, got %v", got)
	}
	if got := master.FailedWorkers(); len(got) != 0 {
		t.Fatalf("attested worker must not be marked failed, got %v", got)
	}
	if n := master.Aggregator().RejectedCount(); n != 0 {
		t.Fatalf("aggregator rejected %d snapshots, want 0", n)
	}
}

// TestUnsignedProgressRejected is the fail-closed half: once attestation is on,
// a snapshot with no worker_id/signature must be discarded, its telemetry must
// never reach the aggregator, and the worker must be marked failed.
func TestUnsignedProgressRejected(t *testing.T) {
	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	master := attestationTestMaster(t, "w1", kp)
	const addr = "10.0.0.2:50061"

	snap := attestationTestSnapshot()
	rp := &distproto.RunProgress{RunId: "run-1", Timestamp: time.Now().UnixMilli(), Telemetry: snap}
	if master.handleRunProgress(addr, rp, nil) {
		t.Fatal("unsigned progress must be rejected when attestation is required")
	}

	if agg := master.Aggregator().Snapshot(); agg.Workers != 0 || agg.TotalRequests != 0 {
		t.Fatalf("unsigned telemetry must not be aggregated: %+v", agg)
	}
	if got := master.RejectedWorkers(); len(got) != 1 || got[addr] == "" {
		t.Fatalf("rejection reason not recorded for %s: %v", addr, got)
	}
	if got := master.FailedWorkers(); len(got) != 1 || got[0] != addr {
		t.Fatalf("unsigned worker must be marked failed, got %v", got)
	}
}

// TestForgedProgressRejected covers two forgeries of the signature half: a
// signature produced by a different key than the pinned one, and a genuine
// signature over a snapshot that was modified afterwards.
func TestForgedProgressRejected(t *testing.T) {
	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	other, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("second keypair: %v", err)
	}

	t.Run("signed by another key", func(t *testing.T) {
		master := attestationTestMaster(t, "w1", kp)
		const addr = "10.0.0.3:50061"
		rp := signedProgress(t, other, "w1", "run-1", attestationTestSnapshot())

		if master.handleRunProgress(addr, rp, nil) {
			t.Fatal("signature from a different key must be rejected")
		}
		if agg := master.Aggregator().Snapshot(); agg.Workers != 0 {
			t.Fatalf("forged telemetry was aggregated: %+v", agg)
		}
		if len(master.RejectedWorkers()) != 1 {
			t.Fatalf("forged worker must be recorded as rejected: %v", master.RejectedWorkers())
		}
		if len(master.FailedWorkers()) != 1 {
			t.Fatalf("forged worker must be marked failed: %v", master.FailedWorkers())
		}
	})

	t.Run("telemetry tampered after signing", func(t *testing.T) {
		master := attestationTestMaster(t, "w1", kp)
		const addr = "10.0.0.4:50061"
		rp := signedProgress(t, kp, "w1", "run-1", attestationTestSnapshot())
		rp.Telemetry.TotalRequests = 1_000_000 // inflate the numbers on the wire

		if master.handleRunProgress(addr, rp, nil) {
			t.Fatal("tampered telemetry must not verify")
		}
		if agg := master.Aggregator().Snapshot(); agg.Workers != 0 {
			t.Fatalf("tampered telemetry was aggregated: %+v", agg)
		}
	})

	t.Run("identity mismatch on one connection", func(t *testing.T) {
		master := attestationTestMaster(t, "w1", kp)
		const addr = "10.0.0.5:50061"
		if !master.handleRunProgress(addr, signedProgress(t, kp, "w1", "run-1", attestationTestSnapshot()), nil) {
			t.Fatal("first attested snapshot must be accepted")
		}
		// Same pinned key, but the stream now claims a different worker id:
		// one connection may only ever speak for one identity.
		claim := signedProgress(t, kp, "w2", "run-1", attestationTestSnapshot())
		if master.handleRunProgress(addr, claim, nil) {
			t.Fatal("a second worker identity on the same connection must be rejected")
		}
	})
}

// TestSignedFinalReportAccepted verifies the RunCompleted half of the
// attestation: a report signed by the pinned worker verifies, a tampered report
// does not.
func TestSignedFinalReportAccepted(t *testing.T) {
	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	master := attestationTestMaster(t, "w1", kp)
	const addr = "10.0.0.6:50061"

	rep := &distproto.Report{Name: "injected", TotalRequests: 10, TotalErrors: 0, Rps: 5}
	ts := time.Now().UnixMilli()
	sig, err := SignReport(kp, "w1", "run-1", ts, rep)
	if err != nil {
		t.Fatalf("sign report: %v", err)
	}
	rc := &distproto.RunCompleted{RunId: "run-1", Timestamp: ts, Report: rep, WorkerId: "w1", Signature: sig}
	if !master.handleRunCompleted(addr, rc, nil) {
		t.Fatalf("signed final report must be accepted (rejected: %v)", master.RejectedWorkers())
	}

	master2 := attestationTestMaster(t, "w1", kp)
	rc.Report.TotalRequests = 999_999
	if master2.handleRunCompleted("10.0.0.7:50061", rc, nil) {
		t.Fatal("tampered final report must not verify")
	}
}

// signedStatus builds the heartbeat a worker with kp emits for workerID.
func signedStatus(t *testing.T, kp *attest.Keypair, workerID string, healthy bool, activeRuns int64) *distproto.StatusReport {
	t.Helper()
	sig, err := SignStatus(kp, workerID, healthy, activeRuns)
	if err != nil {
		t.Fatalf("sign status: %v", err)
	}
	return &distproto.StatusReport{
		WorkerId:   workerID,
		Healthy:    healthy,
		ActiveRuns: activeRuns,
		Signature:  sig,
	}
}

// TestSignedStatusAccepted verifies the heartbeat half of the attestation: a
// status heartbeat signed by the pinned worker verifies, is accepted and is
// kept for the fleet monitor.
func TestSignedStatusAccepted(t *testing.T) {
	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	master := attestationTestMaster(t, "w1", kp)
	const addr = "10.0.0.8:50061"

	sr := signedStatus(t, kp, "w1", true, 2)
	if !master.handleStatusReport(addr, sr, nil) {
		t.Fatalf("signed status heartbeat must be accepted (rejected: %v)", master.RejectedWorkers())
	}
	master.storeStatus(addr, sr)
	if got := master.StatusReports()[addr]; got == nil || got.GetWorkerId() != "w1" {
		t.Fatalf("signed heartbeat was not stored: %+v", master.StatusReports()[addr])
	}
	if got := master.RejectedWorkers(); len(got) != 0 {
		t.Fatalf("no rejection expected, got %v", got)
	}
}

// TestUnsignedStatusRejected is the fail-closed half for heartbeats: once
// attestation is on, an unsigned status heartbeat must be dropped.
func TestUnsignedStatusRejected(t *testing.T) {
	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	master := attestationTestMaster(t, "w1", kp)
	const addr = "10.0.0.9:50061"

	sr := &distproto.StatusReport{WorkerId: "w1", Healthy: true, ActiveRuns: 1}
	if master.handleStatusReport(addr, sr, nil) {
		t.Fatal("unsigned status heartbeat must be rejected when attestation is required")
	}
	if got := master.RejectedWorkers(); len(got) != 1 || got[addr] == "" {
		t.Fatalf("rejection reason not recorded for %s: %v", addr, got)
	}
}

// TestForgedStatusRejected covers forgeries of the heartbeat signature: a
// signature produced by a different key than the pinned one, and a genuine
// signature over a tampered health/active-runs payload.
func TestForgedStatusRejected(t *testing.T) {
	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	other, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("second keypair: %v", err)
	}

	t.Run("signed by another key", func(t *testing.T) {
		master := attestationTestMaster(t, "w1", kp)
		const addr = "10.0.0.10:50061"
		if master.handleStatusReport(addr, signedStatus(t, other, "w1", true, 2), nil) {
			t.Fatal("signature from a different key must be rejected")
		}
		if len(master.RejectedWorkers()) != 1 {
			t.Fatalf("forged worker must be recorded as rejected: %v", master.RejectedWorkers())
		}
	})

	t.Run("heartbeat tampered after signing", func(t *testing.T) {
		master := attestationTestMaster(t, "w1", kp)
		const addr = "10.0.0.11:50061"
		sr := signedStatus(t, kp, "w1", true, 2)
		sr.Healthy = false // tamper after signing
		if master.handleStatusReport(addr, sr, nil) {
			t.Fatal("tampered heartbeat must not verify")
		}
	})
}

// TestStatusAttestationMessageIsDeterministic checks the canonical statement
// the status signature is over: two calls with equal inputs must produce equal
// bytes, and changing the signed payload must change them.
func TestStatusAttestationMessageIsDeterministic(t *testing.T) {
	first := StatusAttestationMessage("w1", true, 3)
	second := StatusAttestationMessage("w1", true, 3)
	if string(first) != string(second) {
		t.Fatal("status attestation message must be deterministic")
	}
	if string(StatusAttestationMessage("w1", true, 3)) == string(StatusAttestationMessage("w1", false, 3)) {
		t.Fatal("status attestation message must reflect the health flag")
	}
	if string(StatusAttestationMessage("w1", true, 3)) == string(StatusAttestationMessage("w1", true, 4)) {
		t.Fatal("status attestation message must reflect active runs")
	}
}

// TestAggregatorStrictGate is the defence-in-depth check: even a caller that
// bypasses the recvLoop verification cannot push an unverified snapshot into a
// strict aggregator.
func TestAggregatorStrictGate(t *testing.T) {
	a := NewAggregator()
	a.SetRequireVerified(true)
	if a.Update("w1", attestationTestSnapshot()) {
		t.Fatal("strict aggregator must refuse Update (unverified)")
	}
	if a.UpdateVerified("w1", attestationTestSnapshot(), false) {
		t.Fatal("strict aggregator must refuse an explicitly unverified snapshot")
	}
	if !a.UpdateVerified("w1", attestationTestSnapshot(), true) {
		t.Fatal("strict aggregator must accept a verified snapshot")
	}
	if n := a.RejectedCount(); n != 2 {
		t.Fatalf("RejectedCount = %d, want 2", n)
	}

	a.SetRequireVerified(false)
	if !a.Update("w2", attestationTestSnapshot()) {
		t.Fatal("unstrict aggregator must accept unsigned snapshots")
	}
}
