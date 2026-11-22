package coordinator

// attest.go — the *signature half* of worker attestation.
//
// The identity half (internal/dist/coordinator/master.go, Register +
// VerifyWorkerAttestation) answers "is this worker on the allowlist and does it
// hold the pinned private key". This file closes the loop for telemetry: every
// RunProgress and RunCompleted a worker streams carries an Ed25519 signature
// over a canonical statement about *that* payload, so the master can prove the
// numbers were produced by the pinned worker identity and were not mutated in
// transit by anything else on the control-plane port.
//
// # What is signed
//
// A signature covers a small canonical byte string, never the raw protobuf:
//
//	sift/worker-progress-attest/v1\n
//	<len>:<worker_id>\n
//	<len>:<run_id>\n
//	<len>:<timestamp-ms>\n
//	<len>:<sha256 hex of the deterministic telemetry encoding>\n
//
// Length prefixes make the encoding unambiguous (a worker_id containing '\n'
// cannot shift into the run_id field), and the SHA-256 digest folds the whole
// snapshot — including its maps — into one fixed-size value.
//
// # Why the digest is deterministic
//
// TelemetrySnapshot carries map fields (status_codes, error_types), and Go's
// protobuf encoder may emit map entries in any order. Signing a
// non-deterministic encoding would make honest signatures fail intermittently.
// The digest therefore uses proto.MarshalOptions{Deterministic: true}, which
// sorts map keys and is stable across calls, and the verifier recomputes it
// from the bytes it actually received.
//
// # Replay
//
// worker_id, run_id and timestamp are all inside the signed message, so a
// signature captured from run A cannot authenticate a snapshot in run B, and a
// snapshot cannot be relabelled as a later sample. Re-sending an identical
// signed snapshot is harmless: progress snapshots are cumulative, so an exact
// replay carries no new claims.
//
// # Fail-closed defaults
//
// If the payload cannot be encoded, signing and verification both fail rather
// than falling back to "accept".

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"

	"google.golang.org/protobuf/proto"

	"github.com/asadbekabdulboqiyev/sift/internal/attest"
	distproto "github.com/asadbekabdulboqiyev/sift/internal/dist/proto"
)

const (
	// progressAttestDomain versions the progress statement. Changing the fields
	// below requires a new domain string so an old signature can never be
	// reinterpreted under the new rules.
	progressAttestDomain = "sift/worker-progress-attest/v1"
	// reportAttestDomain versions the final-report statement.
	reportAttestDomain = "sift/worker-report-attest/v1"
	// statusAttestDomain versions the status-heartbeat statement.
	statusAttestDomain = "sift/worker-status-attest/v1"
	// registrationAttestDomain versions the worker-registration challenge
	// response. A signature over the master's one-time nonce proves possession
	// of the pinned key before the master hands the worker a scenario.
	registrationAttestDomain = "sift/worker-register-attest/v1"
	// failureAttestDomain versions the run-failure statement, so an unsigned or
	// replayed failure cannot terminate an attested run.
	failureAttestDomain = "sift/worker-failure-attest/v1"
)

// SnapshotDigest returns the SHA-256 of the deterministic protobuf encoding of
// snap. Two processes that hold the same logical snapshot derive the same
// digest, which is what makes the signature verifiable.
func SnapshotDigest(snap *distproto.TelemetrySnapshot) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	if snap == nil {
		return zero, fmt.Errorf("coordinator: snapshot digest: nil telemetry")
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(snap)
	if err != nil {
		return zero, fmt.Errorf("coordinator: snapshot digest: %w", err)
	}
	return sha256.Sum256(raw), nil
}

// ReportDigest returns the SHA-256 of the deterministic protobuf encoding of a
// final report.
func ReportDigest(rep *distproto.Report) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	if rep == nil {
		return zero, fmt.Errorf("coordinator: report digest: nil report")
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(rep)
	if err != nil {
		return zero, fmt.Errorf("coordinator: report digest: %w", err)
	}
	return sha256.Sum256(raw), nil
}

// attestationMessage builds the canonical, length-prefixed statement that is
// signed. Every field is emitted as "<decimal byte length>:<bytes>\n".
func attestationMessage(domain string, fields ...string) []byte {
	var b bytes.Buffer
	b.WriteString(domain)
	b.WriteByte('\n')
	for _, f := range fields {
		b.WriteString(strconv.Itoa(len(f)))
		b.WriteByte(':')
		b.WriteString(f)
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// ProgressAttestationMessage returns the exact bytes a worker signs for one
// progress snapshot and a master verifies.
func ProgressAttestationMessage(workerID, runID string, timestamp int64, digest [sha256.Size]byte) []byte {
	return attestationMessage(progressAttestDomain,
		workerID,
		runID,
		strconv.FormatInt(timestamp, 10),
		hex.EncodeToString(digest[:]),
	)
}

// ReportAttestationMessage returns the exact bytes a worker signs for its final
// report and a master verifies.
func ReportAttestationMessage(workerID, runID string, timestamp int64, digest [sha256.Size]byte) []byte {
	return attestationMessage(reportAttestDomain,
		workerID,
		runID,
		strconv.FormatInt(timestamp, 10),
		hex.EncodeToString(digest[:]),
	)
}

// SignProgress produces the signature a worker attaches to a RunProgress event.
// It returns an error (never a partial/fake signature) when the keypair or the
// snapshot is unusable.
func SignProgress(kp *attest.Keypair, workerID, runID string, timestamp int64, snap *distproto.TelemetrySnapshot) ([]byte, error) {
	digest, err := SnapshotDigest(snap)
	if err != nil {
		return nil, err
	}
	return attest.Sign(kp, ProgressAttestationMessage(workerID, runID, timestamp, digest))
}

// SignReport produces the signature a worker attaches to a RunCompleted event.
func SignReport(kp *attest.Keypair, workerID, runID string, timestamp int64, rep *distproto.Report) ([]byte, error) {
	digest, err := ReportDigest(rep)
	if err != nil {
		return nil, err
	}
	return attest.Sign(kp, ReportAttestationMessage(workerID, runID, timestamp, digest))
}

// StatusAttestationMessage returns the exact bytes a worker signs for one
// status heartbeat and a master verifies. The statement carries the worker
// identity, the health flag and the number of active runs, all emitted as
// length-prefixed canonical strings. Heartbeats carry no run id, so the
// statement is scoped to the worker rather than to a run.
func StatusAttestationMessage(workerID string, healthy bool, activeRuns int64) []byte {
	return attestationMessage(statusAttestDomain,
		workerID,
		strconv.FormatBool(healthy),
		strconv.FormatInt(activeRuns, 10),
	)
}

// SignStatus produces the signature a worker attaches to a StatusReport
// heartbeat. It returns an error (never a partial/fake signature) when the
// keypair is unusable.
func SignStatus(kp *attest.Keypair, workerID string, healthy bool, activeRuns int64) ([]byte, error) {
	return attest.Sign(kp, StatusAttestationMessage(workerID, healthy, activeRuns))
}

// RegistrationAttestationMessage is the statement a worker signs to prove it
// holds the private key pinned for workerID. It binds the claimed address and
// the master's one-time challenge, so a captured proof cannot be replayed from
// a different address or on a later registration attempt. The challenge is a
// binary nonce; storing it in a length-prefixed string field keeps the encoding
// unambiguous.
func RegistrationAttestationMessage(workerID, address string, challenge []byte) []byte {
	return attestationMessage(registrationAttestDomain,
		workerID,
		address,
		string(challenge),
	)
}

// SignRegistration signs a registration challenge with the worker's identity.
func SignRegistration(kp *attest.Keypair, workerID, address string, challenge []byte) ([]byte, error) {
	return attest.Sign(kp, RegistrationAttestationMessage(workerID, address, challenge))
}

// FailureAttestationMessage is the statement a worker signs for a RunFailed
// event. Binding the run id, timestamp and error text stops an on-path attacker
// from forging or relabelling a failure to end a run early.
func FailureAttestationMessage(workerID, runID string, timestamp int64, errMsg string) []byte {
	return attestationMessage(failureAttestDomain,
		workerID,
		runID,
		strconv.FormatInt(timestamp, 10),
		errMsg,
	)
}

// SignFailure signs a RunFailed event with the worker's identity.
func SignFailure(kp *attest.Keypair, workerID, runID string, timestamp int64, errMsg string) ([]byte, error) {
	return attest.Sign(kp, FailureAttestationMessage(workerID, runID, timestamp, errMsg))
}

// attestFailed attaches this worker's identity and Ed25519 signature to a
// RunFailed event. A worker without a keypair leaves both fields empty, which
// only an unattested coordinator accepts.
func (w *Worker) attestFailed(rf *distproto.RunFailed) error {
	if w.cfg.Keypair == nil || rf == nil {
		return nil
	}
	rf.WorkerId = w.cfg.ID
	sig, err := SignFailure(w.cfg.Keypair, w.cfg.ID, rf.GetRunId(), rf.GetTimestamp(), rf.GetError())
	if err != nil {
		return err
	}
	rf.Signature = sig
	return nil
}

// attestProgress attaches this worker's identity and Ed25519 signature to a
// progress snapshot. A worker without a keypair leaves both fields empty, which
// only an unattested coordinator accepts. A keypair present but unusable is an
// error: sending an unsigned frame would get the worker dropped, so the caller
// fails the run explicitly instead.
func (w *Worker) attestProgress(rp *distproto.RunProgress) error {
	if w.cfg.Keypair == nil || rp == nil {
		return nil
	}
	rp.WorkerId = w.cfg.ID
	sig, err := SignProgress(w.cfg.Keypair, w.cfg.ID, rp.GetRunId(), rp.GetTimestamp(), rp.GetTelemetry())
	if err != nil {
		return err
	}
	rp.Signature = sig
	return nil
}

// attestCompleted attaches this worker's identity and Ed25519 signature to the
// final report.
func (w *Worker) attestCompleted(rc *distproto.RunCompleted) error {
	if w.cfg.Keypair == nil || rc == nil {
		return nil
	}
	rc.WorkerId = w.cfg.ID
	sig, err := SignReport(w.cfg.Keypair, w.cfg.ID, rc.GetRunId(), rc.GetTimestamp(), rc.GetReport())
	if err != nil {
		return err
	}
	rc.Signature = sig
	return nil
}

// VerifyProgressSignature checks a RunProgress signature against the public key
// pinned for workerID. It fails closed: an unpinned worker, an unencodable
// snapshot, or a malformed/short/forged signature all return false.
func (m *Master) VerifyProgressSignature(workerID, runID string, timestamp int64, snap *distproto.TelemetrySnapshot, sig []byte) bool {
	digest, err := SnapshotDigest(snap)
	if err != nil {
		return false
	}
	return m.VerifyWorkerSignature(workerID, ProgressAttestationMessage(workerID, runID, timestamp, digest), sig)
}

// VerifyReportSignature checks a RunCompleted signature against the public key
// pinned for workerID.
func (m *Master) VerifyReportSignature(workerID, runID string, timestamp int64, rep *distproto.Report, sig []byte) bool {
	digest, err := ReportDigest(rep)
	if err != nil {
		return false
	}
	return m.VerifyWorkerSignature(workerID, ReportAttestationMessage(workerID, runID, timestamp, digest), sig)
}

// VerifyStatusSignature checks a StatusReport heartbeat signature against the
// public key pinned for workerID. It fails closed: an unpinned worker, a
// missing signature, or a malformed/forged signature all return false.
func (m *Master) VerifyStatusSignature(workerID string, healthy bool, activeRuns int64, sig []byte) bool {
	return m.VerifyWorkerSignature(workerID, StatusAttestationMessage(workerID, healthy, activeRuns), sig)
}

// VerifyFailureSignature checks a RunFailed signature against the key pinned
// for workerID. It fails closed just like progress/report verification.
func (m *Master) VerifyFailureSignature(workerID, runID string, timestamp int64, errMsg string, sig []byte) bool {
	return m.VerifyWorkerSignature(workerID, FailureAttestationMessage(workerID, runID, timestamp, errMsg), sig)
}

// VerifyWorkerSignature checks sig over msg against the key pinned for
// workerID. Unlike VerifyWorkerAttestation the caller does not supply the
// public key, so a caller cannot accidentally verify against a key it merely
// believes belongs to the worker: the pin is the only trust anchor.
func (m *Master) VerifyWorkerSignature(workerID string, msg, sig []byte) bool {
	m.mu.Lock()
	pinned, ok := m.workerPubs[workerID]
	m.mu.Unlock()
	if !ok {
		return false
	}
	return attest.VerifySig(pinned, msg, sig)
}

// attestationRequiredLocked reports whether telemetry must be signed.
//
// Two ways to turn attestation on: set RequireWorkerAttestation, or pin at
// least one worker key (AuthorizedWorkers / SetWorkerKey). Pinning is a
// deliberate operator act, so it is treated as "this fleet is attested" — a
// fleet that has pinned *any* identity never accepts unsigned telemetry from
// anybody, which is what keeps an unpinned impostor from slipping in beside the
// pinned workers. Callers must hold m.mu.
func (m *Master) attestationRequiredLocked() bool {
	return m.cfg.RequireWorkerAttestation || len(m.workerPubs) > 0
}

// attestationRequired is the lock-taking form of attestationRequiredLocked.
func (m *Master) attestationRequired() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.attestationRequiredLocked()
}

// syncAttestationModeLocked pushes the current policy into the Aggregator so it
// becomes a second, independent gate: even a future caller that bypasses the
// recvLoop verification cannot inject an unverified snapshot while attestation
// is on. Callers must hold m.mu.
func (m *Master) syncAttestationModeLocked() {
	m.agg.SetRequireVerified(m.attestationRequiredLocked())
}

// activeRunID returns the run the master currently accepts telemetry for. An
// empty string means no run has been started (for example in unit tests that
// drive the handlers directly); in that case the context check is skipped.
func (m *Master) activeRunID() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.runID
}

// runIDMatchesActive reports whether frameRun belongs to the active run. It is
// the replay-context guard: a correctly signed frame from an earlier run must
// not be accepted as this run's telemetry or final report.
func (m *Master) runIDMatchesActive(frameRun string) bool {
	active := m.activeRunID()
	return active == "" || frameRun == active
}

// boundWorkerID returns the worker id already attested for a connection address.
func (m *Master) boundWorkerID(addr string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.workerIDs[addr]
	return id, ok
}

// bindWorker records that addr speaks for workerID. It refuses to rebind a
// connection to a different identity, so a single stream cannot present two
// worker ids (and thereby mix two workers' telemetry under one connection).
func (m *Master) bindWorker(addr, workerID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if id, ok := m.workerIDs[addr]; ok && id != "" && id != workerID {
		return false
	}
	m.workerIDs[addr] = workerID
	return true
}

// WorkerIDForAddr returns the identity bound to a connection, if attestation
// has already proven one.
func (m *Master) WorkerIDForAddr(addr string) (string, bool) { return m.boundWorkerID(addr) }

// RejectedWorkers returns the reason each connection was dropped for failing
// attestation, keyed by remote address. Empty when nothing was rejected.
func (m *Master) RejectedWorkers() map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]string, len(m.rejected))
	for addr, reason := range m.rejected {
		out[addr] = reason
	}
	return out
}

// rejectWorker drops every future claim made by addr: the stream is closed, the
// worker is marked failed and the reason is recorded for operators. It is
// deliberately terminal for trust — one unverifiable payload poisons the
// connection, because a stream that has produced one forged frame can no longer
// be trusted for subsequent frames. However, previously accepted telemetry
// snapshots (and any already-received final report) must be preserved so
// measured evidence is not lost; forgetLive=true removes live aggregation state
// only after partial synthesis.
func (m *Master) rejectWorker(addr, workerID, reason string, stream distproto.MasterWorker_CoordinateClient) {
	m.rejectWorkerWithPolicy(addr, workerID, reason, stream, true)
}

func (m *Master) rejectWorkerWithPolicy(addr, workerID, reason string, stream distproto.MasterWorker_CoordinateClient, forgetLive bool) {
	if workerID == "" {
		m.cfg.Logf("worker %s REJECTED: %s; preserving existing telemetry evidence and stopping trust in this stream", addr, reason)
	} else {
		m.cfg.Logf("worker %s (id %s) REJECTED: %s; preserving existing telemetry evidence and stopping trust in this stream", addr, workerID, reason)
	}
	m.mu.Lock()
	if m.rejected == nil {
		m.rejected = make(map[string]string)
	}
	m.rejected[addr] = reason
	m.failureReasons[addr] = reason
	m.mu.Unlock()

	if stream != nil {
		// Closing the send side unblocks recvLoop, which then returns.
		_ = stream.CloseSend()
	}
	// Mark finished/failed first so workerFinished can synthesize a partial
	// report from the last accepted snapshot when no trusted final report exists.
	m.workerFinished(addr, true)
	if forgetLive {
		m.agg.Forget(addr)
	}
}

// handleRunProgress verifies one progress snapshot from addr and, when it is
// acceptable, hands it to the Aggregator. It returns false when the worker was
// rejected, which tells recvLoop to stop reading from that connection.
//
// In the default (unattested, single-tenant) mode the snapshot is accepted as
// before. Once attestation is on, the ordering is strict: identity present →
// identity matches the connection's earlier claim → signature verifies against
// the pinned key → only then is the snapshot aggregated.
func (m *Master) handleRunProgress(addr string, rp *distproto.RunProgress, stream distproto.MasterWorker_CoordinateClient) bool {
	if rp == nil || rp.Telemetry == nil {
		return true
	}
	if !m.attestationRequired() {
		m.agg.UpdateVerified(addr, rp.Telemetry, false)
		return true
	}
	workerID := rp.GetWorkerId()
	if workerID == "" {
		m.rejectWorker(addr, "", "progress carries no worker_id while attestation is required", stream)
		return false
	}
	if !m.runIDMatchesActive(rp.GetRunId()) {
		m.rejectWorker(addr, workerID, fmt.Sprintf("progress run_id %q does not match the active run %q", rp.GetRunId(), m.activeRunID()), stream)
		return false
	}
	if bound, ok := m.boundWorkerID(addr); ok && bound != workerID {
		m.rejectWorker(addr, workerID, fmt.Sprintf("worker_id %q does not match the identity %q already attested on this connection", workerID, bound), stream)
		return false
	}
	if !m.VerifyProgressSignature(workerID, rp.GetRunId(), rp.GetTimestamp(), rp.Telemetry, rp.GetSignature()) {
		m.rejectWorker(addr, workerID, "invalid or missing Ed25519 signature on progress snapshot", stream)
		return false
	}
	if !m.bindWorker(addr, workerID) {
		m.rejectWorker(addr, workerID, "connection is already bound to another worker identity", stream)
		return false
	}
	if !m.agg.UpdateVerified(addr, rp.Telemetry, true) {
		// Only reachable if the aggregator and the master disagree about the
		// policy; refusing the snapshot is the safe reaction either way.
		m.rejectWorker(addr, workerID, "aggregator refused a verified snapshot", stream)
		return false
	}
	return true
}

// handleRunCompleted verifies the attestation attached to a final report. It
// returns false when the worker was rejected; the caller must then not store
// the report.
func (m *Master) handleRunCompleted(addr string, rc *distproto.RunCompleted, stream distproto.MasterWorker_CoordinateClient) bool {
	if rc == nil {
		return true
	}
	if !m.attestationRequired() {
		return true
	}
	workerID := rc.GetWorkerId()
	if workerID == "" {
		m.rejectWorker(addr, "", "final report carries no worker_id while attestation is required", stream)
		return false
	}
	if !m.runIDMatchesActive(rc.GetRunId()) {
		m.rejectWorker(addr, workerID, fmt.Sprintf("final report run_id %q does not match the active run %q", rc.GetRunId(), m.activeRunID()), stream)
		return false
	}
	if bound, ok := m.boundWorkerID(addr); ok && bound != workerID {
		m.rejectWorker(addr, workerID, fmt.Sprintf("worker_id %q does not match the identity %q already attested on this connection", workerID, bound), stream)
		return false
	}
	if !m.VerifyReportSignature(workerID, rc.GetRunId(), rc.GetTimestamp(), rc.GetReport(), rc.GetSignature()) {
		m.rejectWorker(addr, workerID, "invalid or missing Ed25519 signature on final report", stream)
		return false
	}
	if !m.bindWorker(addr, workerID) {
		m.rejectWorker(addr, workerID, "connection is already bound to another worker identity", stream)
		return false
	}
	return true
}

// handleRunFailed verifies the attestation on a RunFailed event before the
// master treats it as terminal. Without this gate an on-path attacker (or any
// client holding the shared control-plane token) could end an attested run by
// injecting an unsigned failure, synthesizing a partial report and corrupting
// SLA/regression results. It mirrors handleRunCompleted's fail-closed posture.
func (m *Master) handleRunFailed(addr string, rf *distproto.RunFailed, stream distproto.MasterWorker_CoordinateClient) bool {
	if rf == nil {
		return true
	}
	if !m.attestationRequired() {
		return true
	}
	workerID := rf.GetWorkerId()
	if workerID == "" {
		m.rejectWorker(addr, "", "run failure carries no worker_id while attestation is required", stream)
		return false
	}
	if !m.runIDMatchesActive(rf.GetRunId()) {
		m.rejectWorker(addr, workerID, fmt.Sprintf("run failure run_id %q does not match the active run %q", rf.GetRunId(), m.activeRunID()), stream)
		return false
	}
	if bound, ok := m.boundWorkerID(addr); ok && bound != workerID {
		m.rejectWorker(addr, workerID, fmt.Sprintf("worker_id %q does not match the identity %q already attested on this connection", workerID, bound), stream)
		return false
	}
	if !m.VerifyFailureSignature(workerID, rf.GetRunId(), rf.GetTimestamp(), rf.GetError(), rf.GetSignature()) {
		m.rejectWorker(addr, workerID, "invalid or missing Ed25519 signature on run failure", stream)
		return false
	}
	if !m.bindWorker(addr, workerID) {
		m.rejectWorker(addr, workerID, "connection is already bound to another worker identity", stream)
		return false
	}
	return true
}

// handleStatusReport verifies one heartbeat from addr against the pinned worker
// key when attestation is on, then lets the caller store it. It returns false
// when the worker was rejected, which tells recvLoop to stop reading from that
// connection.
//
// The heartbeat is verified with the same fail-closed posture as a progress
// snapshot: identity present → identity matches the connection's earlier claim →
// signature verifies against the pinned key. A heartbeat without a signature
// (or with a bad one) drops the worker instead of letting an unauthenticated
// liveness frame through.
func (m *Master) handleStatusReport(addr string, sr *distproto.StatusReport, stream distproto.MasterWorker_CoordinateClient) bool {
	if sr == nil {
		return true
	}
	if !m.attestationRequired() {
		return true
	}
	workerID := sr.GetWorkerId()
	if workerID == "" {
		m.rejectWorker(addr, "", "status heartbeat carries no worker_id while attestation is required", stream)
		return false
	}
	if bound, ok := m.boundWorkerID(addr); ok && bound != workerID {
		m.rejectWorker(addr, workerID, fmt.Sprintf("worker_id %q does not match the identity %q already attested on this connection", workerID, bound), stream)
		return false
	}
	if !m.VerifyStatusSignature(workerID, sr.GetHealthy(), sr.GetActiveRuns(), sr.GetSignature()) {
		m.rejectWorker(addr, workerID, "invalid or missing Ed25519 signature on status heartbeat", stream)
		return false
	}
	if !m.bindWorker(addr, workerID) {
		m.rejectWorker(addr, workerID, "connection is already bound to another worker identity", stream)
		return false
	}
	return true
}
