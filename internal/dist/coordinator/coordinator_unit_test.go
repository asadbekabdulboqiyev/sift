package coordinator

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/asadbekabdulboqiyev/sift/internal/attest"
	"github.com/asadbekabdulboqiyev/sift/internal/config"
	distproto "github.com/asadbekabdulboqiyev/sift/internal/dist/proto"
	"github.com/asadbekabdulboqiyev/sift/internal/metrics"
	"github.com/asadbekabdulboqiyev/sift/internal/report"
)

// unitNoopLogf keeps unit tests silent without dropping log arguments.
func unitNoopLogf(string, ...any) {}

// unitKeypair builds an Ed25519 identity from a fixed seed so tests are
// deterministic and never depend on the system CSPRNG.
func unitKeypair() *attest.Keypair {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &attest.Keypair{Private: priv, Public: priv.Public().(ed25519.PublicKey)}
}

// unitCommandStream is an in-process fake bidirectional stream. Only Recv and
// Send are implemented, which is all the Coordinate loops use.
type unitCommandStream struct {
	grpc.ServerStream
	cmds      []*distproto.WorkerCommand
	idx       int
	responses []*distproto.WorkerEvent
	sendErr   error
}

func (s *unitCommandStream) Recv() (*distproto.WorkerCommand, error) {
	if s.idx >= len(s.cmds) {
		return nil, io.EOF
	}
	cmd := s.cmds[s.idx]
	s.idx++
	return cmd, nil
}

func (s *unitCommandStream) Send(event *distproto.WorkerEvent) error {
	if s.sendErr != nil {
		return s.sendErr
	}
	s.responses = append(s.responses, event)
	return nil
}

func unitScenarioProto(users, steps int) *distproto.Scenario {
	sc := &config.Scenario{
		Name:    "unit",
		Profile: config.Profile{Type: config.ProfileSteady, Users: users, Duration: 1, Timeout: 1},
	}
	for i := 0; i < steps; i++ {
		sc.Steps = append(sc.Steps, config.Step{Name: "step", URL: "http://127.0.0.1:1/"})
	}
	return ScenarioToProto(sc)
}

// ---------------------------------------------------------------------------
// convert.go — wire converters
// ---------------------------------------------------------------------------

func TestUnitStatusAndErrorsProtoConverters(t *testing.T) {
	t.Run("status round trip", func(t *testing.T) {
		// Arrange.
		in := map[int]uint64{200: 10, 404: 2, 500: 1}
		// Act.
		wire := StatusToProto(in)
		back := StatusFromProto(wire)
		// Assert.
		if len(wire) != len(in) || wire[200] != 10 || wire[500] != 1 {
			t.Fatalf("StatusToProto = %v", wire)
		}
		if len(back) != len(in) {
			t.Fatalf("StatusFromProto = %v", back)
		}
		for code, n := range in {
			if back[code] != n {
				t.Fatalf("status %d: got %d, want %d", code, back[code], n)
			}
		}
	})

	t.Run("errors round trip", func(t *testing.T) {
		// Arrange.
		in := map[string]uint64{"timeout": 7, "dns": 3}
		// Act.
		wire := ErrorsToProto(in)
		back := ErrorsFromProto(wire)
		// Assert.
		if wire["timeout"] != 7 || wire["dns"] != 3 {
			t.Fatalf("ErrorsToProto = %v", wire)
		}
		if back["timeout"] != 7 || back["dns"] != 3 || len(back) != 2 {
			t.Fatalf("ErrorsFromProto = %v", back)
		}
	})
}

func TestUnitLatencyToProto(t *testing.T) {
	// Arrange: five deterministic observations.
	var h metrics.Histogram
	for _, d := range []time.Duration{
		10 * time.Millisecond, 20 * time.Millisecond, 30 * time.Millisecond,
		40 * time.Millisecond, 50 * time.Millisecond,
	} {
		h.Add(d)
	}
	snap := h.Snapshot()

	// Act.
	got := LatencyToProto(snap)

	// Assert: every field mirrors the source snapshot.
	if got.MinMs != snap.Min.Milliseconds() || got.MaxMs != snap.Max.Milliseconds() {
		t.Fatalf("min/max = %d/%d, want %d/%d", got.MinMs, got.MaxMs, snap.Min.Milliseconds(), snap.Max.Milliseconds())
	}
	if got.AvgMs != snap.Average.Milliseconds() {
		t.Fatalf("avg = %d, want %d", got.AvgMs, snap.Average.Milliseconds())
	}
	if got.P50Ms != snap.Percentile(0.50).Milliseconds() ||
		got.P95Ms != snap.Percentile(0.95).Milliseconds() ||
		got.P99Ms != snap.Percentile(0.99).Milliseconds() {
		t.Fatalf("percentiles = %d/%d/%d, want %d/%d/%d",
			got.P50Ms, got.P95Ms, got.P99Ms,
			snap.Percentile(0.50).Milliseconds(), snap.Percentile(0.95).Milliseconds(), snap.Percentile(0.99).Milliseconds())
	}
}

func TestUnitTelemetryToProto(t *testing.T) {
	// Arrange: one telemetry with a single recorded step.
	tel := metrics.NewTelemetry()
	step := metrics.NewStepStats("login")
	step.Record(10*time.Millisecond, 200, "")
	step.Record(20*time.Millisecond, 500, "timeout")
	step.Record(30*time.Millisecond, 500, "timeout")
	tel.AddStep(step)
	tel.Finish()

	// Act.
	got := TelemetryToProto(tel, tel.Overall.Latency.Snapshot())

	// Assert: counters and histograms are transferred; time-derived fields are
	// intentionally not asserted because they depend on the wall clock.
	if got.TotalRequests != 3 || got.TotalErrors != 2 {
		t.Fatalf("totals = %d/%d, want 3/2", got.TotalRequests, got.TotalErrors)
	}
	if got.StatusCodes[200] != 1 || got.StatusCodes[500] != 2 {
		t.Fatalf("status codes = %v", got.StatusCodes)
	}
	if got.ErrorTypes["timeout"] != 2 {
		t.Fatalf("error types = %v", got.ErrorTypes)
	}
	if len(got.Steps) != 1 {
		t.Fatalf("steps = %d, want 1", len(got.Steps))
	}
	gotStep := got.Steps[0]
	if gotStep.Name != "login" || gotStep.Requests != 3 || gotStep.Errors != 2 {
		t.Fatalf("step = %+v", gotStep)
	}
	if got.Latency == nil || gotStep.Latency == nil {
		t.Fatal("latency percentiles missing")
	}
	if gotStep.StatusCodes[500] != 2 || gotStep.ErrorTypes["timeout"] != 2 {
		t.Fatalf("step histograms = %v / %v", gotStep.StatusCodes, gotStep.ErrorTypes)
	}
}

func TestUnitReportProtoConverters(t *testing.T) {
	start := time.UnixMilli(1_700_000_000_000)
	duration := 5 * time.Second

	t.Run("nil inputs", func(t *testing.T) {
		if StepReportToProto(nil) != nil {
			t.Fatal("StepReportToProto(nil) must be nil")
		}
		if ReportToProto(nil) != nil {
			t.Fatal("ReportToProto(nil) must be nil")
		}
		if ReportFromProto(nil) != nil {
			t.Fatal("ReportFromProto(nil) must be nil")
		}
		if got := StepReportFromProto(nil); got.Name != "" || got.Requests != 0 {
			t.Fatalf("StepReportFromProto(nil) = %+v", got)
		}
	})

	t.Run("full report round trip", func(t *testing.T) {
		// Arrange.
		rep := &report.Report{
			Name: "load", BaseURL: "http://x", LoadProfile: "steady",
			StartedAt: start, EndedAt: start.Add(duration), Duration: duration,
			ActiveUsers: 10, TotalRequests: 100, TotalErrors: 4,
			ErrorRatePct: 4, RPS: 20,
			Status: map[int]uint64{200: 96, 500: 4},
			Errors: map[string]uint64{"timeout": 4},
			Overall: report.StepReport{
				Name: "overall", Requests: 100, Errors: 4,
				Status:     map[int]uint64{200: 96, 500: 4},
				ErrorTypes: map[string]uint64{"timeout": 4},
				Min:        time.Millisecond, Avg: 10 * time.Millisecond, Max: 50 * time.Millisecond,
				P50: 8 * time.Millisecond, P95: 30 * time.Millisecond, P99: 45 * time.Millisecond,
			},
			Steps: []report.StepReport{{Name: "login", Requests: 100, Errors: 4,
				Status: map[int]uint64{200: 96, 500: 4}, ErrorTypes: map[string]uint64{"timeout": 4},
				P99: 45 * time.Millisecond}},
			SLA:      []report.SLAResult{{Metric: "p99", Target: "<=50ms", Actual: "45ms", Pass: true}},
			Timeline: []metrics.TimelineSample{{Second: 1, Requests: 50, Errors: 2, ActiveUsers: 10}},
		}

		// Act.
		wire := ReportToProto(rep)
		back := ReportFromProto(wire)

		// Assert: proto carries every field.
		if wire.Name != "load" || wire.BaseUrl != "http://x" || wire.LoadProfile != "steady" {
			t.Fatalf("identity lost: %+v", wire)
		}
		if wire.TotalRequests != 100 || wire.TotalErrors != 4 || wire.ActiveUsers != 10 {
			t.Fatalf("totals lost: %+v", wire)
		}
		if wire.StatusCodes[200] != 96 || wire.Errors["timeout"] != 4 {
			t.Fatalf("histograms lost: %v / %v", wire.StatusCodes, wire.Errors)
		}
		if wire.Overall == nil || wire.Overall.P99Ms != 45 {
			t.Fatalf("overall lost: %+v", wire.Overall)
		}
		if len(wire.Steps) != 1 || wire.Steps[0].Name != "login" {
			t.Fatalf("steps lost: %+v", wire.Steps)
		}
		if len(wire.Sla) != 1 || !wire.Sla[0].Pass || wire.Sla[0].Metric != "p99" {
			t.Fatalf("sla lost: %+v", wire.Sla)
		}
		if len(wire.Timeline) != 1 || wire.Timeline[0].RequestsTotal != 50 {
			t.Fatalf("timeline lost: %+v", wire.Timeline)
		}
		// Assert: round trip preserves the values (timestamps are normalized
		// from start+duration, which are consistent here).
		if back.Name != rep.Name || back.BaseURL != rep.BaseURL || back.TotalRequests != 100 {
			t.Fatalf("round trip identity lost: %+v", back)
		}
		if !back.StartedAt.Equal(start) || !back.EndedAt.Equal(start.Add(duration)) || back.Duration != duration {
			t.Fatalf("round trip timing lost: start=%s end=%s dur=%s", back.StartedAt, back.EndedAt, back.Duration)
		}
		if back.Overall.P99 != 45*time.Millisecond || back.Overall.Errors != 4 {
			t.Fatalf("round trip overall lost: %+v", back.Overall)
		}
		if len(back.Steps) != 1 || back.Steps[0].Requests != 100 {
			t.Fatalf("round trip steps lost: %+v", back.Steps)
		}
		if len(back.SLA) != 1 || back.SLA[0].Actual != "45ms" {
			t.Fatalf("round trip sla lost: %+v", back.SLA)
		}
		if len(back.Timeline) != 1 || back.Timeline[0].Requests != 50 {
			t.Fatalf("round trip timeline lost: %+v", back.Timeline)
		}
	})

	t.Run("sla helpers", func(t *testing.T) {
		in := []report.SLAResult{
			{Metric: "error_rate", Target: "<=1%", Actual: "0.5%", Pass: true},
			{Metric: "rps", Target: ">=100", Actual: "90", Pass: false},
		}
		wire := slaResultsToProto(in)
		if len(wire) != 2 || wire[1].Metric != "rps" || wire[1].Pass {
			t.Fatalf("slaResultsToProto = %+v", wire)
		}
		back := slaResultsFromProto(wire)
		if len(back) != 2 || back[0].Target != "<=1%" || back[1].Actual != "90" {
			t.Fatalf("slaResultsFromProto = %+v", back)
		}
		if got := slaResultsToProto(nil); len(got) != 0 {
			t.Fatalf("slaResultsToProto(nil) = %+v", got)
		}
	})
}

// ---------------------------------------------------------------------------
// split.go / aggregator.go — small deterministic helpers
// ---------------------------------------------------------------------------

func TestUnitSplitUsers(t *testing.T) {
	tests := []struct {
		name         string
		users, index int
		total        int
		want         int
	}{
		{"even split", 10, 0, 2, 5},
		{"remainder to first", 10, 0, 3, 4},
		{"remainder exhausted", 10, 2, 3, 3},
		{"zero workers", 10, 0, 0, 0},
		{"negative workers", 10, 0, -2, 0},
		{"zero users", 0, 0, 3, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := SplitUsers(tc.users, tc.index, tc.total); got != tc.want {
				t.Fatalf("SplitUsers(%d,%d,%d) = %d, want %d", tc.users, tc.index, tc.total, got, tc.want)
			}
		})
	}

	sum := 0
	for i := 0; i < 3; i++ {
		sum += SplitUsers(100, i, 3)
	}
	if sum != 100 {
		t.Fatalf("shares sum to %d, want 100", sum)
	}
}

// TestUnitAggregatorRejectsOlderSnapshot pins run-internal replay protection:
// an older signed snapshot must not roll back a worker's live counters. The
// timestamp is part of the signed digest, so a replay cannot bump it.
func TestUnitAggregatorRejectsOlderSnapshot(t *testing.T) {
	a := NewAggregator()
	newer := &distproto.TelemetrySnapshot{Timestamp: 200, TotalRequests: 20}
	if !a.UpdateVerified("w1", newer, true) {
		t.Fatal("newer snapshot was refused")
	}
	older := &distproto.TelemetrySnapshot{Timestamp: 100, TotalRequests: 10}
	if a.UpdateVerified("w1", older, true) {
		t.Fatal("older snapshot overwrote a newer one")
	}
	if got, _ := a.SnapshotOf("w1"); got.GetTotalRequests() != 20 {
		t.Fatalf("counters rolled back: total = %d, want 20", got.GetTotalRequests())
	}
	// An exact re-send (equal timestamp) is harmless and must still be accepted.
	if !a.UpdateVerified("w1", &distproto.TelemetrySnapshot{Timestamp: 200, TotalRequests: 20}, true) {
		t.Fatal("exact replay with equal timestamp was refused")
	}
	// A strictly newer snapshot is accepted.
	if !a.UpdateVerified("w1", &distproto.TelemetrySnapshot{Timestamp: 300, TotalRequests: 30}, true) {
		t.Fatal("newer snapshot was refused")
	}
	// Disconnect forgets live state, so a fresh run can start from any timestamp.
	a.Forget("w1")
	if !a.UpdateVerified("w1", older, true) {
		t.Fatal("fresh snapshot refused after Forget")
	}
}

func TestUnitAggregatorRequireVerified(t *testing.T) {
	a := NewAggregator()
	if a.RequireVerified() {
		t.Fatal("new aggregator must not require verification")
	}

	a.SetRequireVerified(true)
	if !a.RequireVerified() {
		t.Fatal("RequireVerified must reflect SetRequireVerified(true)")
	}

	snap := &distproto.TelemetrySnapshot{TotalRequests: 1}
	if a.Update("w1", snap) {
		t.Fatal("strict aggregator accepted an unverified snapshot")
	}
	if got := a.RejectedCount(); got != 1 {
		t.Fatalf("RejectedCount = %d, want 1", got)
	}
	if !a.UpdateVerified("w1", snap, true) {
		t.Fatal("strict aggregator refused a verified snapshot")
	}
	if got, ok := a.SnapshotOf("w1"); !ok || got.TotalRequests != 1 {
		t.Fatalf("verified snapshot not stored: %+v ok=%v", got, ok)
	}

	a.SetRequireVerified(false)
	if a.RequireVerified() {
		t.Fatal("RequireVerified must reflect SetRequireVerified(false)")
	}
	if !a.Update("w2", snap) {
		t.Fatal("non-strict aggregator refused an unverified snapshot")
	}
	if a.Update("w3", nil) {
		t.Fatal("nil snapshot must never be stored")
	}
}

// ---------------------------------------------------------------------------
// master.go — deterministic control-plane paths
// ---------------------------------------------------------------------------

func TestUnitMasterAccessorsAndPins(t *testing.T) {
	kp := unitKeypair()
	m := NewMaster(MasterConfig{
		Scenario:          &config.Scenario{Name: "s", Profile: config.Profile{Users: 42}},
		Logf:              unitNoopLogf,
		AuthorizedWorkers: map[string]string{"w1": attest.PublicKeyHex(kp.Public), "broken": "not-hex"},
	})

	select {
	case <-m.Done():
		t.Fatal("Done must be open before the run finishes")
	default:
	}
	if m.RunID() != "" {
		t.Fatalf("RunID = %q, want empty before StartRun", m.RunID())
	}
	if m.Aggregator() == nil || !m.Aggregator().RequireVerified() {
		t.Fatal("configured allowlist must enable strict aggregation")
	}

	pub, ok := m.AuthorizedWorkerPub("w1")
	if !ok || !bytes.Equal(pub, kp.Public) {
		t.Fatalf("pinned key = %x ok=%v, want %x", pub, ok, kp.Public)
	}
	if _, ok := m.AuthorizedWorkerPub("broken"); ok {
		t.Fatal("invalid pin must be dropped (fail closed)")
	}
	if _, ok := m.AuthorizedWorkerPub("unknown"); ok {
		t.Fatal("unknown worker must have no pinned key")
	}
}

func TestUnitMasterCoordinateStatus(t *testing.T) {
	getStatus := &distproto.WorkerCommand{
		Payload: &distproto.WorkerCommand_GetStatus{GetStatus: &distproto.GetStatus{}},
	}

	t.Run("replies with master status then returns on EOF", func(t *testing.T) {
		m := NewMaster(MasterConfig{Logf: unitNoopLogf})
		stream := &unitCommandStream{cmds: []*distproto.WorkerCommand{getStatus}}

		err := m.Coordinate(stream)

		if !errors.Is(err, io.EOF) {
			t.Fatalf("Coordinate error = %v, want io.EOF", err)
		}
		if len(stream.responses) != 1 {
			t.Fatalf("responses = %d, want 1", len(stream.responses))
		}
		sr := stream.responses[0].GetStatusReport()
		if sr == nil || sr.WorkerId != "master" || !sr.Healthy {
			t.Fatalf("status reply = %+v", sr)
		}
	})

	t.Run("propagates send errors", func(t *testing.T) {
		wantErr := errors.New("send failed")
		m := NewMaster(MasterConfig{Logf: unitNoopLogf})
		stream := &unitCommandStream{cmds: []*distproto.WorkerCommand{getStatus}, sendErr: wantErr}

		err := m.Coordinate(stream)

		if !errors.Is(err, wantErr) {
			t.Fatalf("Coordinate error = %v, want %v", err, wantErr)
		}
	})
}

func TestUnitMasterPingAndCapabilities(t *testing.T) {
	m := NewMaster(MasterConfig{
		Scenario: &config.Scenario{Name: "s", Profile: config.Profile{Users: 42}},
		Logf:     unitNoopLogf,
	})

	ping, err := m.Ping(context.Background(), &distproto.PingRequest{})
	if err != nil || ping.Version != Version || ping.WorkerId != "master" {
		t.Fatalf("Ping = %+v, %v", ping, err)
	}

	caps, err := m.GetCapabilities(context.Background(), &distproto.CapabilitiesRequest{})
	if err != nil {
		t.Fatalf("GetCapabilities error: %v", err)
	}
	if caps.MaxUsers != 42 || caps.MaxDurationSec <= 0 || !caps.SupportsTls || !caps.SupportsSessions {
		t.Fatalf("capabilities = %+v", caps)
	}
	found := false
	for _, p := range caps.Protocols {
		if p == "grpc" {
			found = true
		}
	}
	if !found {
		t.Fatalf("grpc protocol missing: %v", caps.Protocols)
	}
}

func TestUnitMasterStartRunFailuresAndForceDone(t *testing.T) {
	m := NewMaster(MasterConfig{
		Scenario: &config.Scenario{Name: "s", Profile: config.Profile{Users: 2}},
		Logf:     unitNoopLogf,
	})

	err := m.StartRun(context.Background(), "run-1")
	if err == nil || !strings.Contains(err.Error(), "no connected workers") {
		t.Fatalf("StartRun error = %v, want 'no connected workers'", err)
	}
	if m.RunID() != "run-1" {
		t.Fatalf("RunID = %q, want run-1", m.RunID())
	}
	select {
	case <-m.Done():
		t.Fatal("Done must stay open after a failed StartRun")
	default:
	}

	// A rejected start must stay retryable: it never committed m.started, so
	// the second attempt fails for the same reason (no workers) instead of
	// being permanently locked out with "run already started".
	err = m.StartRun(context.Background(), "run-2")
	if err == nil || !strings.Contains(err.Error(), "no connected workers") {
		t.Fatalf("second StartRun error = %v, want 'no connected workers'", err)
	}
	if m.started {
		t.Fatal("failed StartRun must not leave the master in started state")
	}

	// Two never-reporting workers: forceDone must synthesize failure evidence
	// and close the run without any timers or goroutines.
	m.clients["w1"] = nil
	m.clients["w2"] = nil
	m.forceDone()

	select {
	case <-m.Done():
	default:
		t.Fatal("Done must be closed by forceDone")
	}
	if m.runEndedAt.IsZero() {
		t.Fatal("forceDone must record an end time")
	}
	if got := m.FailedWorkers(); len(got) != 2 {
		t.Fatalf("FailedWorkers = %v, want two entries", got)
	}
	if len(m.reports) != 2 {
		t.Fatalf("partial reports = %d, want 2", len(m.reports))
	}
}

func TestUnitMasterStopRunAndReportHelpers(t *testing.T) {
	m := NewMaster(MasterConfig{
		Scenario: &config.Scenario{Name: "s", Profile: config.Profile{Users: 2}},
		Logf:     unitNoopLogf,
	})

	// No streams registered: StopRun is a deterministic no-op.
	m.StopRun("run-x", true)
	select {
	case <-m.Done():
		t.Fatal("StopRun must not close Done")
	default:
	}

	m.touch("w1")
	if m.lastSeen["w1"].IsZero() {
		t.Fatal("touch did not record lastSeen")
	}

	m.storeReport("w1", nil)
	if len(m.reports) != 0 {
		t.Fatalf("nil report must be ignored: %v", m.reports)
	}
	m.storeReport("w2", ReportToProto(&report.Report{Name: "r", TotalRequests: 7}))
	if got := m.reports["w2"]; got == nil || got.TotalRequests != 7 {
		t.Fatalf("stored report = %+v", got)
	}
	merged := m.FinalReport()
	if merged == nil || merged.TotalRequests != 7 {
		t.Fatalf("FinalReport = %+v", merged)
	}
	if got := m.PartialReportForTest("no-such-worker"); got != nil {
		t.Fatalf("PartialReportForTest without evidence = %+v, want nil", got)
	}
}

// ---------------------------------------------------------------------------
// worker.go — deterministic command handling
// ---------------------------------------------------------------------------

func TestUnitWorkerAccessors(t *testing.T) {
	w := NewWorker(WorkerConfig{ID: "w1", MaxUsers: 25, Logf: unitNoopLogf})

	if w.ID() != "w1" || w.ActiveRuns() != 0 {
		t.Fatalf("identity = %q active=%d", w.ID(), w.ActiveRuns())
	}

	ping, err := w.Ping(context.Background(), &distproto.PingRequest{})
	if err != nil || ping.WorkerId != "w1" || ping.Version != Version {
		t.Fatalf("Ping = %+v, %v", ping, err)
	}

	capsRPC, err := w.GetCapabilities(context.Background(), &distproto.CapabilitiesRequest{})
	if err != nil {
		t.Fatalf("GetCapabilities error: %v", err)
	}
	caps := w.Capabilities()
	if caps.MaxUsers != 25 || capsRPC.MaxUsers != 25 || caps.MaxDurationSec <= 0 {
		t.Fatalf("capabilities = %+v / rpc=%+v", caps, capsRPC)
	}

	w.activeRuns["r1"] = &runContext{runID: "r1"}
	if w.ActiveRuns() != 1 {
		t.Fatalf("ActiveRuns = %d, want 1", w.ActiveRuns())
	}
	w.removeRun("r1")
	if w.ActiveRuns() != 0 {
		t.Fatalf("ActiveRuns after removeRun = %d, want 0", w.ActiveRuns())
	}
}

func TestUnitWorkerCoordinateStartRunFailures(t *testing.T) {
	tests := []struct {
		name        string
		start       *distproto.StartRun
		setup       func(*Worker)
		wantErrPart string
	}{
		{
			name:        "nil scenario",
			start:       &distproto.StartRun{RunId: "r"},
			wantErrPart: "invalid scenario",
		},
		{
			name:        "users above max",
			start:       &distproto.StartRun{RunId: "r", Scenario: unitScenarioProto(11, 1)},
			wantErrPart: "exceeds max-users",
		},
		{
			name:  "max concurrent runs",
			start: &distproto.StartRun{RunId: "new", Scenario: unitScenarioProto(1, 1)},
			setup: func(w *Worker) {
				w.cfg.MaxConcurrentRuns = 1
				w.activeRuns["busy"] = &runContext{runID: "busy"}
			},
			wantErrPart: "max concurrent runs",
		},
		{
			name:  "duplicate run id",
			start: &distproto.StartRun{RunId: "dup", Scenario: unitScenarioProto(1, 1)},
			setup: func(w *Worker) {
				w.activeRuns["dup"] = &runContext{runID: "dup"}
			},
			wantErrPart: "already active",
		},
		{
			name:        "engine rejects scenario",
			start:       &distproto.StartRun{RunId: "r", Scenario: unitScenarioProto(1, 0)},
			wantErrPart: "at least one step",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange.
			w := NewWorker(WorkerConfig{ID: "w", MaxUsers: 10, Logf: unitNoopLogf})
			if tc.setup != nil {
				tc.setup(w)
			}
			stream := &unitCommandStream{cmds: []*distproto.WorkerCommand{{
				Payload: &distproto.WorkerCommand_StartRun{StartRun: tc.start},
			}}}

			// Act.
			err := w.Coordinate(stream)

			// Assert: one RunFailure is emitted and the loop exits on EOF. No
			// engine goroutines are started on any of these rejection paths.
			if !errors.Is(err, io.EOF) {
				t.Fatalf("Coordinate error = %v, want io.EOF", err)
			}
			if w.ActiveRuns() != len(w.activeRuns) {
				t.Fatalf("unexpected active run count: %d", w.ActiveRuns())
			}
			if len(stream.responses) != 1 {
				t.Fatalf("responses = %d, want 1", len(stream.responses))
			}
			failed := stream.responses[0].GetRunFailed()
			if failed == nil || failed.RunId != tc.start.RunId ||
				!strings.Contains(failed.Error, tc.wantErrPart) {
				t.Fatalf("RunFailed = %+v, want error containing %q", failed, tc.wantErrPart)
			}
		})
	}
}

func TestUnitWorkerSendAndStatus(t *testing.T) {
	t.Run("send propagates stream errors", func(t *testing.T) {
		wantErr := errors.New("stream broken")
		w := NewWorker(WorkerConfig{ID: "w", Logf: unitNoopLogf})
		stream := &unitCommandStream{sendErr: wantErr}

		err := w.send(stream, &distproto.WorkerEvent{})

		if !errors.Is(err, wantErr) {
			t.Fatalf("send error = %v, want %v", err, wantErr)
		}
		// sendFailure is best-effort and must not panic on a broken stream.
		w.sendFailure(stream, "r", "message")
	})

	t.Run("get-status emits status report and other commands are safe", func(t *testing.T) {
		w := NewWorker(WorkerConfig{ID: "w", Logf: unitNoopLogf})
		stream := &unitCommandStream{cmds: []*distproto.WorkerCommand{
			{Payload: &distproto.WorkerCommand_GetStatus{GetStatus: &distproto.GetStatus{}}},
			{Payload: &distproto.WorkerCommand_MigrateSession{MigrateSession: &distproto.MigrateSession{
				SessionId: "s1", TargetWorker: "w2",
			}}},
			{}, // no payload: ignored by the Coordinate switch
		}}

		err := w.Coordinate(stream)

		if !errors.Is(err, io.EOF) {
			t.Fatalf("Coordinate error = %v, want io.EOF", err)
		}
		if len(stream.responses) != 1 {
			t.Fatalf("responses = %d, want 1", len(stream.responses))
		}
		sr := stream.responses[0].GetStatusReport()
		if sr == nil || sr.WorkerId != "w" || !sr.Healthy || sr.ActiveRuns != 0 || sr.System == nil {
			t.Fatalf("status report = %+v", sr)
		}
	})

	t.Run("signed status carries a signature", func(t *testing.T) {
		w := NewWorker(WorkerConfig{ID: "w", Keypair: unitKeypair(), Logf: unitNoopLogf})
		stream := &unitCommandStream{cmds: []*distproto.WorkerCommand{{
			Payload: &distproto.WorkerCommand_GetStatus{GetStatus: &distproto.GetStatus{}},
		}}}

		if err := w.Coordinate(stream); !errors.Is(err, io.EOF) {
			t.Fatalf("Coordinate error = %v, want io.EOF", err)
		}
		if len(stream.responses) != 1 || len(stream.responses[0].GetStatusReport().Signature) == 0 {
			t.Fatalf("signed status missing signature: %+v", stream.responses)
		}
	})
}

func TestUnitWorkerStopAndCpuSampling(t *testing.T) {
	w := NewWorker(WorkerConfig{ID: "w", Logf: unitNoopLogf})
	w.activeRuns["r1"] = &runContext{runID: "r1", cancel: func() {}}

	// nil stop is a no-op; a real stop cancels the tracked run but leaves it in
	// the map for runStream's deferred removeRun.
	w.handleStopRun(nil)
	w.handleStopRun(&distproto.StopRun{RunId: "r1", Graceful: true})
	if w.ActiveRuns() != 1 {
		t.Fatalf("handleStopRun must not delete the run directly: %d", w.ActiveRuns())
	}

	// First CPU sample has no baseline; subsequent samples are clamped >= 0.
	if got := w.cpuPercent(); got != 0 {
		t.Fatalf("first cpuPercent = %v, want 0", got)
	}
	if got := w.cpuPercent(); got < 0 {
		t.Fatalf("cpuPercent = %v, want >= 0", got)
	}
}

func TestUnitWorkerAttestHelpers(t *testing.T) {
	t.Run("signed progress and completion", func(t *testing.T) {
		w := NewWorker(WorkerConfig{ID: "w", Keypair: unitKeypair(), Logf: unitNoopLogf})
		rp := &distproto.RunProgress{
			RunId: "r", Timestamp: 123,
			Telemetry: &distproto.TelemetrySnapshot{TotalRequests: 1},
		}
		rc := &distproto.RunCompleted{
			RunId: "r", Timestamp: 123,
			Report: &distproto.Report{Name: "r"},
		}

		if err := w.attestProgress(rp); err != nil {
			t.Fatalf("attestProgress: %v", err)
		}
		if err := w.attestCompleted(rc); err != nil {
			t.Fatalf("attestCompleted: %v", err)
		}
		if rp.WorkerId != "w" || len(rp.Signature) == 0 {
			t.Fatalf("progress not signed: %+v", rp)
		}
		if rc.WorkerId != "w" || len(rc.Signature) == 0 {
			t.Fatalf("completion not signed: %+v", rc)
		}
	})

	t.Run("nil inputs and unattested worker", func(t *testing.T) {
		signed := NewWorker(WorkerConfig{ID: "w", Keypair: unitKeypair(), Logf: unitNoopLogf})
		if err := signed.attestProgress(nil); err != nil {
			t.Fatalf("attestProgress(nil): %v", err)
		}
		if err := signed.attestCompleted(nil); err != nil {
			t.Fatalf("attestCompleted(nil): %v", err)
		}

		plain := NewWorker(WorkerConfig{ID: "w", Logf: unitNoopLogf})
		rp := &distproto.RunProgress{RunId: "r"}
		rc := &distproto.RunCompleted{RunId: "r"}
		if err := plain.attestProgress(rp); err != nil {
			t.Fatalf("unattested attestProgress: %v", err)
		}
		if err := plain.attestCompleted(rc); err != nil {
			t.Fatalf("unattested attestCompleted: %v", err)
		}
		if rp.WorkerId != "" || len(rp.Signature) != 0 || rc.WorkerId != "" || len(rc.Signature) != 0 {
			t.Fatalf("unattested worker must leave telemetry unsigned: %+v %+v", rp, rc)
		}
	})
}

// ---------------------------------------------------------------------------
// client-stream driven master receive loop
// ---------------------------------------------------------------------------

// unitEventStream fakes the client side of the Coordinate stream so recvLoop
// can be exercised without a network or a goroutine.
type unitEventStream struct {
	grpc.ClientStream
	events  []*distproto.WorkerEvent
	idx     int
	recvErr error
	closed  bool
}

func (s *unitEventStream) Recv() (*distproto.WorkerEvent, error) {
	if s.idx >= len(s.events) {
		if s.recvErr != nil {
			return nil, s.recvErr
		}
		return nil, io.EOF
	}
	event := s.events[s.idx]
	s.idx++
	return event, nil
}

func (s *unitEventStream) Send(*distproto.WorkerCommand) error { return nil }
func (s *unitEventStream) CloseSend() error {
	s.closed = true
	return nil
}

func TestUnitMasterRecvLoop(t *testing.T) {
	t.Run("progress, status and completion are stored", func(t *testing.T) {
		m := NewMaster(MasterConfig{Logf: unitNoopLogf})
		stream := &unitEventStream{events: []*distproto.WorkerEvent{
			{Payload: &distproto.WorkerEvent_RunProgress{RunProgress: &distproto.RunProgress{
				RunId: "r", Telemetry: &distproto.TelemetrySnapshot{TotalRequests: 12, TotalErrors: 1},
			}}},
			{Payload: &distproto.WorkerEvent_RunStarted{RunStarted: &distproto.RunStarted{RunId: "r"}}},
			{Payload: &distproto.WorkerEvent_StatusReport{StatusReport: &distproto.StatusReport{
				WorkerId: "w", Healthy: true, ActiveRuns: 1,
			}}},
			{Payload: &distproto.WorkerEvent_RunCompleted{RunCompleted: &distproto.RunCompleted{
				RunId: "r", Report: &distproto.Report{Name: "r", TotalRequests: 12},
			}}},
		}}

		m.recvLoop("w1", stream)

		if snap, ok := m.agg.SnapshotOf("w1"); !ok || snap.TotalRequests != 12 {
			t.Fatalf("aggregated progress = %+v ok=%v", snap, ok)
		}
		if sr := m.statusReports["w1"]; sr == nil || !sr.Healthy || sr.ActiveRuns != 1 {
			t.Fatalf("stored status = %+v", sr)
		}
		if rep := m.reports["w1"]; rep == nil || rep.TotalRequests != 12 {
			t.Fatalf("stored final report = %+v", rep)
		}
		if !m.finished["w1"] {
			t.Fatal("completion must mark the worker finished")
		}
	})

	t.Run("run failed event records the reason", func(t *testing.T) {
		m := NewMaster(MasterConfig{Logf: unitNoopLogf})
		stream := &unitEventStream{events: []*distproto.WorkerEvent{{
			Payload: &distproto.WorkerEvent_RunFailed{RunFailed: &distproto.RunFailed{
				RunId: "r", Error: "engine crashed",
			}},
		}}}

		m.recvLoop("w2", stream)

		if m.failureReasons["w2"] != "engine crashed" {
			t.Fatalf("failure reason = %q", m.failureReasons["w2"])
		}
		if got := m.FailedWorkers(); len(got) != 1 || got[0] != "w2" {
			t.Fatalf("FailedWorkers = %v", got)
		}
	})

	t.Run("recv error synthesizes failure evidence", func(t *testing.T) {
		m := NewMaster(MasterConfig{
			Scenario: &config.Scenario{Name: "s", Profile: config.Profile{Users: 1}},
			Logf:     unitNoopLogf,
		})
		stream := &unitEventStream{recvErr: errors.New("transport gone")}

		m.recvLoop("w3", stream)

		if m.failureReasons["w3"] != "transport gone" {
			t.Fatalf("failure reason = %q", m.failureReasons["w3"])
		}
		if rep := m.reports["w3"]; rep == nil {
			t.Fatal("disconnected worker must keep a partial failure report")
		}
	})
}

func TestUnitMasterLivenessLoopReturnsOnDone(t *testing.T) {
	m := NewMaster(MasterConfig{Logf: unitNoopLogf})
	m.forceDone() // closes doneCh so the loop exits on its first select

	// The loop must not block or touch any worker once the run is done.
	m.livenessLoop([]string{"w1"})
}

func TestUnitTLSOptionsEnabled(t *testing.T) {
	tests := []struct {
		name string
		opts TLSOptions
		want bool
	}{
		{"none", TLSOptions{}, false},
		{"cert only", TLSOptions{CertFile: "server.crt"}, false},
		{"key only", TLSOptions{KeyFile: "server.key"}, false},
		{"both", TLSOptions{CertFile: "server.crt", KeyFile: "server.key"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.opts.Enabled(); got != tc.want {
				t.Fatalf("Enabled() = %v, want %v", got, tc.want)
			}
		})
	}
}
