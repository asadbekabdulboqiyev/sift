package audit360

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"syscall"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/attest"
)

// Manager runs and tracks Sift 360° jobs.
type Manager struct {
	mu   sync.RWMutex
	jobs map[string]*job

	// signerPath, when set, is the persistent Ed25519 key every report is
	// sealed with, so the seal names a stable identity a verifier can pin.
	signerMu   sync.Mutex
	signerPath string
	signer     *attest.Keypair
}

type job struct {
	mu        sync.RWMutex
	status    JobStatus
	report    *Audit360Report
	subs      map[chan Event]struct{}
	cancel    context.CancelFunc
	demoStore string
	mode      string
}

func NewManager() *Manager {
	return &Manager{jobs: make(map[string]*job)}
}

// NewManagerWithSignerKey seals every report with the key stored at path,
// creating it on first use (mode 0600).
//
// Without this the manager mints a throwaway key per run, and the public key
// travels inside the signed payload — so verification can only show that a file
// is self-consistent, not who produced it. A persistent key is what makes
// `sift audit360 verify --key <hex>` meaningful.
func NewManagerWithSignerKey(path string) *Manager {
	m := NewManager()
	m.signerPath = path
	return m
}

// signerKeypair returns the configured signing identity, loading it once.
// A nil keypair with a non-nil error means the caller asked for a persistent
// identity but it could not be loaded; the run still seals, and the report
// records why it fell back to an ephemeral key.
func (m *Manager) signerKeypair() (*attest.Keypair, error) {
	if m.signerPath == "" {
		return nil, nil
	}
	m.signerMu.Lock()
	defer m.signerMu.Unlock()
	if m.signer != nil {
		return m.signer, nil
	}
	kp, _, err := attest.LoadOrCreateKeypairPEM(m.signerPath)
	if err != nil {
		return nil, err
	}
	m.signer = kp
	return kp, nil
}

// Start starts an audit with no dial control. It keeps the original API for
// callers that do not enforce authz on the resolved socket address.
func (m *Manager) Start(ctx context.Context, target string, maxDur time.Duration, demoStoreURL, mode string) (string, error) {
	return m.StartWithControl(ctx, target, maxDur, demoStoreURL, mode, nil)
}

// StartWithControl starts an audit and installs control on every dial the run
// makes, so the gate can refuse a socket whose resolved peer address falls
// outside the approved target class. Nil keeps the original dial behaviour.
func (m *Manager) StartWithControl(ctx context.Context, target string, maxDur time.Duration, demoStoreURL, mode string, control func(network, address string, c syscall.RawConn) error) (string, error) {
	id := newJobID()
	stages := defaultStages()
	now := time.Now()
	if mode == "" {
		mode = ModeStandard
	}
	st := JobStatus{
		JobID:        id,
		TargetURL:    target,
		State:        "queued",
		StartedAt:    now,
		UpdatedAt:    now,
		CurrentStage: "",
		Stages:       stages,
		ProgressPct:  0,
	}
	runCtx, cancel := context.WithCancel(ctx)
	j := &job{
		status:    st,
		subs:      make(map[chan Event]struct{}),
		cancel:    cancel,
		demoStore: demoStoreURL,
		mode:      mode,
	}
	m.mu.Lock()
	// Simple retention: keep at most 20 jobs, preferring to evict completed/failed
	// jobs and avoiding eviction of running/queued jobs when possible.
	for len(m.jobs) >= 20 {
		evict := ""
		var evictAt time.Time
		for k, v := range m.jobs {
			st := v.snapshot()
			if st == nil {
				evict = k
				break
			}
			if st.State == "running" || st.State == "queued" {
				continue
			}
			finished := st.FinishedAt
			if finished.IsZero() {
				finished = st.UpdatedAt
			}
			if finished.IsZero() {
				finished = st.StartedAt
			}
			if evict == "" || finished.Before(evictAt) || evictAt.IsZero() {
				evict = k
				evictAt = finished
			}
		}
		if evict == "" {
			// All jobs appear active; evict one arbitrary entry as last resort.
			for k := range m.jobs {
				evict = k
				break
			}
		}
		if victim, ok := m.jobs[evict]; ok {
			// An evicted job may still be running (the all-active fallback
			// above picks an arbitrary entry), and its status is no longer
			// reachable through Get, so stop it instead of letting it scan a
			// target nobody can observe. Without this the per-job context is
			// only released when the parent context dies.
			if victim.cancel != nil {
				victim.cancel()
			}
			delete(m.jobs, evict)
		}
	}
	m.jobs[id] = j
	m.mu.Unlock()

	go m.run(runCtx, j, target, maxDur, control)
	return id, nil
}

func (m *Manager) run(ctx context.Context, j *job, target string, maxDur time.Duration, control func(network, address string, c syscall.RawConn) error) {
	// Release the per-job context when the run ends, whichever way it ends.
	// `job.cancel` was stored but never called, so every finished audit left a
	// live cancel func and a child context attached to the caller's context
	// until the caller itself was cancelled (gosec G118).
	defer j.cancel()
	j.update(func(s *JobStatus) {
		s.State = "running"
		s.UpdatedAt = time.Now()
		s.CurrentStage = StageScan
	})
	j.publishStatus()

	kp, kerr := m.signerKeypair()
	rep, err := Run(ctx, Options{TargetURL: target, MaxDuration: maxDur, DemoStoreURL: j.demoStore, Mode: j.mode, DialControl: control, SignerKey: kp, SignerKeyErr: kerr}, func(stageID, status, detail, errMsg string) {
		j.update(func(s *JobStatus) {
			applyStageUpdate(s, stageID, status, detail, errMsg)
		})
		j.publishStatus()
	})
	if err != nil {
		j.update(func(s *JobStatus) {
			s.State = "failed"
			s.Error = err.Error()
			s.FinishedAt = time.Now()
			s.UpdatedAt = s.FinishedAt
			s.ProgressPct = progressFromStages(s.Stages)
		})
		j.publish(Event{Type: "failed", Status: j.snapshot(), Error: err.Error()})
		return
	}

	j.mu.Lock()
	j.report = rep
	j.mu.Unlock()
	j.update(func(s *JobStatus) {
		s.State = "completed"
		s.Report = rep
		s.FinishedAt = time.Now()
		s.UpdatedAt = s.FinishedAt
		s.CurrentStage = ""
		markAllDone(s)
		s.ProgressPct = 100
	})
	j.publish(Event{Type: "completed", Status: j.snapshot(), Report: rep})
}

func (m *Manager) Get(jobID string) (*JobStatus, bool) {
	m.mu.RLock()
	j, ok := m.jobs[jobID]
	m.mu.RUnlock()
	if !ok {
		return nil, false
	}
	st := j.snapshot()
	return st, true
}

func (m *Manager) Subscribe(jobID string) (<-chan Event, func(), bool) {
	m.mu.RLock()
	j, ok := m.jobs[jobID]
	m.mu.RUnlock()
	if !ok {
		return nil, nil, false
	}
	ch := make(chan Event, 16)
	j.mu.Lock()
	j.subs[ch] = struct{}{}
	// send immediate snapshot
	snap := j.snapshotLocked()
	j.mu.Unlock()
	// A finished job will never publish again, so a late subscriber has to be
	// handed the terminal event right away. Sending only a "status" frame left
	// the SSE handler waiting for completed/failed until the client hung up.
	ev := Event{Type: "status", Status: snap}
	if snap != nil {
		switch snap.State {
		case "completed":
			ev = Event{Type: "completed", Status: snap}
		case "failed":
			ev = Event{Type: "failed", Status: snap, Error: snap.Error}
		}
	}
	select {
	case ch <- ev:
	default:
	}
	cancel := func() {
		j.mu.Lock()
		if _, ok := j.subs[ch]; ok {
			delete(j.subs, ch)
			close(ch)
		}
		j.mu.Unlock()
	}
	return ch, cancel, true
}

func (j *job) update(fn func(*JobStatus)) {
	j.mu.Lock()
	defer j.mu.Unlock()
	fn(&j.status)
	j.status.UpdatedAt = time.Now()
	j.status.ProgressPct = progressFromStages(j.status.Stages)
}

func (j *job) snapshot() *JobStatus {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.snapshotLocked()
}

func (j *job) snapshotLocked() *JobStatus {
	cp := j.status
	cp.Stages = append([]StageProgress(nil), j.status.Stages...)
	if j.report != nil {
		// copy pointer ok; report treated immutable after completion
		cp.Report = j.report
	}
	return &cp
}

func (j *job) publishStatus() {
	j.publish(Event{Type: "status", Status: j.snapshot()})
}

func (j *job) publish(ev Event) {
	j.mu.RLock()
	for ch := range j.subs {
		select {
		case ch <- ev:
		default:
			// drop if slow subscriber
		}
	}
	j.mu.RUnlock()
}

func defaultStages() []StageProgress {
	return []StageProgress{
		{ID: StageScan, Label: "Scanning Security", Status: StatusPending},
		{ID: StageStress, Label: "Testing Load Limit", Status: StatusPending},
		{ID: StageResilience, Label: "Calculating Resilience", Status: StatusPending},
		{ID: StageSeal, Label: "Sealing VPMP Certificate", Status: StatusPending},
	}
}

func applyStageUpdate(s *JobStatus, stageID, status, detail, errMsg string) {
	found := -1
	for i := range s.Stages {
		if s.Stages[i].ID == stageID {
			found = i
			break
		}
	}
	if found == -1 {
		return
	}
	st := &s.Stages[found]
	st.Status = status
	if detail != "" {
		st.Detail = detail
	}
	if errMsg != "" {
		st.Error = errMsg
	}
	now := time.Now()
	if status == StatusRunning && st.StartedAt.IsZero() {
		st.StartedAt = now
		s.CurrentStage = stageID
	}
	if status == StatusCompleted || status == StatusFailed || status == StatusSkipped {
		if st.StartedAt.IsZero() {
			st.StartedAt = now
		}
		st.EndedAt = now
		if s.CurrentStage == stageID {
			s.CurrentStage = ""
		}
	}
	s.ProgressPct = progressFromStages(s.Stages)
}

func markAllDone(s *JobStatus) {
	for i := range s.Stages {
		if s.Stages[i].Status == StatusPending || s.Stages[i].Status == StatusRunning {
			s.Stages[i].Status = StatusCompleted
			if s.Stages[i].EndedAt.IsZero() {
				s.Stages[i].EndedAt = time.Now()
			}
		}
	}
}

func progressFromStages(stages []StageProgress) int {
	if len(stages) == 0 {
		return 0
	}
	total := 0
	for _, st := range stages {
		switch st.Status {
		case StatusCompleted, StatusFailed, StatusSkipped:
			total += 100
		case StatusRunning:
			total += 45
		default:
			total += 0
		}
	}
	p := total / len(stages)
	if p < 0 {
		p = 0
	}
	if p > 100 {
		p = 100
	}
	return p
}

func newJobID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return hex.EncodeToString([]byte(time.Now().Format("20060102150405.000000000")))
	}
	return "a360-" + hex.EncodeToString(b[:])
}
