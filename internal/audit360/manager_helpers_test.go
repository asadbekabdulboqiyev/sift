package audit360

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestNewManagerAndGetMissing(t *testing.T) {
	m := NewManager()
	if m == nil {
		t.Fatal("NewManager returned nil")
	}
	if st, ok := m.Get("missing"); ok || st != nil {
		t.Fatalf("Get(missing) = (%v,%v), want (nil,false)", st, ok)
	}
}

func TestNewJobIDFormat(t *testing.T) {
	id := newJobID()
	if !strings.HasPrefix(id, "a360-") {
		t.Fatalf("newJobID() = %q, want prefix a360-", id)
	}
	if len(id) != len("a360-")+24 {
		t.Fatalf("newJobID() len = %d, want %d", len(id), len("a360-")+24)
	}
}

func TestDefaultStagesAndProgress(t *testing.T) {
	stages := defaultStages()
	if len(stages) != 4 {
		t.Fatalf("len(defaultStages()) = %d, want 4", len(stages))
	}
	wantIDs := []string{StageScan, StageLoad, StageResilience, StageSeal}
	for i, id := range wantIDs {
		if stages[i].ID != id {
			t.Errorf("stage[%d].ID = %q, want %q", i, stages[i].ID, id)
		}
		if stages[i].Status != StatusPending {
			t.Errorf("stage[%d].Status = %q, want %q", i, stages[i].Status, StatusPending)
		}
	}
	if p := progressFromStages(nil); p != 0 {
		t.Errorf("progressFromStages(nil) = %d, want 0", p)
	}
	if p := progressFromStages(stages); p != 0 {
		t.Errorf("progressFromStages(pending) = %d, want 0", p)
	}

	stages[0].Status = StatusRunning
	if p := progressFromStages(stages); p != 11 { // 45/4 truncated
		t.Errorf("progressFromStages(one running) = %d, want 11", p)
	}

	for i := range stages {
		stages[i].Status = StatusCompleted
	}
	if p := progressFromStages(stages); p != 100 {
		t.Errorf("progressFromStages(all completed) = %d, want 100", p)
	}
}

func TestApplyStageUpdateAndMarkAllDone(t *testing.T) {
	st := &JobStatus{Stages: defaultStages()}
	applyStageUpdate(st, "unknown", StatusRunning, "x", "")
	if st.CurrentStage != "" {
		t.Fatalf("unknown stage changed current stage to %q", st.CurrentStage)
	}

	applyStageUpdate(st, StageScan, StatusRunning, "scanning", "")
	if st.CurrentStage != StageScan {
		t.Fatalf("CurrentStage = %q, want %q", st.CurrentStage, StageScan)
	}
	if st.Stages[0].StartedAt.IsZero() {
		t.Fatal("running stage StartedAt not set")
	}

	applyStageUpdate(st, StageScan, StatusCompleted, "done", "")
	if st.Stages[0].Status != StatusCompleted || st.Stages[0].EndedAt.IsZero() {
		t.Fatalf("completed stage not finalized: %+v", st.Stages[0])
	}
	if st.CurrentStage != "" {
		t.Fatalf("CurrentStage after completion = %q, want empty", st.CurrentStage)
	}

	applyStageUpdate(st, StageLoad, StatusFailed, "", "boom")
	if st.Stages[1].Status != StatusFailed || st.Stages[1].Error != "boom" {
		t.Fatalf("failed stage = %+v, want failed with error", st.Stages[1])
	}

	// markAllDone should complete any pending/running stages.
	st.Stages[2].Status = StatusPending
	st.Stages[3].Status = StatusRunning
	st.Stages[3].EndedAt = time.Time{}
	markAllDone(st)
	for i := 2; i < 4; i++ {
		if st.Stages[i].Status != StatusCompleted {
			t.Errorf("stage[%d].Status = %q, want completed", i, st.Stages[i].Status)
		}
		if st.Stages[i].EndedAt.IsZero() {
			t.Errorf("stage[%d].EndedAt not set", i)
		}
	}
}

// TestManagerSignerKeypairPersists is the difference between an attributable
// seal and a self-consistent one: the key is created once, kept on disk, and
// reused, so every report from this install names the same identity.
func TestManagerSignerKeypairPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit360-key.pem")
	m := NewManagerWithSignerKey(path)

	first, err := m.signerKeypair()
	if err != nil {
		t.Fatalf("signerKeypair: %v", err)
	}
	if first == nil || len(first.Private) != ed25519.PrivateKeySize {
		t.Fatal("signerKeypair did not return a usable key")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("key file not created: %v", err)
	}
	// Windows does not carry POSIX permission bits, so a mode assertion there
	// would fail for a file that is correctly created; the same policy applies
	// to the rest of the suite.
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(path); err == nil && info.Mode().Perm() != 0o600 {
			t.Fatalf("key file mode = %o, want 0600", info.Mode().Perm())
		}
	}

	second, err := m.signerKeypair()
	if err != nil {
		t.Fatalf("signerKeypair (cached): %v", err)
	}
	if !first.Public.Equal(second.Public) {
		t.Fatal("second call returned a different identity")
	}

	// A fresh manager over the same path must load the same key, not mint one.
	reopened, err := NewManagerWithSignerKey(path).signerKeypair()
	if err != nil {
		t.Fatalf("signerKeypair (reopen): %v", err)
	}
	if !first.Public.Equal(reopened.Public) {
		t.Fatal("reopened manager minted a new identity instead of loading the stored one")
	}
}

// TestManagerWithoutSignerKeyKeepsLegacyBehaviour: a manager built with
// NewManager has no path, so it seals with a per-run key exactly as before.
func TestManagerWithoutSignerKeyKeepsLegacyBehaviour(t *testing.T) {
	kp, err := NewManager().signerKeypair()
	if err != nil || kp != nil {
		t.Fatalf("signerKeypair without a path = (%v,%v), want (nil,nil)", kp, err)
	}
}
