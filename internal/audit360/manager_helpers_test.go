package audit360

import (
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
	wantIDs := []string{StageScan, StageStress, StageResilience, StageSeal}
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

	applyStageUpdate(st, StageStress, StatusFailed, "", "boom")
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
