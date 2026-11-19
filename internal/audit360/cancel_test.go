package audit360

// cancel_test.go — a cancelled run must not be reported as a completed audit.
// Run ignored the caller's context, so a job cancelled by retention eviction or
// by a shutdown still walked through scoring and sealing, and the manager
// published "completed" with progress 100 and a signed certificate for a scan
// that never finished.

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestRunRejectsCancelledContext is the unit-level half: a cancelled parent
// context is an error, not a report.
func TestRunRejectsCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	rep, err := Run(ctx, Options{
		// .invalid never resolves, so even a regression cannot send traffic.
		TargetURL:   "http://audit360-cancelled.invalid/",
		MaxDuration: 5 * time.Second,
		Mode:        ModePassive,
	}, nil)

	if err == nil {
		t.Fatalf("Run with a cancelled context returned a report (score=%d, cert=%q)", rep.ResilienceScore, rep.CertificateID)
	}
	if rep != nil {
		t.Fatalf("a cancelled run must not return a report, got %+v", rep)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "cancel") {
		t.Fatalf("error should say the run was cancelled, got %v", err)
	}
}

// TestManagerMarksCancelledJobFailed is the end-to-end half: the job the
// dashboard and SSE clients see must be failed, with no report attached.
func TestManagerMarksCancelledJobFailed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := NewManagerWithSignerKey(filepath.Join(t.TempDir(), "audit360-key.pem"))
	id, err := m.Start(ctx, "http://audit360-cancelled.invalid/", 5*time.Second, "", ModePassive)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	deadline := time.Now().Add(30 * time.Second)
	for {
		st, ok := m.Get(id)
		if !ok {
			t.Fatalf("job %s disappeared", id)
		}
		if st.State == "completed" || st.State == "failed" {
			if st.State != "failed" {
				t.Fatalf("cancelled job state = %q, want failed (report=%v, progress=%d)",
					st.State, st.Report != nil, st.ProgressPct)
			}
			if st.Report != nil {
				t.Fatalf("a failed job must not carry a report, got %+v", st.Report)
			}
			if st.ProgressPct == 100 {
				t.Fatal("a failed job must not report 100% progress")
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("job did not reach a terminal state, state=%q", st.State)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
