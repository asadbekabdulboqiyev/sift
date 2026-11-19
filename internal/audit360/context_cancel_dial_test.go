package audit360

// context_cancel_dial_test.go - a cancelled audit must not keep sending traffic.
//
// Run treats cancellation as "the caller no longer wants this run" (retention
// eviction, shutdown, user abort). The security stage must therefore stop
// dialing once its context is done. Before the fix it launched the scanner
// goroutine and an explicit reachability dial unconditionally, so a cancelled
// run still sent packets to the target.

import (
	"context"
	"testing"
	"time"
)

// TestRunSecurityScanHonorsCancelledContext verifies that a scan whose context
// is already cancelled performs no network dial at all. The dial-counting
// control records every attempted connection (it rejects them, so no real
// traffic leaves the process), making a regression unambiguous.
func TestRunSecurityScanHonorsCancelledContext(t *testing.T) {
	target := localTarget(t)
	c := &dialCounter{}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, _ = runSecurityScan(ctx, target, c.control)

	if n := c.count(); n != 0 {
		t.Fatalf("runSecurityScan attempted %d dial(s) after ctx was cancelled, want 0", n)
	}
}

// TestRunStressTestHonorsCancelledContext verifies that the stress stage does
// not send its reachability probe once the run has been cancelled.
func TestRunStressTestHonorsCancelledContext(t *testing.T) {
	target := localTarget(t)
	c := &dialCounter{}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_ = runStressTest(ctx, target, time.Second, c.control)

	if n := c.count(); n != 0 {
		t.Fatalf("runStressTest attempted %d dial(s) after ctx was cancelled, want 0", n)
	}
}
