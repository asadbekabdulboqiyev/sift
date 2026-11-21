package audit360

import (
	"context"
	"fmt"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"
)

// dialCounter is a rejecting Control callback that records every dial it
// intercepts. Returning an error makes the connection fail after the resolved
// peer address has already been observed, which is exactly where the authz
// decision has to run.
type dialCounter struct {
	mu    sync.Mutex
	calls int
}

func (d *dialCounter) control(network, address string, c syscall.RawConn) error {
	d.mu.Lock()
	d.calls++
	d.mu.Unlock()
	return fmt.Errorf("test: dial to %s refused", address)
}

func (d *dialCounter) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

func localTarget(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return "http://" + ln.Addr().String()
}

// TestProbeReachableUsesDialControl verifies that the reachability probe no
// longer bypasses the gate: a rejecting control makes the probe fail, and the
// control is actually invoked.
func TestProbeReachableUsesDialControl(t *testing.T) {
	target := localTarget(t)

	// Baseline: the listener is reachable without a control, so any change in
	// behaviour below is caused by the control and not by the test listener.
	if !probeReachable(target, time.Second, nil) {
		t.Fatal("baseline probe without control failed; test listener is not reachable")
	}

	c := &dialCounter{}
	if probeReachable(target, time.Second, c.control) {
		t.Fatal("probeReachable succeeded even though the control rejected the dial")
	}
	if n := c.count(); n == 0 {
		t.Fatal("probeReachable never invoked the dial control")
	}
}

// TestRunSecurityScanUsesDialControl verifies that both the scanner phases and
// the explicit reachability dial inside runSecurityScan pass through the
// control.
func TestRunSecurityScanUsesDialControl(t *testing.T) {
	target := localTarget(t)
	c := &dialCounter{}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, _ = runSecurityScan(ctx, target, c.control)

	if n := c.count(); n == 0 {
		t.Fatal("runSecurityScan never invoked the dial control")
	}
}

// TestRunLoadTestUsesDialControl verifies that the load stage's reachability
// probe is gated as well, so an unauthorized target cannot be load-tested.
func TestRunLoadTestUsesDialControl(t *testing.T) {
	target := localTarget(t)
	c := &dialCounter{}

	out := runLoadTest(context.Background(), target, time.Second, c.control)
	if n := c.count(); n == 0 {
		t.Fatalf("runLoadTest never invoked the dial control on its probe, notes: %v", out.Notes)
	}
}

// TestManagerStartWithControlThreadsControl verifies the public API contract
// the dashboard relies on: a control passed to StartWithControl reaches the
// audit run's dialers.
func TestManagerStartWithControlThreadsControl(t *testing.T) {
	target := localTarget(t)
	c := &dialCounter{}

	m := NewManager()
	id, err := m.StartWithControl(context.Background(), target, 5*time.Second, "", ModePassive, c.control)
	if err != nil {
		t.Fatalf("StartWithControl: %v", err)
	}

	deadline := time.Now().Add(20 * time.Second)
	for {
		st, ok := m.Get(id)
		if !ok {
			t.Fatalf("job %s disappeared", id)
		}
		if st.State == "completed" || st.State == "failed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("job did not finish, state=%q", st.State)
		}
		time.Sleep(10 * time.Millisecond)
	}

	if n := c.count(); n == 0 {
		t.Fatal("StartWithControl run never invoked the dial control")
	}
}
