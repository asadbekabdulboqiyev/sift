package dashboard

// ws_command_budget_test.go pins the per-connection command budget in the
// WebSocket command loop. The upgrade's IP limiter only sees the GET, so a
// single authorized client could otherwise spam the gated start/stop path and
// keep the policy classifier plus audit fsync busy. These tests prove the
// budget caps that burst without ever tearing down the socket.

import (
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// budgetTestTarget is a public literal address: the default policy classifies
// it without DNS, so these tests exercise the budget rather than the gate.
const budgetTestTarget = "http://93.184.216.34/"

// newBudgetTestServer isolates the policy/audit env and returns a server whose
// command handler records every dispatched command under mu.
func newBudgetTestServer(t *testing.T) (*Server, func() []string) {
	t.Helper()
	isolateWSGateEnv(t)

	s := NewServer()
	var mu sync.Mutex
	var commands []string
	s.SetCommandHandler(func(cmd string, args map[string]interface{}) {
		mu.Lock()
		defer mu.Unlock()
		commands = append(commands, cmd)
	})
	snapshot := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), commands...)
	}
	return s, snapshot
}

func TestWSCommandBudgetBurstDenied(t *testing.T) {
	s, dispatched := newBudgetTestServer(t)

	srv := httptest.NewServer(s)
	defer srv.Close()
	conn := dialDashboardWS(t, srv)
	defer conn.Close()
	_ = readWSCommandFrame(t, conn) // init

	// Exhaust the budget with stops: they are metered but skip the audit
	// fsync, so the setup stays inside the 1s refill window even on slow CI.
	// Starts would each pay for an fsync and could let a token refill midway.
	for i := 0; i < wsRunCommandBurst; i++ {
		if err := conn.WriteJSON(map[string]any{"type": "stop"}); err != nil {
			t.Fatalf("write stop: %v", err)
		}
	}
	waitFor(t, "the in-budget stops to dispatch", func() bool {
		return len(dispatched()) == wsRunCommandBurst
	})

	// Just over the budget the start gets the same command_error frame shape
	// as an authorization denial, but with the budget reason, and dispatches
	// nothing.
	wsStartJSON(t, conn, budgetTestTarget)
	frame := readWSCommandFrame(t, conn)
	assertCommandError(t, frame, "start", wsRunCommandLimited)
	if got, want := frame["error"], wsRunCommandLimited; got != want {
		t.Errorf("budget error = %v, want %q", got, want)
	}

	if got := len(dispatched()); got != wsRunCommandBurst {
		t.Fatalf("dispatched = %d, want %d (over-budget start must not dispatch)", got, wsRunCommandBurst)
	}
}

func TestWSCommandBudgetReadLoopSurvivesExhaustion(t *testing.T) {
	s, dispatched := newBudgetTestServer(t)

	srv := httptest.NewServer(s)
	defer srv.Close()
	conn := dialDashboardWS(t, srv)
	defer conn.Close()
	_ = readWSCommandFrame(t, conn) // init

	// Exhaust the budget with stops: they are metered but skip the audit
	// fsync, so this setup is deterministic regardless of disk speed.
	for i := 0; i < wsRunCommandBurst; i++ {
		if err := conn.WriteJSON(map[string]any{"type": "stop"}); err != nil {
			t.Fatalf("write stop: %v", err)
		}
	}
	waitFor(t, "the in-budget stops to dispatch", func() bool {
		return len(dispatched()) == wsRunCommandBurst
	})
	if err := conn.WriteJSON(map[string]any{"type": "stop"}); err != nil {
		t.Fatalf("write overflow stop: %v", err)
	}
	assertCommandError(t, readWSCommandFrame(t, conn), "stop", wsRunCommandLimited)

	// The read loop kept running: a non-run command on the same socket still
	// dispatches even though the run budget is exhausted.
	if err := conn.WriteJSON(map[string]any{"type": "ping"}); err != nil {
		t.Fatalf("write ping: %v", err)
	}
	waitFor(t, "a non-run command after exhaustion", func() bool {
		got := dispatched()
		return len(got) == wsRunCommandBurst+1 && got[wsRunCommandBurst] == "ping"
	})

	// After a refill the very same socket can drive a run command again:
	// exhaustion never kills the connection. Retry the write inside waitFor
	// rather than sleeping a fixed interval, so the test waits only as long
	// as the refill actually needs. Premature stops are budget-denied and
	// dispatch nothing; the first one accepted after the token lands does.
	waitFor(t, "a run command after refill", func() bool {
		if err := conn.WriteJSON(map[string]any{"type": "stop"}); err != nil {
			return false
		}
		got := dispatched()
		return len(got) >= wsRunCommandBurst+2 && got[wsRunCommandBurst+1] == "stop"
	})

	// A fresh socket starts with a full budget, so one client's burst cannot
	// throttle another dashboard tab. Measure from the post-refill count so a
	// slow runner that lets a second token land cannot skew the index.
	afterRefill := len(dispatched())
	other := dialDashboardWS(t, srv)
	defer other.Close()
	_ = readWSCommandFrame(t, other) // init
	wsStartJSON(t, other, budgetTestTarget)
	waitFor(t, "a run command on a fresh socket", func() bool {
		got := dispatched()
		return len(got) == afterRefill+1 && got[afterRefill] == "start"
	})
}

func TestWSCommandBudgetNonRunCommandsNotCharged(t *testing.T) {
	s, dispatched := newBudgetTestServer(t)

	srv := httptest.NewServer(s)
	defer srv.Close()
	conn := dialDashboardWS(t, srv)
	defer conn.Close()
	_ = readWSCommandFrame(t, conn) // init

	// Well past the run budget, non-run commands still all dispatch and no
	// command_error frame is produced for them.
	const n = 3 * wsRunCommandBurst
	for i := 0; i < n; i++ {
		if err := conn.WriteJSON(map[string]any{"type": "unknown"}); err != nil {
			t.Fatalf("write unknown: %v", err)
		}
	}
	// Ordered processing makes a sentinel a dispatch barrier: once it lands,
	// every earlier non-run command has been handled and any erroneous frame
	// would already be queued for the read check below.
	if err := conn.WriteJSON(map[string]any{"type": "sentinel"}); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}
	waitFor(t, "the non-run flood and sentinel to dispatch", func() bool {
		got := dispatched()
		return len(got) == n+1 && got[n] == "sentinel"
	})

	if err := conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if _, _, err := conn.ReadMessage(); err == nil {
		t.Fatal("non-run commands produced an unexpected frame (they must not be charged)")
	}

	// A run command still works afterwards: the non-run flood did not spend
	// any of the budget.
	wsStartJSON(t, conn, budgetTestTarget)
	waitFor(t, "a run command after the non-run flood", func() bool {
		got := dispatched()
		return len(got) == n+2 && got[n+1] == "start"
	})
}
