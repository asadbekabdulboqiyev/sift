package coordinator

// dial_test.go — the worker dialer retries only genuine source-port
// exhaustion. Classifying errors correctly matters both ways: retrying a real
// failure (refused/DNS/timeout) hides bugs and wastes the Ping deadline, while
// failing fast on EADDRNOTAVAIL reintroduces the loopback flake this fixes.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func dialError(errno syscall.Errno) error {
	return &net.OpError{
		Op:  "dial",
		Net: "tcp",
		Err: os.NewSyscallError("connect", errno),
	}
}

func TestIsEphemeralPortPressure(t *testing.T) {
	retry := []struct {
		name string
		err  error
	}{
		{"EADDRNOTAVAIL", dialError(syscall.EADDRNOTAVAIL)},
		{"EADDRINUSE", dialError(syscall.EADDRINUSE)},
		{"wrapped EADDRNOTAVAIL", fmt.Errorf("dial worker: %w", dialError(syscall.EADDRNOTAVAIL))},
	}
	for _, tc := range retry {
		if !isEphemeralPortPressure(tc.err) {
			t.Errorf("%s: want retry, got no retry (%v)", tc.name, tc.err)
		}
	}

	failFast := []struct {
		name string
		err  error
	}{
		{"connection refused", dialError(syscall.ECONNREFUSED)},
		{"deadline", context.DeadlineExceeded},
		{"plain", errors.New("boom")},
	}
	for _, tc := range failFast {
		if isEphemeralPortPressure(tc.err) {
			t.Errorf("%s: want fail-fast, got retry (%v)", tc.name, tc.err)
		}
	}
}

// stubDial swaps the dialer and the retry tunables for the duration of a test.
func stubDial(t *testing.T, fn func(context.Context, string) (net.Conn, error)) *int32 {
	t.Helper()
	var calls int32
	prevDial, prevBudget, prevDelay, prevAttempt := dialTCP, dialRetryBudget, dialRetryDelay, dialAttemptTimeout
	dialTCP = func(ctx context.Context, addr string) (net.Conn, error) {
		atomic.AddInt32(&calls, 1)
		return fn(ctx, addr)
	}
	dialRetryBudget = 2 * time.Second
	dialRetryDelay = time.Millisecond
	dialAttemptTimeout = 50 * time.Millisecond
	t.Cleanup(func() {
		dialTCP, dialRetryBudget, dialRetryDelay, dialAttemptTimeout = prevDial, prevBudget, prevDelay, prevAttempt
	})
	return &calls
}

// TestDialWorkerRetriesUntilSuccess covers the intended path: the host is out
// of source ports for a moment, then recovers, and the worker connects.
func TestDialWorkerRetriesUntilSuccess(t *testing.T) {
	var attempts int32
	calls := stubDial(t, func(_ context.Context, _ string) (net.Conn, error) {
		if atomic.AddInt32(&attempts, 1) < 3 {
			return nil, dialError(syscall.EADDRNOTAVAIL)
		}
		c1, c2 := net.Pipe()
		_ = c2.Close()
		return c1, nil
	})

	conn, err := dialWorker(context.Background(), "127.0.0.1:1")
	if err != nil {
		t.Fatalf("dialWorker: %v", err)
	}
	_ = conn.Close()
	if got := atomic.LoadInt32(calls); got != 3 {
		t.Fatalf("expected 3 attempts, got %d", got)
	}
}

// TestDialWorkerFailsFastOnRealError pins the other half of the contract: a
// refused/unknown error must not be retried, or a real outage is hidden behind
// the retry budget.
func TestDialWorkerFailsFastOnRealError(t *testing.T) {
	calls := stubDial(t, func(_ context.Context, _ string) (net.Conn, error) {
		return nil, dialError(syscall.ECONNREFUSED)
	})

	if _, err := dialWorker(context.Background(), "127.0.0.1:1"); err == nil {
		t.Fatal("expected error")
	}
	if got := atomic.LoadInt32(calls); got != 1 {
		t.Fatalf("expected 1 attempt, got %d", got)
	}
}

// TestDialWorkerStopsAtRetryBudget proves the loop is bounded by wall-clock
// time even when the host never recovers and the caller's context has no
// deadline (gRPC's connect context is much longer than the Ping deadline).
func TestDialWorkerStopsAtRetryBudget(t *testing.T) {
	calls := stubDial(t, func(_ context.Context, _ string) (net.Conn, error) {
		return nil, dialError(syscall.EADDRNOTAVAIL)
	})
	dialRetryBudget = 150 * time.Millisecond

	start := time.Now()
	_, err := dialWorker(context.Background(), "127.0.0.1:1")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected budget error")
	}
	if !isEphemeralPortPressure(err) {
		t.Fatalf("expected last dial error to surface, got %v", err)
	}
	if elapsed > time.Second {
		t.Fatalf("retry loop exceeded its budget: %s", elapsed)
	}
	if atomic.LoadInt32(calls) < 2 {
		t.Fatalf("expected retries before giving up, got %d attempt(s)", atomic.LoadInt32(calls))
	}
}

// TestDialWorkerStopsOnContextCancel covers the caller walking away mid-retry.
func TestDialWorkerStopsOnContextCancel(t *testing.T) {
	stubDial(t, func(ctx context.Context, _ string) (net.Conn, error) {
		return nil, dialError(syscall.EADDRNOTAVAIL)
	})
	dialRetryDelay = 10 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	defer cancel()

	start := time.Now()
	_, err := dialWorker(ctx, "127.0.0.1:1")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("cancel was not honored promptly: %s", elapsed)
	}
}
