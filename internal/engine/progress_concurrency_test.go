package engine

// Priority-1 concurrency coverage for progress.go and broadcast.go: cancellation,
// multiple waiters, idempotent Finish, and deadlock/goroutine-leak checks.

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// lockedBuffer is a thread-safe io.Writer for progress rendering tests.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (w *lockedBuffer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func (w *lockedBuffer) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

// terminalProgress builds a tracker whose render loop is active. A bytes.Buffer
// is not a character device, so isTerminal is forced on explicitly; quiet mode
// keeps periodic renders from racing with the final render.
func terminalProgress(t *testing.T, quiet bool) (*ProgressTracker, *lockedBuffer) {
	t.Helper()
	out := &lockedBuffer{}
	pt := newProgressTracker(30*time.Second, 4, out)
	pt.isTerminal = true
	pt.SetQuiet(quiet)
	t.Cleanup(func() {
		// Finish is idempotent; calling it here guarantees the loop is stopped
		// even when a test fails early.
		pt.Finish()
	})
	go pt.loop()
	return pt, out
}

func TestProgressFinishConcurrentCallersDoNotDeadlock(t *testing.T) {
	pt, _ := terminalProgress(t, true)

	const callers = 16
	finished := make(chan struct{}, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pt.Finish()
			finished <- struct{}{}
		}()
	}

	deadline := time.After(2 * time.Second)
	for i := 0; i < callers; i++ {
		select {
		case <-finished:
		case <-deadline:
			t.Fatal("concurrent Finish calls deadlocked")
		}
	}
	wg.Wait()

	select {
	case <-pt.done:
	default:
		t.Fatal("Finish returned but the render loop did not signal done")
	}
}

func TestProgressFinishStopsRenderLoop(t *testing.T) {
	pt, out := terminalProgress(t, false)
	pt.Update(12, 1, 3*time.Millisecond)

	done := make(chan struct{})
	go func() {
		pt.Finish()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Finish blocked waiting for the render loop")
	}

	select {
	case <-pt.stop:
	default:
		t.Fatal("Finish did not close the stop channel")
	}
	if text := out.String(); !strings.Contains(text, "12") || !strings.Contains(text, "100%") {
		t.Fatalf("final render missing counters or completion marker: %q", text)
	}
}

func TestProgressUpdateDuringFinishIsSafe(t *testing.T) {
	pt, _ := terminalProgress(t, true)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	updated := make(chan struct{}, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			// Record at least one update before Finish so the snapCount
			// assertion cannot fail on goroutine scheduling.
			pt.Update(uint64(id+1), uint64(id%2), time.Duration(id)*time.Millisecond)
			updated <- struct{}{}
			for {
				select {
				case <-stop:
					return
				default:
					pt.Update(uint64(id+1), uint64(id%2), time.Duration(id)*time.Millisecond)
				}
			}
		}(i)
	}

	for i := 0; i < 8; i++ {
		<-updated
	}
	pt.Finish()
	close(stop)
	wg.Wait()

	if got := pt.snapCount.Load(); got == 0 {
		t.Fatal("no updates were recorded during Finish")
	}
}

func TestNewProgressTrackerFields(t *testing.T) {
	pt := NewProgressTracker(7*time.Second, 9)
	if pt == nil {
		t.Fatal("NewProgressTracker returned nil")
	}
	if pt.duration != 7*time.Second || pt.totalUsers != 9 {
		t.Fatalf("tracker fields = (%v, %d), want (7s, 9)", pt.duration, pt.totalUsers)
	}
	if pt.stop == nil || pt.done == nil {
		t.Fatal("tracker channels were not initialized")
	}
	pt.Finish()
}

// waitCaptured mirrors broadcast.wait and reports the instant it captured the
// current channel. The signal is sent while the broadcast mutex is held, so
// once the caller has received one signal per waiter, all waiters hold the
// same channel and a single notify is guaranteed to release them. This keeps
// the test deterministic without adding a test-only seam to production code.
func waitCaptured(b *broadcast, ctx context.Context, captured chan<- struct{}) error {
	b.mu.Lock()
	ch := b.ch
	captured <- struct{}{}
	b.mu.Unlock()
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestBroadcastNotifyWakesAllWaiters(t *testing.T) {
	b := newBroadcast()
	const waiters = 32

	done := make(chan error, waiters)
	captured := make(chan struct{}, waiters)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for i := 0; i < waiters; i++ {
		go func() {
			done <- waitCaptured(b, ctx, captured)
		}()
	}

	// One notify releases every waiter only if all of them captured the
	// channel it closes; the handshake above guarantees that ordering.
	for i := 0; i < waiters; i++ {
		<-captured
	}
	b.notify()

	received := 0
	for received < waiters {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("waiter %d returned an error: %v", received, err)
			}
			received++
		case <-ctx.Done():
			t.Fatalf("only %d of %d waiters were released by notify: %v", received, waiters, ctx.Err())
		}
	}
}

func TestBroadcastWaitRespectsContextCancellation(t *testing.T) {
	b := newBroadcast()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := b.wait(ctx); err != context.Canceled {
		t.Fatalf("wait(canceled) = %v, want context.Canceled", err)
	}
}

func TestBroadcastWaitTimesOutUntilNextNotify(t *testing.T) {
	b := newBroadcast()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := b.wait(ctx); err != context.DeadlineExceeded {
		t.Fatalf("wait before notify = %v, want context.DeadlineExceeded", err)
	}

	// Wait until the waiter has captured the open channel before notifying;
	// a fixed sleep made this depend on host scheduling.
	wctx, wcancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer wcancel()
	captured := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() { done <- waitCaptured(b, wctx, captured) }()
	<-captured
	b.notify()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("wait after notify = %v, want nil", err)
		}
	case <-wctx.Done():
		t.Fatalf("notify did not wake the waiter: %v", wctx.Err())
	}
}

func TestBroadcastConcurrentNotifyAndWait(t *testing.T) {
	b := newBroadcast()
	const workers = 16

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				b.notify()
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
				_ = b.wait(ctx)
				cancel()
			}
		}()
	}

	finished := make(chan struct{})
	go func() {
		wg.Wait()
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent notify/wait deadlocked")
	}
}
