package tenant

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// TestWithContextPreservesParentContextMetadata verifies that adding a tenant
// ID does not drop the deadline, cancellation or unrelated values already
// carried by the parent context.
func TestWithContextPreservesParentContextMetadata(t *testing.T) {
	type foreignKey struct{}

	deadline := time.Now().Add(time.Hour)
	parent, cancel := context.WithDeadline(context.WithValue(context.Background(), foreignKey{}, "keep-me"), deadline)
	defer cancel()

	// Act
	derived := WithContext(parent, "t-acme")

	// Assert
	if got := FromContext(derived); got != "t-acme" {
		t.Fatalf("FromContext(derived) = %q, want t-acme", got)
	}
	if got := derived.Value(foreignKey{}); got != "keep-me" {
		t.Fatalf("unrelated parent value lost: %v", got)
	}
	gotDeadline, ok := derived.Deadline()
	if !ok || !gotDeadline.Equal(deadline) {
		t.Fatalf("derived deadline = %v (ok=%v), want %v", gotDeadline, ok, deadline)
	}
}

// TestFromContextIsUnaffectedByCancellation pins the common middleware case
// where a tenant ID is read after the request context has been cancelled.
func TestFromContextIsUnaffectedByCancellation(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	ctx := WithContext(parent, "t-cancelled")
	cancel()

	if got := FromContext(ctx); got != "t-cancelled" {
		t.Fatalf("FromContext(cancelled) = %q, want t-cancelled", got)
	}
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatalf("context.Err() = %v, want context.Canceled", ctx.Err())
	}
}

// TestWithContextConcurrentIsolation checks that different goroutines deriving
// from one parent never observe each other's tenant ID.
func TestWithContextConcurrentIsolation(t *testing.T) {
	const workers = 16
	parent := context.Background()

	var wg sync.WaitGroup
	errCh := make(chan string, workers)
	for i := 0; i < workers; i++ {
		id := "t-" + string(rune('a'+i))
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got := FromContext(WithContext(parent, id)); got != id {
				errCh <- id + ": got " + got
			}
		}()
	}
	wg.Wait()
	close(errCh)

	for msg := range errCh {
		t.Error(msg)
	}
	if got := FromContext(parent); got != "" {
		t.Errorf("parent context mutated by workers: %q", got)
	}
}
