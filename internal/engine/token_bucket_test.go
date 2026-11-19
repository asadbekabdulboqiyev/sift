package engine

import (
	"context"
	"testing"
	"time"
)

func TestTokenBucketSetRate(t *testing.T) {
	b := newTokenBucket(0)
	if b.rate != 0 {
		t.Errorf("initial rate = %f, want 0", b.rate)
	}

	// Should block when rate is 0.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	err := b.wait(ctx)
	cancel()
	if err == nil {
		t.Error("expected timeout when rate is 0")
	}

	// Ramp up to 200 rps.
	b.setRate(200)
	if b.rate != 200 || b.burst != 200 {
		t.Errorf("after setRate: rate=%f burst=%f, want 200/200", b.rate, b.burst)
	}

	// Should now grant tokens.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel2()
	if err := b.wait(ctx2); err != nil {
		t.Errorf("expected grant after setRate(200), got %v", err)
	}
}
