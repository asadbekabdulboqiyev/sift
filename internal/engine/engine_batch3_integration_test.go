//go:build integration

package engine

import (
	"context"
	"testing"
	"time"
)

func TestTokenBucketBurstCapsAtInitial(t *testing.T) {
	// Burst equals the initial rate. After full drain, idling longer than
	// burst/rate seconds must not let more than `burst` tokens accumulate.
	b := newTokenBucket(20) // burst 20, so 1.3s of idle would yield 26 uncapped
	for i := 0; i < 20; i++ {
		_ = b.wait(context.Background())
	}
	time.Sleep(1300 * time.Millisecond)
	for i := 0; i < 20; i++ {
		if err := b.wait(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	// 21st token must NOT be available: burst ceiling caps accumulation at 20
	// (uncapped idling would have banked 26). At 20/s the 21st needs ~50ms.
	tctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := b.wait(tctx); err == nil {
		t.Fatal("burst ceiling ignored: more than 20 tokens accumulated")
	}
}

func TestTokenBucketSetRateIncreaseCeiling(t *testing.T) {
	b := newTokenBucket(1)
	_ = b.wait(context.Background()) // drain the single token
	b.setRate(5)                     // raise ceiling to 5
	time.Sleep(1200 * time.Millisecond)
	// Refill would be 6s*5=30 uncapped; ceiling caps at 5 -> 5 instant, 6th blocks.
	for i := 0; i < 5; i++ {
		if err := b.wait(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	tctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if err := b.wait(tctx); err == nil {
		t.Fatal("raised ceiling exceeded: more than 5 tokens accumulated")
	}
}
