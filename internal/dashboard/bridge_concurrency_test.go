package dashboard

import (
	"sync"
	"testing"
	"time"
)

// TestRecordRequestIsRaceFree drives RecordRequest from several goroutines.
// The counters were incremented under b.mu but read outside it when computing
// RPS and the error rate, so this failed under -race. It also asserts the
// counters themselves stay exact.
func TestRecordRequestIsRaceFree(t *testing.T) {
	b := NewEngineBridge(NewServer())
	b.StartRun(&RunConfig{})

	const goroutines, perGoroutine = 4, 250
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				b.RecordRequest(200, time.Millisecond, i%2 == 0 && j%2 == 0)
			}
		}(i)
	}
	wg.Wait()

	b.mu.Lock()
	gotReqs, gotErrs := b.totalReqs, b.totalErrors
	b.mu.Unlock()
	if want := uint64(goroutines * perGoroutine); gotReqs != want {
		t.Fatalf("totalReqs = %d, want %d", gotReqs, want)
	}
	if gotErrs == 0 || gotErrs > gotReqs {
		t.Fatalf("totalErrors = %d, want 0 < errors <= %d", gotErrs, gotReqs)
	}
}
