//go:build !linux

package hostxray

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"testing"
)

// On non-Linux hosts the platform collector reports Go runtime metrics only.
// These tests use a background context and never touch the network or DNS.
func TestRuntimeCollectorCollectReturnsRuntimeOnlySample(t *testing.T) {
	collector, err := newPlatformCollector(Options{})
	if err != nil {
		t.Fatalf("newPlatformCollector: %v", err)
	}
	rc, ok := collector.(*runtimeCollector)
	if !ok {
		t.Fatalf("collector type = %T, want *runtimeCollector", collector)
	}

	sample, err := rc.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if sample.Timestamp.IsZero() {
		t.Error("sample has no timestamp")
	}
	if sample.Source != SourceRuntime {
		t.Errorf("source = %q, want %q", sample.Source, SourceRuntime)
	}
	wantPlatform := runtime.GOOS + "/" + runtime.GOARCH
	if sample.Platform != wantPlatform {
		t.Errorf("platform = %q, want %q", sample.Platform, wantPlatform)
	}
	if !sample.Runtime.Available || sample.Runtime.GOMAXPROCS <= 0 || sample.Runtime.Goroutines <= 0 {
		t.Errorf("runtime stats are not usable: %+v", sample.Runtime)
	}
	if len(sample.Notes) != 2 {
		t.Fatalf("notes = %v, want 2 runtime-only caveats", sample.Notes)
	}
	joined := strings.Join(sample.Notes, " ")
	if !strings.Contains(joined, "kernel evidence is unavailable") || !strings.Contains(joined, "not the host kernel") {
		t.Errorf("notes do not state the runtime-only limitation: %v", sample.Notes)
	}
}

func TestRuntimeCollectorCollectRespectsCanceledContext(t *testing.T) {
	collector, err := newPlatformCollector(Options{})
	if err != nil {
		t.Fatalf("newPlatformCollector: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	sample, err := collector.Collect(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Collect error = %v, want context.Canceled", err)
	}
	if !sample.Timestamp.IsZero() {
		t.Errorf("canceled Collect returned sample %+v, want zero value", sample)
	}
}
