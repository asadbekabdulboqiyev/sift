package scanner

// portscan_perf_test.go — measures the cost of dispatching a very large port
// list. With a cancelled context the old per-port goroutines were still all
// created before any of them reached the semaphore.

import (
	"context"
	"testing"
)

func BenchmarkScanPortsCancelledManyPorts(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ports := make([]int, 4096)
	for i := range ports {
		ports[i] = 10000 + i
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ScanPorts(ctx, "127.0.0.1", ports, nil)
	}
}

func TestScanPortsCancelledStopsDispatch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ports := make([]int, 4096)
	for i := range ports {
		ports[i] = 10000 + i
	}

	const target = "127.0.0.1:0"
	res := ScanPorts(ctx, target, ports, nil)

	if res.Target != target || res.Opened != 0 || len(res.Ports) != 0 {
		t.Errorf("cancelled result = target %q, opened %d, ports %d; want clean empty result", res.Target, res.Opened, len(res.Ports))
	}
	// The semaphore caps dispatch at 64 slots. The old per-port goroutine
	// dispatch would have attempted every one of the 4096 ports.
	if res.Closed > 64 {
		t.Errorf("closed ports = %d, want at most 64 for a cancelled run", res.Closed)
	}
}

func TestScanPortsFindsAllOpenPortsAfterSemaphoreChange(t *testing.T) {
	ports := make([]int, 0, 4)
	want := make(map[int]bool, 4)
	for i := 0; i < 4; i++ {
		_, port := startBannerListener(t, "SSH-2.0-Perf\r\n")
		ports = append(ports, port)
		want[port] = true
	}

	res := ScanPorts(context.Background(), "127.0.0.1", ports, nil)
	if res.Opened != len(want) {
		t.Fatalf("Opened = %d, want %d (Ports: %+v)", res.Opened, len(want), res.Ports)
	}
	for _, entry := range res.Ports {
		if !want[entry.Port] {
			t.Errorf("unexpected open port %d", entry.Port)
			continue
		}
		delete(want, entry.Port)
	}
	if len(want) != 0 {
		t.Errorf("missing open ports: %v", want)
	}
}
