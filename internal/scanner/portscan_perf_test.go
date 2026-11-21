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
