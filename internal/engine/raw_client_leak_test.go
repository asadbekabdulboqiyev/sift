package engine

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/config"
)

// countOpenFDs returns the number of entries in /dev/fd (available on both
// Linux and macOS). Each call opens and closes one directory fd, so the count
// is consistent across calls and the delta between two calls is meaningful.
func countOpenFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/dev/fd")
	if err != nil {
		t.Fatalf("read /dev/fd: %v", err)
	}
	return len(entries)
}

// TestUDPRawClientClosesSocket pins that one raw UDP exchange does not leak a
// file descriptor. DialContext creates a connected UDP socket on every call;
// without an explicit Close the run exhausts its fd budget after a few
// thousand iterations (one leaked socket per request attempt).
func TestUDPRawClientClosesSocket(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer func() { _ = pc.Close() }()

	e := &Engine{}
	ctx := context.Background()
	step := config.Step{} // fire-and-forget, no body

	// Warm up so one-off runtime fds do not skew the measurement.
	e.rawClient(ctx, "udp", pc.LocalAddr().String(), step, nil, time.Second)

	before := countOpenFDs(t)
	const n = 100
	for i := 0; i < n; i++ {
		res, _ := e.rawClient(ctx, "udp", pc.LocalAddr().String(), step, nil, time.Second)
		if res.errName != "" {
			t.Fatalf("iteration %d: udp error %q", i, res.errName)
		}
	}
	after := countOpenFDs(t)
	// Allow slack for runtime background fds; the bug leaks one fd per call,
	// so the observed delta should be ~n, not ~0.
	if after-before > n/2 {
		t.Fatalf("raw UDP exchange leaked file descriptors: before=%d after=%d over %d calls", before, after, n)
	}
}
