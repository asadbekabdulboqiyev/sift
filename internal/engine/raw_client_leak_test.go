package engine

import (
	"context"
	"net"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/config"
)

// fdDir returns the per-process directory that lists open file descriptors.
// Linux exposes /proc/self/fd; macOS has no procfs and exposes /dev/fd instead.
// Windows has neither and must skip this test (see TestUDPRawClientClosesSocket).
func fdDir() string {
	if runtime.GOOS == "linux" {
		return "/proc/self/fd"
	}
	return "/dev/fd"
}

// countOpenFDs returns the number of open file descriptors for this process.
//
// It deliberately uses Readdirnames instead of os.ReadDir: os.ReadDir builds
// DirEntry values and, when the filesystem reports DT_UNKNOWN (as macOS
// fdescfs does for /dev/fd), calls fstatat on every entry. Under -race other
// goroutines open and close fds concurrently, so an fd can vanish between
// ReadDirent and that fstatat. Go tolerates ENOENT there but not EBADF, which
// made the whole read fail with "fstatat /dev/fd: bad file descriptor".
// Readdirnames only reads raw directory names and never stats the entries.
//
// Each call opens one directory fd for the duration of the read and closes it
// before returning, so both samples include the same +1 and the delta is
// meaningful. Only numeric names are counted (the fd numbers themselves).
func countOpenFDs(t *testing.T) int {
	t.Helper()
	dir := fdDir()
	f, err := os.Open(dir)
	if err != nil {
		t.Fatalf("open %s: %v", dir, err)
	}
	defer func() { _ = f.Close() }()
	names, err := f.Readdirnames(-1)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	count := 0
	for _, name := range names {
		if _, err := strconv.Atoi(name); err == nil {
			count++
		}
	}
	return count
}

// TestUDPRawClientClosesSocket pins that one raw UDP exchange does not leak a
// file descriptor. DialContext creates a connected UDP socket on every call;
// without an explicit Close the run exhausts its fd budget after a few
// thousand iterations (one leaked socket per request attempt).
func TestUDPRawClientClosesSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Windows has no /proc/self/fd or /dev/fd directory to enumerate.
		// The leak assertion stays fully enabled on Linux and macOS.
		t.Skip("no portable open-fd directory on Windows")
	}

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
