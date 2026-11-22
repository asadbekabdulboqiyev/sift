package browser

// guardproxy_options_test.go pins the shared guard-proxy entry point used by
// browserload. Without it a second Chromium stack could silently reintroduce
// the direct-network bypass this package just closed.

import (
	"reflect"
	"sync/atomic"
	"syscall"
	"testing"
)

func TestGuardProxyFlagValues(t *testing.T) {
	const addr = "http://127.0.0.1:45678"
	want := []guardProxyFlag{
		{"proxy-server", addr},
		{"proxy-bypass-list", "<-loopback>"},
		{"disable-quic", true},
		{"force-webrtc-ip-handling-policy", "disable_non_proxied_udp"},
	}
	if got := guardProxyFlagValues(addr); !reflect.DeepEqual(got, want) {
		t.Fatalf("guard flags = %v, want %v", got, want)
	}
}

func TestGuardProxyOptionsWithoutControlStartsNothing(t *testing.T) {
	flags, closeFn, err := GuardProxyOptions(nil)
	if err != nil {
		t.Fatalf("GuardProxyOptions(nil): %v", err)
	}
	if len(flags) != 0 {
		t.Fatalf("nil control returned %d flags, want 0", len(flags))
	}
	if closeFn == nil {
		t.Fatal("nil control returned a nil closer; callers cannot defer it safely")
	}
	if err := closeFn(); err != nil {
		t.Fatalf("nil-control closer: %v", err)
	}
}

func TestGuardProxyOptionsWithControlReturnsFlagsAndCloser(t *testing.T) {
	var calls atomic.Int32
	control := func(_, _ string, _ syscall.RawConn) error {
		calls.Add(1)
		return nil
	}
	flags, closeFn, err := GuardProxyOptions(control)
	if err != nil {
		t.Fatalf("GuardProxyOptions(control): %v", err)
	}
	if len(flags) != 4 {
		t.Fatalf("flags = %d, want 4 (proxy-server, bypass-list, disable-quic, WebRTC)", len(flags))
	}
	if closeFn == nil {
		t.Fatal("controlled runner has no closer; guard proxy listener would leak")
	}
	// The closer must be idempotent, matching Browser.Close().
	if err := closeFn(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := closeFn(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if calls.Load() != 0 {
		t.Fatal("starting the proxy must not dial any destination")
	}
}
