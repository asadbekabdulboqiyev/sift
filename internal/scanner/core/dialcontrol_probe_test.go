package core

// dialcontrol_probe_test.go pins the dial-time control on the low-level probe.
// SendProbeWithControl must run the hook with the resolved peer address, must
// abort the request when the hook refuses, and SendProbe must keep working as
// the nil-control compatibility wrapper.

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
)

// errProbeRefused is the sentinel returned by a refusing dial hook.
var errProbeRefused = errors.New("probe dial hook refused the connection")

// TestSendProbeWithControlInvokesControl proves the hook runs at least once,
// with the resolved host:port peer, before a successful probe completes.
func TestSendProbeWithControlInvokesControl(t *testing.T) {
	// Arrange
	var calls atomic.Int64
	var peer atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wantPeer := strings.TrimPrefix(srv.URL, "http://")
	control := func(_ string, address string, _ syscall.RawConn) error {
		calls.Add(1)
		peer.Store(address)
		return nil
	}

	// Act
	resp, err := SendProbeWithControl(srv.URL, http.MethodGet, "/", nil, control)

	// Assert
	if err != nil {
		t.Fatalf("SendProbeWithControl: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if n := calls.Load(); n < 1 {
		t.Errorf("control calls = %d, want at least 1", n)
	}
	if got, ok := peer.Load().(string); !ok || got != wantPeer {
		t.Errorf("control peer = %v, want %q", got, wantPeer)
	}
}

// TestSendProbeWithControlRefusesDial proves a hook error aborts the request
// before the server ever accepts a connection.
func TestSendProbeWithControlRefusesDial(t *testing.T) {
	// Arrange
	var calls atomic.Int64
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	control := func(_ string, _ string, _ syscall.RawConn) error {
		calls.Add(1)
		return errProbeRefused
	}

	// Act
	resp, err := SendProbeWithControl(srv.URL, http.MethodGet, "/", nil, control)

	// Assert
	if err == nil {
		if resp != nil {
			_ = resp.Body.Close()
		}
		t.Fatal("SendProbeWithControl with a refusing hook returned no error")
	}
	if !errors.Is(err, errProbeRefused) && !strings.Contains(err.Error(), errProbeRefused.Error()) {
		t.Fatalf("error = %v, want the dial-hook refusal", err)
	}
	if n := calls.Load(); n < 1 {
		t.Errorf("control calls = %d, want at least 1", n)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("server hits = %d, want 0: a refused dial must not reach the server", n)
	}
}

// TestSendProbeStillWorksWithoutControl keeps the compatibility promise: the
// old SendProbe entry point still reaches the server with no hook installed.
func TestSendProbeStillWorksWithoutControl(t *testing.T) {
	// Arrange
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Probe", "ok")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Act
	resp, err := SendProbe(srv.URL, http.MethodGet, "/", nil)

	// Assert
	if err != nil {
		t.Fatalf("SendProbe: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if got := resp.Header.Get("X-Probe"); got != "ok" {
		t.Errorf("X-Probe = %q, want ok", got)
	}
}
