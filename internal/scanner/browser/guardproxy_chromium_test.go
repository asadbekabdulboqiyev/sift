package browser

// guardproxy_chromium_test.go proves the guard proxy is actually on Chromium's
// network path. Pure-Go tests cover the proxy in isolation; these tests confirm
// the --proxy-server / --proxy-bypass-list flags make a real browser obey it.
// They skip when no Chromium binary is installed (CI images without one).

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/authz"
)

// gatedBrowser opens a browser with the given control, extending the launch
// timeout the way the other real-browser tests do and skipping when this
// machine cannot start Chromium at all.
func gatedBrowser(t *testing.T, control dialControl) *Browser {
	t.Helper()
	if !chromeInstalled() {
		t.Skip("no Chrome/Chromium binary on this machine")
	}
	prev := probeTimeout
	probeTimeout = func() time.Duration { return 90 * time.Second }
	t.Cleanup(func() { probeTimeout = prev })

	b, err := New(WithDialControl(control))
	if err != nil {
		if strings.Contains(err.Error(), "invalid context") {
			t.Fatalf("New: %v — browser context wiring is broken", err)
		}
		t.Skipf("browser could not be started in this environment: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

func TestBrowserWithDialControlReachesApprovedLoopback(t *testing.T) {
	var hits atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html><body><h1>guard-ok</h1></body></html>")
	}))
	defer up.Close()

	b := gatedBrowser(t, authz.DialControl(authz.ClassLoopback))
	html, err := b.Page(up.URL, 60*time.Second)
	if err != nil {
		t.Fatalf("Page via approved proxy: %v", err)
	}
	if !strings.Contains(html, "guard-ok") {
		t.Fatalf("rendered HTML = %q, want guard-ok", html)
	}
	if got := hits.Load(); got == 0 {
		t.Fatal("upstream server was never reached")
	}
}

func TestBrowserWithDialControlRefusesUnapprovedLoopback(t *testing.T) {
	var hits atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html><body><h1>should-not-reach</h1></body></html>")
	}))
	defer up.Close()

	// ClassPublic refuses a loopback destination. If Chromium were bypassing
	// the proxy (its default for localhost), the page would still render and
	// hits would be > 0 — exactly the gap this change closes.
	b := gatedBrowser(t, authz.DialControl(authz.ClassPublic))
	html, err := b.Page(up.URL, 30*time.Second)
	if err == nil && strings.Contains(html, "should-not-reach") {
		t.Fatalf("unapproved loopback rendered despite ClassPublic gate: %q", html)
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("unapproved loopback reached upstream %d times", got)
	}
}
