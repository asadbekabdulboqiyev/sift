package scanner

// verify_control_test.go proves the false-positive verifier obeys the gate's
// dial control. Finding URLs come from crawled pages, so an uncontrolled
// verifier would be a second SSRF path independent of the vulnerability scan.

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestVerifierWithControlDialsThroughHook(t *testing.T) {
	var hits, controlCalls int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer up.Close()

	v := NewVerifierWithControl(2*time.Second, func(_, _ string, _ syscall.RawConn) error {
		atomic.AddInt32(&controlCalls, 1)
		return nil
	})
	page, err := v.fetch(up.URL)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if page.status != http.StatusOK {
		t.Fatalf("status = %d, want 200", page.status)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("upstream hits = %d, want 1", got)
	}
	if got := atomic.LoadInt32(&controlCalls); got == 0 {
		t.Fatal("verifier never applied the dial control")
	}
}

func TestVerifierWithNilControlKeepsDirectBehavior(t *testing.T) {
	v := NewVerifierWithControl(2*time.Second, nil)
	if v.Client.Transport != nil {
		t.Fatal("nil control must keep the default transport")
	}
	if plain := NewVerifier(2 * time.Second); plain.Client.Transport != nil {
		t.Fatal("NewVerifier must keep the default transport")
	}
}
