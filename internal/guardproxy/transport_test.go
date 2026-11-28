package guardproxy

// transport_test.go pins the adapter contract: nil-control transports stay
// direct, controlled transports pin a loopback guard proxy, and Close is
// observable and reusable.

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"testing"
)

func TestWrapTransportNilControlKeepsDirectBehavior(t *testing.T) {
	selectorCalls := 0
	selector := func(*http.Request) (*url.URL, error) {
		selectorCalls++
		return nil, nil
	}
	base := &http.Transport{Proxy: selector, MaxIdleConns: 7}
	tr, closer, err := WrapTransport(base, nil)
	if err != nil {
		t.Fatalf("WrapTransport(nil control): %v", err)
	}
	if closer == nil {
		t.Fatal("nil-control closer is nil; callers cannot defer it safely")
	}
	if tr.MaxIdleConns != 7 {
		t.Fatalf("base settings not preserved: MaxIdleConns=%d", tr.MaxIdleConns)
	}
	req, err := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Proxy(req); err != nil {
		t.Fatalf("original proxy selector failed: %v", err)
	}
	if selectorCalls != 1 {
		t.Fatalf("original selector called %d times, want 1", selectorCalls)
	}
	if err := closer.Close(); err != nil {
		t.Fatalf("noop closer: %v", err)
	}
}

func TestWrapTransportNonNilControlUsesLoopbackGuard(t *testing.T) {
	blocked := errors.New("blocked by test gate")
	control := func(_, address string, _ syscall.RawConn) error {
		if strings.Contains(address, "blocked.example") {
			return blocked
		}
		return nil
	}
	tr, closer, err := WrapTransport(&http.Transport{}, control)
	if err != nil {
		t.Fatalf("WrapTransport(control): %v", err)
	}
	defer closer.Close()

	req, err := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	u, err := tr.Proxy(req)
	if err != nil {
		t.Fatalf("guard proxy selector: %v", err)
	}
	if u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" {
		t.Fatalf("proxy URL = %q, want an ephemeral loopback guard", u.String())
	}
	lazy, ok := closer.(*Lazy)
	if !ok {
		t.Fatalf("closer type = %T, want *Lazy", closer)
	}
	if !lazy.IsGuardAddr(u.Host) {
		t.Fatalf("IsGuardAddr(%q) = false", u.Host)
	}
	guardedControl := lazy.Control(control)
	if err := guardedControl("tcp", u.Host, nil); err != nil {
		t.Fatalf("guard socket must be exempt from the destination check: %v", err)
	}
	if err := guardedControl("tcp", "blocked.example:443", nil); !errors.Is(err, blocked) {
		t.Fatalf("non-guard socket error = %v, want the caller's control error", err)
	}
}

func TestLazyReopensAfterClose(t *testing.T) {
	lazy := NewLazy(Options{Control: allowAll})
	u1, err := lazy.URL()
	if err != nil {
		t.Fatal(err)
	}
	if err := lazy.Close(); err != nil {
		t.Fatal(err)
	}
	u2, err := lazy.URL()
	if err != nil {
		t.Fatalf("URL after close: %v", err)
	}
	if u1.String() == u2.String() {
		t.Fatalf("Lazy reused the closed listener address %q", u1.String())
	}
	if err := lazy.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLazyClosePropagatesListenerError(t *testing.T) {
	want := errors.New("listener close failed")
	lazy := NewLazy(Options{
		Control: allowAll,
		listen: func(network, address string) (net.Listener, error) {
			ln, err := net.Listen(network, address)
			if err != nil {
				return nil, err
			}
			return &failingListener{Listener: ln, err: want}, nil
		},
	})
	if _, err := lazy.URL(); err != nil {
		t.Fatalf("URL: %v", err)
	}
	if err := lazy.Close(); !errors.Is(err, want) {
		t.Fatalf("close error = %v, want %v", err, want)
	}
}
