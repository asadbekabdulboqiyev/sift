package engine

// ws_client_proxy_control_test.go pins the CWE-290 fix on the WebSocket
// dialer. gorilla passes the destination request to Dialer.Proxy, but the
// socket Control hook then sees only the proxy address. Without re-checking
// the destination in the proxy selector, a ws/wss URL carrying metadata or a
// private address could be fetched through an egress proxy unnoticed.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// wsTestProxyBase is a named function so reflect pointer identity can prove
// the nil-control passthrough returns the exact base selector.
func wsTestProxyBase(_ *http.Request) (*url.URL, error) {
	return &url.URL{Scheme: "http", Host: "127.0.0.1:3128"}, nil
}

// TestWebSocketProxyDestinationControl proves a refusing control stops a
// metadata destination before any socket to the proxy is opened.
func TestWebSocketProxyDestinationControl(t *testing.T) {
	var proxyHits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	base := func(*http.Request) (*url.URL, error) { return proxyURL, nil }

	var controlCalls atomic.Int32
	control := func(_, address string, _ syscall.RawConn) error {
		controlCalls.Add(1)
		if strings.HasPrefix(address, "169.254.169.254") {
			return errors.New("refusing metadata destination")
		}
		return nil
	}

	dialer := newWSDialerWithProxy(context.Background(), time.Second, control, base)
	conn, _, err := dialer.DialContext(context.Background(), "ws://169.254.169.254/latest/meta-data", nil)
	if err == nil {
		_ = conn.Close()
		t.Fatal("websocket dial succeeded although the destination control refused it")
	}
	if proxyHits.Load() != 0 {
		t.Fatalf("proxy received %d request(s); the destination must be refused before the proxy dial", proxyHits.Load())
	}
	if controlCalls.Load() == 0 {
		t.Fatal("destination control was never applied")
	}
}

// TestWebSocketProxyNilControlPassthrough proves a nil control leaves the
// proxy selector untouched (historical direct behavior), rather than wrapping
// it in a destination check.
func TestWebSocketProxyNilControlPassthrough(t *testing.T) {
	dialer := newWSDialerWithProxy(context.Background(), time.Second, nil, wsTestProxyBase)
	if dialer.Proxy == nil {
		t.Fatal("nil control produced a nil proxy selector")
	}
	got := reflect.ValueOf(dialer.Proxy).Pointer()
	want := reflect.ValueOf(wsTestProxyBase).Pointer()
	if got != want {
		t.Fatal("nil control wrapped the proxy selector; want the untouched base selector")
	}
}
