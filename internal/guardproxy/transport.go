package guardproxy

// transport.go — the controlled HTTP-transport adapter.
//
// Pointing a Go transport at a plain forward proxy is not enough: the socket
// Control hook would see the loopback proxy address, and a class check such as
// authz.DialControl(ClassPublic) would refuse it as "loopback". The adapter
// therefore (a) pins the transport's Proxy selector to the local guard proxy,
// (b) exempts only that exact loopback socket from the caller's Control hook
// while leaving the hook on every other dial, and (c) returns an io.Closer so
// the owner can shut the listener down with its own lifecycle.

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"sync"
	"syscall"
	"time"
)

// Lazy owns a guard proxy that is created on first use and can be recreated
// after Close, so an Engine run can be reused without pinning a dead listener.
// It is safe for concurrent use. A finalizer is a backstop for callers with no
// explicit teardown seam; callers that have one must still call Close.
type Lazy struct {
	mu   sync.Mutex
	opts Options
	p    *Proxy
}

// NewLazy prepares a guard proxy without starting a listener yet. A nil
// control produces a Lazy whose selector returns an error; use WrapTransport
// to keep the historical direct behavior for nil controls instead.
func NewLazy(opts Options) *Lazy {
	l := &Lazy{opts: opts}
	// The listener goroutines hold *Proxy, not *Lazy, so this finalizer is a
	// real backstop: when the owning transport becomes unreachable its Proxy
	// closure (and with it the Lazy) becomes unreachable too.
	runtime.SetFinalizer(l, func(l *Lazy) { _ = l.Close() })
	return l
}

// get returns the live proxy, creating it on first use or after a Close.
func (l *Lazy) get() (*Proxy, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.p == nil || l.p.Closed() {
		p, err := New(l.opts)
		if err != nil {
			return nil, err
		}
		l.p = p
	}
	return l.p, nil
}

// URL returns the current (or first) guard proxy URL.
func (l *Lazy) URL() (*url.URL, error) {
	p, err := l.get()
	if err != nil {
		return nil, err
	}
	return p.URL(), nil
}

// Closed reports whether no live listener is currently owned. A closed Lazy
// starts a fresh proxy on the next URL call, so this is a lifecycle diagnostic,
// not a permanent terminal state.
func (l *Lazy) Closed() bool {
	l.mu.Lock()
	p := l.p
	l.mu.Unlock()
	return p == nil || p.Closed()
}

// ProxySelector is an http.Transport.Proxy / websocket.Dialer.Proxy selector
// that pins every request through the local guard proxy. Environment proxies
// are deliberately ignored: they resolve destinations independently and are
// the split-horizon path this adapter removes.
func (l *Lazy) ProxySelector() func(*http.Request) (*url.URL, error) {
	return func(*http.Request) (*url.URL, error) {
		u, err := l.URL()
		if err != nil {
			return nil, fmt.Errorf("guardproxy: %w", err)
		}
		return u, nil
	}
}

// IsGuardAddr reports whether address (host:port) is the proxy's own loopback
// listener. The socket to the proxy must be exempt from the destination class
// check: the guard applies that check to the destination itself.
func (l *Lazy) IsGuardAddr(address string) bool {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	l.mu.Lock()
	p := l.p
	l.mu.Unlock()
	if p == nil {
		return false
	}
	ph, pp, err := net.SplitHostPort(p.Addr())
	return err == nil && host == ph && port == pp
}

// Control returns a hook that passes only the guard proxy's own socket without
// checking, and otherwise applies control unchanged. This keeps the caller's
// decision on every direct dial while making the loopback proxy usable even
// under a strict public-only decision.
func (l *Lazy) Control(control Control) Control {
	if control == nil {
		return nil
	}
	return func(network, address string, c syscall.RawConn) error {
		if l.IsGuardAddr(address) {
			return nil
		}
		return control(network, address, c)
	}
}

// Close stops the current proxy, if any. The next request transparently
// starts a fresh one. It is idempotent. The underlying Proxy.Close error is
// propagated rather than swallowed (#5), and the ordered shutdown there
// unblocks bridge pumps as well as handlers (#1, #2, #4).
func (l *Lazy) Close() error {
	l.mu.Lock()
	p := l.p
	l.p = nil
	l.mu.Unlock()
	if p == nil {
		return nil
	}
	err := p.Close()
	// Keep l reachable until p.Close returns so the finalizer cannot fire in
	// the middle of an explicit teardown.
	runtime.KeepAlive(l)
	return err
}

// noopCloser preserves direct behavior for callers without a gate decision.
type noopCloser struct{}

func (noopCloser) Close() error { return nil }

// WrapTransport clones base and pins its Proxy selector to a locally created
// guard proxy. The returned transport keeps the caller's TLS, pooling and
// redirect settings, and its DialContext.Control hook is retained for direct
// dials; only the loopback socket to the guard proxy is exempt.
//
// A nil control returns a clone with the original proxy selector (usually
// http.ProxyFromEnvironment) and a no-op closer: dev/tests keep the
// historical direct behavior and must not pay for an unused listener.
//
// Transports with a custom DialTLSContext (uTLS fingerprinting) cannot use the
// Proxy field: Go calls that hook with the PROXY address, so the fingerprinted
// TLS handshake would target the guard instead of the origin. Their owner must
// keep Proxy nil and perform CONNECT in the dial seam (see the engine's
// guardConnectDialContext); this helper deliberately refuses to misconfigure
// such a transport instead of silently leaving the destination unchecked.
func WrapTransport(base *http.Transport, control Control) (*http.Transport, io.Closer, error) {
	tr := base
	if tr == nil {
		tr = http.DefaultTransport.(*http.Transport).Clone()
	} else {
		tr = tr.Clone()
	}
	if control == nil {
		return tr, noopCloser{}, nil
	}
	if tr.DialTLSContext != nil {
		return nil, nil, fmt.Errorf("guardproxy: custom DialTLSContext cannot be proxied (fingerprint path)")
	}
	lazy := NewLazy(Options{Control: control})
	tr.Proxy = lazy.ProxySelector()

	// Go resolves the proxy itself and calls DialContext with the proxy's
	// loopback address. Dial that socket with the same timing settings but the
	// guard-exempt control; any non-proxy dial still uses the caller's hook.
	proxyDialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: lazy.Control(control)}
	callerDial := tr.DialContext
	tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if lazy.IsGuardAddr(address) {
			return proxyDialer.DialContext(ctx, network, address)
		}
		if callerDial != nil {
			return callerDial(ctx, network, address)
		}
		return proxyDialer.DialContext(ctx, network, address)
	}
	return tr, lazy, nil
}
