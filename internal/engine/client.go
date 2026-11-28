package engine

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/asadbekabdulboqiyev/sift/internal/authz"
	"github.com/asadbekabdulboqiyev/sift/internal/fingerprint"
	"github.com/asadbekabdulboqiyev/sift/internal/guardproxy"
)

const maxRedirects = 10

var errRedirectLimitReached = errors.New("stopped after 10 redirects")

// checkRedirect caps redirect chains and refuses to leave the original host or
// scheme. A same-host https -> http downgrade would send cookies and auth
// headers in cleartext on the next hop, so the scheme is pinned as well.
var checkRedirect = func(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return errRedirectLimitReached
	}
	if len(via) > 0 {
		first := via[0].URL
		if req.URL.Host != first.Host {
			return http.ErrUseLastResponse
		}
		if !strings.EqualFold(req.URL.Scheme, first.Scheme) {
			return http.ErrUseLastResponse
		}
	}
	return nil
}

// guardedTransports tracks the guard-proxy listener owned by each controlled
// transport (shared client and pre-warm clients). The engine has no public
// Close in its original API, so the run teardown in closeSessions looks the
// closers up by transport pointer; a finalizer on guardproxy.Lazy is the
// backstop for transports that never see a teardown.
var guardedTransports sync.Map // map[*http.Transport]io.Closer

// guardedEngines tracks guard proxies created for non-HTTP paths (WebSocket)
// when the shared transport has no guard of its own (e.g. a nil-control build).
// Controlled transports, including the uTLS CONNECT path, register in
// guardedTransports instead and are reused by engineWSDialer.
var guardedEngines sync.Map // map[*Engine]io.Closer

func registerTransportGuard(tr *http.Transport, closer io.Closer) {
	guardedTransports.Store(tr, closer)
}

// closeTransportGuard closes the listener for one transport, if it owns one.
// Closing is idempotent; the next request transparently starts a fresh proxy.
func closeTransportGuard(tr *http.Transport) {
	if tr == nil {
		return
	}
	if closer, ok := guardedTransports.Load(tr); ok {
		_ = closer.(io.Closer).Close()
	}
}

// Close stops the guard-proxy listeners owned by this engine. Run already
// calls it at teardown; library users that drive the engine's HTTP/WebSocket
// helpers directly can call it when done. It is safe to call more than once,
// and a later Run transparently starts fresh listeners on demand.
func (e *Engine) Close() error {
	closeTransportGuard(e.transport)
	for _, pc := range e.prewarmed.clients {
		closeTransportGuard(pc.transport)
	}
	if closer, ok := guardedEngines.Load(e); ok {
		_ = closer.(io.Closer).Close()
	}
	return nil
}

// baseTransportWithControl shares the common transport configuration. When
// tlsFP names a fingerprint, outgoing connections present that ClientHello
// instead of Go's default one, so the engine can mimic a real browser or
// platform at the TLS layer (measurable via JA3). Every controlled path now
// reaches the destination through the loopback guard proxy: plain HTTP via
// Transport.Proxy, uTLS via an explicit CONNECT performed in the dial seam.
func baseTransportWithControl(keepAlive bool, tlsFP fingerprint.Profile, control func(network, address string, c syscall.RawConn) error) *http.Transport {
	tr := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
			Control:   control,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConnsPerHost:   1,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		ReadBufferSize:        16 << 10, // fewer syscalls on large responses
		DisableKeepAlives:     !keepAlive,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			// Reuse TLS sessions across connections: resumed handshakes skip
			// most of the round trips, cutting per-connection CPU and latency
			// under heavy churn. Security posture is unchanged (TLS >= 1.2).
			ClientSessionCache: tls.NewLRUClientSessionCache(0),
		},
	}
	if control != nil && tlsFP == "" {
		// Airtight path: every request (including redirects to a name that
		// rebinds) goes through a loopback guard proxy that resolves the
		// destination, checks EVERY answer with control and dials the checked
		// literal IP with the same hook. This also ignores ambient egress
		// proxies, whose independent DNS lookup was the split-horizon gap.
		guarded, closer, err := guardproxy.WrapTransport(tr, control)
		if err == nil {
			registerTransportGuard(guarded, closer)
			return guarded
		}
		// Defensive fallback only: WrapTransport currently fails solely for a
		// custom DialTLSContext, which is excluded above. Keep the in-process
		// check rather than dropping control altogether.
	}
	if tlsFP != "" {
		// Go's transport can only recover the negotiated ALPN protocol from a
		// real *tls.Conn, never from a custom DialTLSContext result. uTLS
		// connections are not *tls.Conn, so HTTP/2 would silently fall back to
		// HTTP/1.1 over an h2-negotiated socket and fail. Presenting a browser
		// fingerprint therefore pins the connection to HTTP/1.1 — a fair trade,
		// since most browsers open plenty of HTTP/1.1 connections anyway.
		tr.ForceAttemptHTTP2 = false
		tr.TLSClientConfig.NextProtos = []string{"http/1.1"}

		opts := fingerprint.Options{
			Fingerprint: tlsFP,
			// Keep session resumption working when masquerading: uTLS keeps
			// its own cache, so repeated connections skip most of the
			// handshake just like the standard stack.
			SessionCache: utls.NewLRUClientSessionCache(0),
			NextProtos:   []string{"http/1.1"},
		}
		if control != nil {
			// net/http cannot combine Transport.Proxy with a custom
			// DialTLSContext: transport.go:1789 calls the custom dialer for
			// the first hop and only then (line 1831) runs proxy setup.
			// Keeping Proxy set would handshake with the guard and then try
			// CONNECT over that TLS socket. Instead Proxy stays nil and the
			// dial seam owns the CONNECT, so uTLS handshakes with the origin
			// over a guard-authorized tunnel.
			lazy := guardproxy.NewLazy(guardproxy.Options{Control: control})
			opts.DialContext = guardConnectDialContext(lazy, control)
			registerTransportGuard(tr, lazy)
		} else {
			// No authorization decision: keep the historical direct dial and
			// ambient proxy behavior for compatibility with existing callers.
			opts.Dialer = net.Dialer{}
		}
		tr.DialTLSContext = fingerprint.NewDialer(opts)
		if tr.Proxy == nil && control == nil {
			// No policy is being enforced here; keep the original ambient
			// selector without involving proxyWithControl on the uTLS path.
			tr.Proxy = http.ProxyFromEnvironment
		}
		return tr
	}
	if tr.Proxy == nil {
		tr.Proxy = proxyWithControl(http.ProxyFromEnvironment, control)
	}
	return tr
}

const guardConnectTimeout = 10 * time.Second

// guardConnectDialContext implements the TCP leg of a controlled uTLS dial.
// The caller's Control never sees the loopback socket to the guard; it is
// applied by the guard to every resolved destination address and to the
// checked literal IP before CONNECT returns 200. A refusal is surfaced as a
// dial error with the guard's status and body, so no ClientHello is sent to a
// destination that failed authorization.
func guardConnectDialContext(lazy *guardproxy.Lazy, control guardproxy.Control) func(context.Context, string, string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout:   guardConnectTimeout,
		KeepAlive: 30 * time.Second,
		Control:   lazy.Control(control),
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil, fmt.Errorf("guardproxy CONNECT: unsupported network %q", network)
		}
		if addr == "" || strings.ContainsAny(addr, " \r\n") {
			return nil, fmt.Errorf("guardproxy CONNECT: invalid authority %q", addr)
		}
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return nil, fmt.Errorf("guardproxy CONNECT: invalid authority %q: %w", addr, err)
		}
		proxyURL, err := lazy.URL()
		if err != nil {
			return nil, fmt.Errorf("guardproxy CONNECT: %w", err)
		}
		conn, err := dialer.DialContext(ctx, network, proxyURL.Host)
		if err != nil {
			return nil, err
		}
		ok := false
		defer func() {
			if !ok {
				_ = conn.Close()
			}
		}()

		deadline := time.Now().Add(guardConnectTimeout)
		if dl, has := ctx.Deadline(); has && dl.Before(deadline) {
			deadline = dl
		}
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("guardproxy CONNECT: set deadline: %w", err)
		}
		stopCancel := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
		req := &http.Request{
			Method: http.MethodConnect,
			URL:    &url.URL{Opaque: addr},
			Host:   addr,
			Header: make(http.Header),
		}
		if err := req.Write(conn); err != nil {
			stopCancel()
			return nil, fmt.Errorf("guardproxy CONNECT %s: write: %w", addr, err)
		}
		reader := bufio.NewReader(conn)
		resp, err := http.ReadResponse(reader, req)
		if err != nil {
			stopCancel()
			return nil, fmt.Errorf("guardproxy CONNECT %s: read response: %w", addr, err)
		}
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
			stopCancel()
			detail := strings.TrimSpace(string(body))
			if detail == "" {
				detail = resp.Status
			}
			return nil, fmt.Errorf("guardproxy CONNECT %s: %s: %s", addr, resp.Status, detail)
		}
		if !stopCancel() {
			return nil, ctx.Err()
		}
		if err := conn.SetDeadline(time.Time{}); err != nil {
			return nil, fmt.Errorf("guardproxy CONNECT %s: clear deadline: %w", addr, err)
		}
		ok = true
		return &bufferedConn{Conn: conn, reader: reader}, nil
	}
}

// bufferedConn preserves any bytes a bufio.Reader pulled past the CONNECT
// headers. CONNECT normally has none, but keeping the reader avoids losing
// early server bytes if that assumption ever changes.
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

// proxyWithControl re-applies the authorization decision to the destination
// when an HTTP proxy carries the request. A Dialer.Control hook sees the proxy
// address in that case, never the target: a name that resolved to an approved
// IP at gate time could rebind to instance metadata or RFC1918 space without
// the socket-level check noticing (CWE-290). When a proxy applies, the target
// host is resolved and passed through the same hook before the request proceeds.
//
// A nil control leaves the base proxy selector untouched.
//
// Deprecated: this is an in-process check only. A proxy that resolves the
// destination itself can still reach a different address. New controlled
// transports must use guardproxy.WrapTransport (or the uTLS CONNECT seam in
// baseTransportWithControl); this helper remains for replay and tests.
func proxyWithControl(base func(*http.Request) (*url.URL, error), control func(network, address string, c syscall.RawConn) error) func(*http.Request) (*url.URL, error) {
	// Delegate to the shared helper so the engine and the pentest transports
	// cannot drift on CWE-290 handling.
	return authz.ProxyWithControl(base, control)
}

// maxConnsPerHostCap bounds the per-host connection limit. Go's transport
// treats MaxConnsPerHost == 0 as "unlimited", but a wide-open limit invites
// unbounded FD growth when a target stalls; an explicit 100k cap covers 100k+
// concurrent virtual users while staying bounded. HTTP/2 multiplexes many
// requests over few connections, so on h2 targets the cap is rarely hit;
// HTTP/1.1 needs one connection per in-flight request, hence the high ceiling.
const maxConnsPerHostCap = 100_000

// applyHTTP2Preference forces the transport to negotiate (or skip) HTTP/2.
// enabled=true keeps Go's default behavior (try h2 via ALPN/h2c). enabled=false
// pins the stack to HTTP/1.1 in both directions: it disables h2c fallback on
// cleartext and narrows the TLS ALPN list so h2 is never negotiated either.
// The fingerprint path already pins NextProtos to "http/1.1" and sets
// ForceAttemptHTTP2=false, so applying this on top is a no-op there.
func applyHTTP2Preference(tr *http.Transport, enabled bool) {
	tr.ForceAttemptHTTP2 = enabled
	if !enabled && tr.TLSClientConfig != nil {
		tr.TLSClientConfig.NextProtos = []string{"http/1.1"}
	}
}

// newTransport is the compatibility wrapper used by existing callers and
// tests. New code that has an authorization hook must use the WithControl form.
func newTransport(keepAlive bool, maxConnsPerHost int, tlsFP fingerprint.Profile) *http.Transport {
	return newTransportWithControl(keepAlive, maxConnsPerHost, tlsFP, nil)
}

// newTransportWithControl builds the shared connection transport. One instance
// is reused by every HTTP client (including per-user cookie-jar clients), so
// pooled sockets, TLS sessions and HTTP/2 state stay shared. An explicit
// http2=false in the profile is applied by the caller via
// applyHTTP2Preference after fingerprint dialing is configured (fingerprinting
// re-pins NextProtos).
func newTransportWithControl(keepAlive bool, maxConnsPerHost int, tlsFP fingerprint.Profile, control func(network, address string, c syscall.RawConn) error) *http.Transport {
	if maxConnsPerHost < 256 {
		maxConnsPerHost = 256
	}
	if maxConnsPerHost > maxConnsPerHostCap {
		maxConnsPerHost = maxConnsPerHostCap
	}
	tr := baseTransportWithControl(keepAlive, tlsFP, control)
	// Idle pool is sized generously (4x): MaxConnsPerHost caps live
	// connections, and idle sockets need headroom so a burst of HTTP/1.1
	// keep-alive requests never sits behind a fresh dial.
	tr.MaxIdleConns = maxConnsPerHost * 4
	tr.MaxIdleConnsPerHost = maxConnsPerHost
	tr.MaxConnsPerHost = maxConnsPerHost
	return tr
}

// clientForJar returns the HTTP client bound to userIndex's cookie jar.
// The client is created once per virtual user and reused for the whole run:
// the heavy transport is shared and the Jar reference never changes, so
// caching the lightweight http.Client wrapper removes a per-request heap
// allocation on the hot path. userIndex < 0 (library calls) or keep-alive
// disabled share the base client without cookies.
func (e *Engine) clientForJar(userIndex int) *http.Client {
	if userIndex < 0 || !e.keepAlive {
		return e.client
	}
	clients := e.jarClients
	if userIndex < len(clients) {
		if c := clients[userIndex]; c != nil {
			return c
		}
	}
	// Cold path: pre-run library use, or the slot was dropped via
	// dropCookieJar. Sessions are built under sessMu; during a run every slot
	// is pre-populated so this path is never taken by workers.
	e.ensureUserSession(userIndex)
	if userIndex < len(e.jarClients) {
		if c := e.jarClients[userIndex]; c != nil {
			return c
		}
	}
	return e.client
}
