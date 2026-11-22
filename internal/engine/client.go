package engine

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/asadbekabdulboqiyev/sift/internal/authz"
	"github.com/asadbekabdulboqiyev/sift/internal/fingerprint"
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

// baseTransportWithControl shares the common transport configuration. When
// tlsFP names a fingerprint, outgoing connections present that ClientHello
// instead of Go's default one, so the engine can mimic a real browser or
// platform at the TLS layer (measurable via JA3). control, when non-nil, is
// installed on every underlying TCP dial, including the uTLS path, so an
// authorization decision can still refuse the address a socket reaches after
// DNS resolution.
func baseTransportWithControl(keepAlive bool, tlsFP fingerprint.Profile, control func(network, address string, c syscall.RawConn) error) *http.Transport {
	tr := &http.Transport{
		Proxy: proxyWithControl(http.ProxyFromEnvironment, control),
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
	if tlsFP != "" {
		// Go's transport can only recover the negotiated ALPN protocol from a
		// real *tls.Conn, never from a custom DialTLSContext result. uTLS
		// connections are not *tls.Conn, so HTTP/2 would silently fall back to
		// HTTP/1.1 over an h2-negotiated socket and fail. Presenting a browser
		// fingerprint therefore pins the connection to HTTP/1.1 — a fair trade,
		// since most browsers open plenty of HTTP/1.1 connections anyway.
		tr.ForceAttemptHTTP2 = false
		tr.TLSClientConfig.NextProtos = []string{"http/1.1"}
		tr.DialTLSContext = fingerprint.NewDialer(fingerprint.Options{
			Fingerprint: tlsFP,
			// The TCP leg of the uTLS dial carries the same socket-level hook
			// as the plain HTTP dialer; Options.resolved fills in its timeouts.
			Dialer: net.Dialer{Control: control},
			// Keep session resumption working when masquerading: uTLS keeps
			// its own cache, so repeated connections skip most of the
			// handshake just like the standard stack.
			SessionCache: utls.NewLRUClientSessionCache(0),
			NextProtos:   []string{"http/1.1"},
		})
	}
	return tr
}

// proxyWithControl re-applies the authorization decision to the destination
// when an HTTP proxy carries the request. A Dialer.Control hook sees the proxy
// address in that case, never the target: a name that resolved to an approved
// IP at gate time could rebind to instance metadata or RFC1918 space without
// the socket-level check noticing (CWE-290). When a proxy applies, the target
// host is resolved and passed through the same hook before the request proceeds.
//
// A nil control leaves the base proxy selector untouched.
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
