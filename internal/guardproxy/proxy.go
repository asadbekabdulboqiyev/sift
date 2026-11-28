// Package guardproxy implements an authorization-aware loopback forward proxy
// for Go HTTP/WebSocket transports and for browser launchers.
//
// A net.Dialer.Control hook runs on the socket to the PROXY, never to the
// destination. Re-checking the destination in-process before handing it to a
// proxy therefore cannot defeat a hostile or split-horizon resolver: the proxy
// performs its own lookup and may connect somewhere the client never checked.
//
// This package closes that gap by owning the proxy itself. Every CONNECT
// authority and every absolute-form HTTP URL is resolved and checked with
// authz.CheckedDialIPs, and the upstream socket is dialed to a checked LITERAL
// IP with the same Control hook installed. Zero approved addresses means no
// connection. The listener is loopback-only and connection count is bounded.
package guardproxy

import (
	"bufio"
	"context"
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

	"github.com/asadbekabdulboqiyev/sift/internal/authz"
)

// Control is the net.Dialer.Control hook shape used across Sift.
type Control = func(network, address string, c syscall.RawConn) error

const (
	defaultTimeout = 30 * time.Second
	defaultMaxConn = 64
)

// allowedProxyMethods is the method allow-list for absolute-form requests.
// CONNECT is handled separately; anything else is refused before a socket is
// opened. Keeping the list explicit prevents odd methods from reaching an
// origin through a component that only ever needed to render/probe web pages.
var allowedProxyMethods = map[string]bool{
	http.MethodGet:     true,
	http.MethodHead:    true,
	http.MethodPost:    true,
	http.MethodPut:     true,
	http.MethodPatch:   true,
	http.MethodDelete:  true,
	http.MethodOptions: true,
}

// Options configures a Proxy. Control is mandatory in practice: without it
// there is no authorization decision to enforce and New returns an error.
// DialContext is an optional seam for tests; when nil the proxy uses a
// net.Dialer with Timeout/KeepAlive and the Control hook installed.
type Options struct {
	Control     Control
	Timeout     time.Duration
	MaxConns    int
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)

	// listen is an unexported seam used by package tests to inject a listener
	// whose Close fails, proving Close propagates teardown errors (#5).
	listen func(network, address string) (net.Listener, error)
}

// destinationError carries the HTTP status a destination failure must produce.
// A policy refusal stays 403; a failure to reach a policy-approved literal IP
// is 502. Keeping them distinct prevents a refused destination from being
// mistaken for a reachable one, and keeps a dial failure from being reported
// as a successful tunnel.
type destinationError struct {
	status int
	err    error
}

func (e *destinationError) Error() string { return e.err.Error() }
func (e *destinationError) Unwrap() error { return e.err }

func proxyErrorStatus(err error) int {
	var de *destinationError
	if errors.As(err, &de) {
		return de.status
	}
	return http.StatusForbidden
}

// Proxy is a loopback-only HTTP forward proxy that authorizes every
// destination against the class accepted by the scan gate.
type Proxy struct {
	control     Control
	timeout     time.Duration
	maxConns    int
	dialContext func(ctx context.Context, network, address string) (net.Conn, error)

	ln net.Listener

	// ctx is canceled by Close. authorize uses it so a shutdown aborts an
	// in-flight DNS lookup or upstream dial instead of waiting for its timeout
	// (#1, #4). It is never used to keep a tunnel alive: tunnels are torn down
	// by closing the tracked sockets.
	ctx    context.Context
	cancel context.CancelFunc

	mu        sync.Mutex
	conns     map[net.Conn]struct{} // accepted client sockets
	upstreams map[net.Conn]struct{} // sockets dialed after a policy check
	closed    bool
	wg        sync.WaitGroup // serve loop, handlers and bridge pumps
}

// New starts the proxy on an ephemeral loopback port. A nil control is a
// configuration error: the whole point of this component is to enforce the
// caller's decision, and silently starting an open relay would be worse than
// failing to start.
func New(opts Options) (*Proxy, error) {
	if opts.Control == nil {
		return nil, errors.New("guardproxy: nil Control: refusing to start an unguarded proxy")
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	maxConns := opts.MaxConns
	if maxConns <= 0 {
		maxConns = defaultMaxConn
	}
	listen := opts.listen
	if listen == nil {
		listen = net.Listen
	}
	ln, err := listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("guardproxy: listen: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &Proxy{
		control:     opts.Control,
		timeout:     timeout,
		maxConns:    maxConns,
		dialContext: opts.DialContext,
		ln:          ln,
		ctx:         ctx,
		cancel:      cancel,
		conns:       make(map[net.Conn]struct{}),
		upstreams:   make(map[net.Conn]struct{}),
	}
	p.wg.Add(1)
	go p.serve()
	return p, nil
}

// URL returns the loopback proxy URL for use as http.Transport.Proxy or as a
// Chromium --proxy-server value.
func (p *Proxy) URL() *url.URL {
	return &url.URL{Scheme: "http", Host: p.ln.Addr().String()}
}

// Addr returns the host:port the proxy listens on.
func (p *Proxy) Addr() string { return p.ln.Addr().String() }

// Closed reports whether Close has been called. A closed proxy must not be
// used as a proxy target any more.
func (p *Proxy) Closed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closed
}

// State reports shutdown state for tests and lifecycle diagnostics. The active
// count includes both client sockets and checked upstream sockets, so a
// successful close must always observe zero (#1, #2).
func (p *Proxy) State() (activeConns int, closed bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.conns) + len(p.upstreams), p.closed
}

// Close performs an ordered, idempotent shutdown:
//
//  1. mark closed under the lock and snapshot every tracked socket, so no new
//     client or upstream connection can be registered after this point;
//  2. cancel the proxy context, aborting in-flight authorization/dial work;
//  3. close the listener, so no new client can be accepted;
//  4. close tracked client sockets first, then upstream sockets, unblocking
//     both directions of every bridge;
//  5. wait for the serve loop, handlers and bridge pumps to exit.
//
// Listener and socket close failures are returned (net.ErrClosed on a socket
// that a handler already closed is benign and ignored) instead of being
// silently dropped by callers (#5). The context is canceled even when a close
// fails, so a failed teardown never leaves an unguarded listener alive.
func (p *Proxy) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	clients := make([]net.Conn, 0, len(p.conns))
	for c := range p.conns {
		clients = append(clients, c)
	}
	upstreams := make([]net.Conn, 0, len(p.upstreams))
	for c := range p.upstreams {
		upstreams = append(upstreams, c)
	}
	p.mu.Unlock()

	p.cancel()
	var firstErr error
	if err := p.ln.Close(); err != nil {
		firstErr = err
	}
	closeAll := func(conns []net.Conn) {
		for _, c := range conns {
			if err := c.Close(); err != nil && firstErr == nil && !errors.Is(err, net.ErrClosed) {
				firstErr = err
			}
		}
	}
	closeAll(clients)
	closeAll(upstreams)
	p.wg.Wait()
	return firstErr
}

// trackUpstream registers a socket dialed to a checked literal IP. It refuses
// to register after shutdown and closes the socket in that case (#1).
func (p *Proxy) trackUpstream(c net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		_ = c.Close()
		return false
	}
	p.upstreams[c] = struct{}{}
	return true
}

func (p *Proxy) closeUpstream(c net.Conn) {
	if c == nil {
		return
	}
	p.mu.Lock()
	delete(p.upstreams, c)
	p.mu.Unlock()
	_ = c.Close()
}

func (p *Proxy) serve() {
	defer p.wg.Done()
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return // listener closed by Close
		}
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			_ = conn.Close()
			return
		}
		if len(p.conns) >= p.maxConns {
			p.mu.Unlock()
			writeProxyError(conn, http.StatusServiceUnavailable, errors.New("too many proxy connections"))
			_ = conn.Close()
			continue
		}
		p.conns[conn] = struct{}{}
		p.mu.Unlock()

		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			defer func() {
				p.mu.Lock()
				delete(p.conns, conn)
				p.mu.Unlock()
				_ = conn.Close()
			}()
			p.handleConn(conn)
		}()
	}
}

func (p *Proxy) handleConn(conn net.Conn) {
	br := bufio.NewReader(conn)
	for {
		_ = conn.SetDeadline(time.Now().Add(p.timeout))
		req, err := http.ReadRequest(br)
		if err != nil {
			// A clean EOF is a normal connection close. A malformed request
			// line/header still deserves a response rather than a silent drop,
			// which also makes rejection testable without an http.Server.
			if !errors.Is(err, io.EOF) {
				writeProxyError(conn, http.StatusBadRequest, err)
			}
			return
		}
		if req.Method == http.MethodConnect {
			p.handleConnect(conn, br, req)
			return
		}
		if !p.handleHTTP(conn, br, req) {
			return
		}
	}
}

// authorize applies the gate's class decision to the destination the client
// actually wants to reach, then dials it with the same hook on the socket.
// Both layers matter: CheckedDialIPs covers the proxy case where DialControl
// would otherwise only see the loopback proxy address, and the Control hook
// catches a DNS answer that changes between resolution and connect.
func (p *Proxy) authorize(ctx context.Context, host, port string) (net.Conn, error) {
	if host == "" || port == "" {
		return nil, errors.New("empty destination host or port")
	}
	ips, err := authz.CheckedDialIPs(ctx, host, port, p.control)
	if err != nil {
		// Policy refusal: 403. Keep the authz reason in the response body.
		return nil, &destinationError{status: http.StatusForbidden, err: err}
	}
	if len(ips) == 0 {
		return nil, &destinationError{status: http.StatusForbidden, err: errors.New("destination resolved to no addresses")}
	}
	// Dial the address we checked, not the hostname: the client resolved
	// nothing here (with an HTTP proxy, name resolution is deferred to us), so
	// a second lookup at connect time would reintroduce the rebinding race.
	// The Control hook stays installed as the authoritative socket-level check.
	dial := p.dialContext
	if dial == nil {
		d := &net.Dialer{
			Timeout:   p.timeout,
			KeepAlive: 30 * time.Second,
			Control:   p.control,
		}
		dial = d.DialContext
	}
	var lastErr error
	for _, ip := range ips {
		conn, dialErr := dial(ctx, "tcp", net.JoinHostPort(ip.String(), port))
		if dialErr == nil {
			if conn == nil {
				return nil, &destinationError{status: http.StatusBadGateway, err: errors.New("dial seam returned a nil connection")}
			}
			// Register the socket before returning it: Close can race with a
			// completed dial and must still see this connection (#1). The caller
			// releases it with closeUpstream.
			if !p.trackUpstream(conn) {
				return nil, &destinationError{status: http.StatusBadGateway, err: errors.New("guard proxy closed while dialing destination")}
			}
			return conn, nil
		}
		lastErr = dialErr
	}
	if lastErr == nil {
		lastErr = errors.New("no approved address was reachable")
	}
	// A checked literal IP was approved but could not be reached. This is a
	// gateway failure, NOT a policy refusal, and must never be reported as a
	// successful CONNECT (#6).
	return nil, &destinationError{status: http.StatusBadGateway, err: lastErr}
}

// SplitAuthority extracts host and port from either a CONNECT authority or an
// absolute-form request URL. Missing ports default by scheme for plain HTTP
// requests; CONNECT requires an explicit port.
func SplitAuthority(req *http.Request) (string, string, error) {
	var authority string
	switch {
	case req.Method == http.MethodConnect:
		authority = req.Host
		if authority == "" && req.URL != nil {
			authority = req.URL.Host
		}
	case req.URL != nil:
		authority = req.URL.Host
		if authority == "" {
			authority = req.Host
		}
	default:
		authority = req.Host
	}
	if authority == "" {
		return "", "", errors.New("missing destination authority")
	}
	host, port, err := net.SplitHostPort(authority)
	if err != nil {
		if req.Method == http.MethodConnect {
			return "", "", fmt.Errorf("CONNECT requires host:port: %w", err)
		}
		host = authority
		// An absolute-form URL on the default port omits the port but keeps
		// IPv6 brackets, e.g. "http://[::1]/". Strip them so CheckedDialIPs
		// sees a literal ParseIP can classify instead of a bogus hostname.
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			host = host[1 : len(host)-1]
		}
		port = "80"
		if req.URL != nil && strings.EqualFold(req.URL.Scheme, "https") {
			port = "443"
		}
	}
	if host == "" || port == "" {
		return "", "", errors.New("empty destination host or port")
	}
	return host, port, nil
}

func (p *Proxy) handleConnect(conn net.Conn, br *bufio.Reader, req *http.Request) {
	host, port, err := SplitAuthority(req)
	if err != nil {
		writeProxyError(conn, http.StatusForbidden, err)
		return
	}
	// authorize is bound to the proxy lifetime: Close aborts a dial that is
	// still in flight instead of waiting for its full timeout (#4).
	upstream, err := p.authorize(p.ctx, host, port)
	if err != nil {
		writeProxyError(conn, proxyErrorStatus(err), err)
		return
	}
	defer func() { p.closeUpstream(upstream) }()

	// CRITICAL (#6): 200 is written only AFTER the checked literal IP has been
	// successfully dialed above. A dial failure is reported as 502 by the
	// branch above, so a client can never use a 200 as proof that a refused or
	// unreachable destination was reached.
	if _, werr := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); werr != nil {
		return
	}
	// Tunnels (and WebSocket upgrades) are long-lived; the per-request
	// deadline must not sever them mid-stream. Close tears them down by
	// closing the tracked client and upstream sockets.
	_ = conn.SetDeadline(time.Time{})
	_ = upstream.SetDeadline(time.Time{})
	p.bridge(conn, br, upstream, upstream)
}

// handleHTTP forwards one absolute-form HTTP request. It returns false when
// the connection is consumed and must be closed: a refused request, a
// transport error, an upgraded (WebSocket) connection that was bridged, or the
// deliberate Connection: close after a normal response. Closing after one
// response means a second request for a different host can never ride an
// already-authorized socket.
func (p *Proxy) handleHTTP(conn net.Conn, br *bufio.Reader, req *http.Request) bool {
	if req.URL == nil || req.URL.Host == "" {
		writeProxyError(conn, http.StatusForbidden, errors.New("absolute-form request required"))
		return false
	}
	if !allowedProxyMethods[req.Method] {
		writeProxyError(conn, http.StatusMethodNotAllowed, fmt.Errorf("method %q is not allowed through the guard proxy", req.Method))
		return false
	}
	// Absolute-form requests carry a cleartext target. HTTPS (and WSS) must use
	// CONNECT so TLS is established end-to-end with the origin; accepting
	// absolute-form https here would send a plaintext request to a TLS port.
	scheme := strings.ToLower(req.URL.Scheme)
	if scheme != "http" {
		writeProxyError(conn, http.StatusForbidden, fmt.Errorf("unsupported absolute-form proxy scheme %q", scheme))
		return false
	}
	host, port, err := SplitAuthority(req)
	if err != nil {
		writeProxyError(conn, http.StatusForbidden, err)
		return false
	}
	upstream, err := p.authorize(p.ctx, host, port)
	if err != nil {
		writeProxyError(conn, proxyErrorStatus(err), err)
		return false
	}
	defer func() { p.closeUpstream(upstream) }()

	// Turn the proxy-form request into an origin-form one before writing it to
	// the destination, and strip hop-by-hop proxy credentials.
	req.RequestURI = ""
	req.URL.Scheme = ""
	req.URL.Host = ""
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Proxy-Connection")
	if err := req.Write(upstream); err != nil {
		return false
	}

	// Keep the reader used for the response: for a 101 upgrade it may have
	// already buffered the origin's first WebSocket frame(s) when they were
	// coalesced with the headers. The bridge must drain THAT reader, not the
	// raw socket, or those frames are silently lost.
	upBR := bufio.NewReader(upstream)
	upResp, err := http.ReadResponse(upBR, req)
	if err != nil {
		return false
	}
	if upResp.StatusCode == http.StatusSwitchingProtocols {
		// WebSocket upgrade: relay the 101 and then pipe the upgraded stream.
		// The single authorization above covers the whole upgraded connection.
		if err := upResp.Write(conn); err != nil {
			return false
		}
		_ = conn.SetDeadline(time.Time{})
		_ = upstream.SetDeadline(time.Time{})
		p.bridge(conn, br, upstream, upBR)
		return false
	}
	upResp.Close = true
	if err := upResp.Write(conn); err != nil {
		return false
	}
	return false
}

// bridge copies bytes in both directions until either side closes, then tears
// down both. Reads from the client go through br so any bytes buffered past
// the request/CONNECT headers are not lost. Reads from the origin go through
// upReader for the same reason: on a 101 upgrade the response reader may hold
// frames coalesced with the handshake headers. CONNECT tunnels pass the raw
// upstream conn as both the writer and the reader.
func (p *Proxy) bridge(conn net.Conn, br *bufio.Reader, upstream net.Conn, upReader io.Reader) {
	done := make(chan struct{}, 2)
	// The pumps are counted in the same WaitGroup as handlers, so Close cannot
	// return while a bridge goroutine is still running (#2). Adding while a
	// Wait is in progress is safe: the calling handler still holds a count.
	p.wg.Add(2)
	go func() {
		defer p.wg.Done()
		_, _ = io.Copy(upstream, br)
		done <- struct{}{}
	}()
	go func() {
		defer p.wg.Done()
		_, _ = io.Copy(conn, upReader)
		done <- struct{}{}
	}()
	<-done
	_ = conn.Close()
	p.closeUpstream(upstream)
	<-done
}

func writeProxyError(w io.Writer, code int, err error) {
	if err == nil {
		err = errors.New("destination refused")
	}
	body := "guard proxy: " + err.Error()
	_, _ = fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, http.StatusText(code), len(body), body)
}
