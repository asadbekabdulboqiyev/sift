package browser

// guardproxy.go — an authorization-aware loopback forward proxy for headless
// Chromium.
//
// Chromium is a separate process with its own DNS resolver and socket stack, so
// the net.Dialer.Control hook the scanner installs on its Go HTTP clients (see
// internal/authz/dial.go) cannot see the addresses Chromium connects to. In
// browser crawl mode a hostile page could therefore rebind its own hostname to
// a metadata/RFC1918 address, or simply fetch one directly, and read the result
// back through the rendered DOM — an SSRF path every other probe in Sift closes.
//
// This proxy brings Chromium under the SAME decision the gate already approved:
// every CONNECT host:port and every absolute-form HTTP request is resolved and
// checked with authz.CheckDialTarget, then dialed with the identical Control
// hook. Chromium is launched with --proxy-server pointed here and with the
// loopback bypass removed, so no page-initiated connection can skip the check.
//
// The listener is bound to 127.0.0.1 only. The proxy never serves a request
// whose destination it could not authorize, so it is not an open relay.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/chromedp/chromedp"

	"github.com/asadbekabdulboqiyev/sift/internal/authz"
)

// dialControl is the same hook shape used by Guard, AuthSession and authz.
type dialControl = func(network, address string, c syscall.RawConn) error

const (
	guardProxyTimeout = 30 * time.Second
	// maxGuardProxyConns bounds concurrently open browser connections. A hostile
	// page can open many fetches/WebSockets at once; without a cap each tunnel
	// holds two goroutines and two sockets until it closes.
	maxGuardProxyConns = 64
)

// allowedProxyMethods is the method allow-list for absolute-form requests.
// CONNECT is handled separately; anything else is refused before a socket is
// opened. Keeping the list explicit prevents odd methods from reaching an
// origin through a component that only ever needed to render web pages.
var allowedProxyMethods = map[string]bool{
	http.MethodGet:     true,
	http.MethodHead:    true,
	http.MethodPost:    true,
	http.MethodPut:     true,
	http.MethodPatch:   true,
	http.MethodDelete:  true,
	http.MethodOptions: true,
}

// guardProxy is a loopback-only HTTP forward proxy that authorizes every
// destination against the class approved by the scan gate.
type guardProxy struct {
	control dialControl
	timeout time.Duration

	ln net.Listener

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
	wg     sync.WaitGroup
}

// startGuardProxy starts the proxy on an ephemeral loopback port. A nil control
// means the caller has no gate decision to enforce, so no proxy is started at
// all and the browser keeps its direct network access (dev/default behavior).
func startGuardProxy(control dialControl, timeout time.Duration) (*guardProxy, error) {
	if control == nil {
		return nil, nil
	}
	if timeout <= 0 {
		timeout = guardProxyTimeout
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("browser: guard proxy listen: %w", err)
	}
	p := &guardProxy{
		control: control,
		timeout: timeout,
		ln:      ln,
		conns:   make(map[net.Conn]struct{}),
	}
	p.wg.Add(1)
	go p.serve()
	return p, nil
}

// addr returns the value Chromium expects for --proxy-server.
func (p *guardProxy) addr() string {
	return "http://" + p.ln.Addr().String()
}

// guardProxyFlag is an inspectable description of one Chromium launch flag.
// Keeping the values separate from the chromedp option construction lets tests
// assert the actual proxy address, bypass and egress policy — not just a count.
type guardProxyFlag struct {
	name  string
	value any
}

// guardProxyFlagValues returns the guard flags for a proxy address. A single
// source of truth for Browser and the independent browser stacks.
func guardProxyFlagValues(proxyAddr string) []guardProxyFlag {
	return []guardProxyFlag{
		{"proxy-server", proxyAddr},
		// Chromium implicitly bypasses the proxy for localhost AND 169.254/16
		// (cloud metadata); "<-loopback>" subtracts those implicit rules, so
		// even those destinations must pass the guard proxy.
		{"proxy-bypass-list", "<-loopback>"},
		// Defense in depth: an Alt-Svc cache must not make Chromium race a
		// QUIC/HTTP3 connection straight to the origin behind the proxy.
		{"disable-quic", true},
		// WebRTC/STUN is UDP and cannot traverse the HTTP proxy. Blocking
		// non-proxied UDP removes that egress path.
		{"force-webrtc-ip-handling-policy", "disable_non_proxied_udp"},
	}
}

// guardProxyFlags returns the allocator options that make Chromium use p for
// every connection. Kept in one place so Browser and the other browser stacks
// cannot drift apart on the bypass/egress flags.
func guardProxyFlags(p *guardProxy) []chromedp.ExecAllocatorOption {
	values := guardProxyFlagValues(p.addr())
	opts := make([]chromedp.ExecAllocatorOption, 0, len(values))
	for _, f := range values {
		opts = append(opts, chromedp.Flag(f.name, f.value))
	}
	return opts
}

// GuardProxyOptions returns the allocator options that force any chromedp
// browser through a loopback guard proxy applying control, plus the closer
// that tears the proxy down. It exists so independent browser stacks (e.g.
// internal/browserload) cannot bypass the scan gate the way Chromium crawl
// mode did before this proxy was introduced.
//
// A nil control means no gate decision is available: no proxy is started, no
// flags are returned, and the closer is a no-op — the historical direct
// behavior for dev/availability checks. The caller MUST invoke close after its
// last browser run, even on error paths.
func GuardProxyOptions(control func(network, address string, c syscall.RawConn) error) ([]chromedp.ExecAllocatorOption, func() error, error) {
	proxy, err := startGuardProxy(control, 0)
	if err != nil {
		return nil, nil, err
	}
	if proxy == nil {
		return nil, func() error { return nil }, nil
	}
	return guardProxyFlags(proxy), proxy.close, nil
}

// close stops accepting, closes every active connection (unblocking tunnels)
// and waits for the handler goroutines to exit.
func (p *guardProxy) close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	for c := range p.conns {
		_ = c.Close()
	}
	p.mu.Unlock()

	err := p.ln.Close()
	p.wg.Wait()
	return err
}

func (p *guardProxy) serve() {
	defer p.wg.Done()
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return // listener closed by close()
		}
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			_ = conn.Close()
			return
		}
		if len(p.conns) >= maxGuardProxyConns {
			p.mu.Unlock()
			writeProxyError(conn, http.StatusServiceUnavailable, errors.New("too many browser connections"))
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

func (p *guardProxy) handleConn(conn net.Conn) {
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

// authorize applies the gate's class decision to the destination the browser
// actually wants to reach, then dials it with the same hook on the socket. Both
// layers matter: CheckDialTarget covers the proxy case where DialControl would
// otherwise only see the loopback proxy address, and DialControl catches a DNS
// answer that changes between resolution and connect.
func (p *guardProxy) authorize(ctx context.Context, host, port string) (net.Conn, error) {
	if host == "" || port == "" {
		return nil, errors.New("empty destination host or port")
	}
	ips, err := authz.CheckedDialIPs(ctx, host, port, p.control)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, errors.New("destination resolved to no addresses")
	}
	// Dial the address we checked, not the hostname: Chromium resolved nothing
	// here (with an HTTP proxy, name resolution is deferred to the proxy), so a
	// second lookup at connect time would reintroduce the rebinding race. The
	// Control hook stays installed as the authoritative socket-level check.
	d := &net.Dialer{
		Timeout:   p.timeout,
		KeepAlive: 30 * time.Second,
		Control:   p.control,
	}
	var lastErr error
	for _, ip := range ips {
		conn, dialErr := d.Dial("tcp", net.JoinHostPort(ip.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
	}
	if lastErr == nil {
		lastErr = errors.New("no approved address was reachable")
	}
	return nil, lastErr
}

// splitAuthority extracts host and port from either a CONNECT authority or an
// absolute-form request URL. Missing ports default by scheme for plain HTTP
// requests; CONNECT requires an explicit port.
func splitAuthority(req *http.Request) (string, string, error) {
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

func (p *guardProxy) handleConnect(conn net.Conn, br *bufio.Reader, req *http.Request) {
	host, port, err := splitAuthority(req)
	if err == nil {
		var upstream net.Conn
		upstream, err = p.authorize(req.Context(), host, port)
		if err == nil {
			if _, werr := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); werr != nil {
				_ = upstream.Close()
				return
			}
			// Tunnels (and WebSocket upgrades) are long-lived; the per-request
			// deadline must not sever them mid-stream.
			_ = conn.SetDeadline(time.Time{})
			_ = upstream.SetDeadline(time.Time{})
			bridge(conn, br, upstream, upstream)
			return
		}
	}
	writeProxyError(conn, http.StatusForbidden, err)
}

// handleHTTP forwards one absolute-form HTTP request. It returns false when the
// connection is consumed and must be closed: a refused request, a transport
// error, an upgraded (WebSocket) connection that was bridged, or the deliberate
// Connection: close after a normal response. Closing after one response means a
// second request for a different host can never ride an already-authorized
// socket.
func (p *guardProxy) handleHTTP(conn net.Conn, br *bufio.Reader, req *http.Request) bool {
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
	host, port, err := splitAuthority(req)
	if err != nil {
		writeProxyError(conn, http.StatusForbidden, err)
		return false
	}
	upstream, err := p.authorize(req.Context(), host, port)
	if err != nil {
		writeProxyError(conn, http.StatusForbidden, err)
		return false
	}
	defer func() { _ = upstream.Close() }()

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
		bridge(conn, br, upstream, upBR)
		return false
	}
	upResp.Close = true
	if err := upResp.Write(conn); err != nil {
		return false
	}
	return false
}

// bridge copies bytes in both directions until either side closes, then tears
// down both. Reads from the browser go through br so any bytes buffered past
// the request/CONNECT headers are not lost. Reads from the origin go through
// upReader for the same reason: on a 101 upgrade the response reader may hold
// frames coalesced with the handshake headers. CONNECT tunnels pass the raw
// upstream conn as both the writer and the reader.
func bridge(conn net.Conn, br *bufio.Reader, upstream net.Conn, upReader io.Reader) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, br)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(conn, upReader)
		done <- struct{}{}
	}()
	<-done
	_ = conn.Close()
	_ = upstream.Close()
	<-done
}

func writeProxyError(w io.Writer, code int, err error) {
	if err == nil {
		err = errors.New("destination refused")
	}
	body := "browser guard proxy: " + err.Error()
	_, _ = fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, http.StatusText(code), len(body), body)
}
