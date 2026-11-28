package browser

// guardproxy.go — an authorization-aware loopback forward proxy for headless
// Chromium.
//
// Chromium is a separate process with its own DNS resolver and socket stack,
// so the net.Dialer.Control hook the scanner installs on its Go HTTP clients
// cannot see the addresses Chromium connects to. In browser crawl mode a
// hostile page could therefore rebind its own hostname to a metadata/RFC1918
// address, or simply fetch one directly, and read the result back through the
// rendered DOM — an SSRF path every other probe in Sift closes.
//
// The proxy listener core lives in internal/guardproxy (plain Go, no chromedp
// import) and is shared with controlled Go transports. It resolves and checks
// every CONNECT/absolute-form destination with authz.CheckedDialIPs and dials
// the checked literal IP with the same Control hook. Chromium is launched with
// --proxy-server pointed there and with the loopback bypass removed, so no
// page-initiated connection can skip the check.
//
// This file keeps only the browser-specific part: translating those launch
// flags into chromedp allocator options.

import (
	"net/http"
	"sync"
	"syscall"
	"time"

	"github.com/chromedp/chromedp"

	"github.com/asadbekabdulboqiyev/sift/internal/guardproxy"
)

// dialControl is the same hook shape used by Guard, AuthSession and authz.
type dialControl = guardproxy.Control

// guardProxy is a thin browser-facing wrapper around the shared plain-Go
// proxy. It keeps the historical browser API (addr/close) while removing the
// duplicated listener implementation.
//
// The launch address is captured once and close is serialized at this layer:
// a late or concurrent flag consumer can never observe a half-torn-down
// listener address, and repeated closes are a no-op (#3). A launch that still
// uses stale flags after Close fails closed — the loopback listener is gone,
// so Chromium gets a connection refusal, never an unguarded direct egress.
type guardProxy struct {
	*guardproxy.Proxy
	mu        sync.Mutex
	closed    bool
	addrValue string
}

func (p *guardProxy) addr() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.addrValue
}

func (p *guardProxy) close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	p.mu.Unlock()
	return p.Close()
}

// startGuardProxy starts the proxy on an ephemeral loopback port. A nil control
// means the caller has no gate decision to enforce, so no proxy is started at
// all and the browser keeps its direct network access (dev/default behavior).
func startGuardProxy(control dialControl, timeout time.Duration) (*guardProxy, error) {
	if control == nil {
		return nil, nil
	}
	p, err := guardproxy.New(guardproxy.Options{Control: control, Timeout: timeout})
	if err != nil {
		return nil, err
	}
	return &guardProxy{Proxy: p, addrValue: "http://" + p.Addr()}, nil
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

// splitAuthority is kept as a thin alias for browser tests that pin parsing
// behavior; the parser itself lives with the proxy that uses it.
func splitAuthority(req *http.Request) (string, string, error) {
	return guardproxy.SplitAuthority(req)
}
