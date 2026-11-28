// proxy.go — re-apply the dial decision to the destination when an HTTP proxy
// carries the request.
//
// A net.Dialer.Control hook runs on the socket to the PROXY, never to the
// destination. On its own it cannot stop a name that resolved to an approved
// address at gate time from rebinding to instance metadata or RFC1918 space
// and being fetched by the egress proxy (CWE-290). The Guard and the engine
// already do this at their request boundary; this shared helper gives every
// other controlled HTTP transport the same check so none of them can drift.
package authz

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"syscall"
)

// ProxyWithControl wraps a transport's Proxy selector so that whenever a proxy
// applies to a request, the destination host is resolved and every answer is
// passed through control before the dial to the proxy is allowed. The selector
// returns control's error to abort the request before any socket is opened.
//
// When the base selector returns nil for a request there is no proxy, so the
// socket-level Control hook sees the real destination and no extra check is
// needed. A nil control or a nil base leaves the selector untouched, keeping
// the historical direct behavior for dev/tests.
//
// Residual: the proxy resolves the destination independently, so this check
// cannot defeat a hostile proxy or a split-horizon/rebind between the client's
// lookup and the proxy's own lookup. It narrows the window to the same accepted
// limit already present in Guard.checkProxyTarget and engine.proxyWithControl;
// the only airtight path is the guard proxy, which dials the checked literal IP.
//
// Migration note: new controlled transports should prefer internal/guardproxy's
// WrapTransport, which resolves, checks and dials the checked literal IP itself.
// This helper is intentionally retained: replay's library path and the
// fallback branch of each guard-proxy caller still need the in-process check.
func ProxyWithControl(base func(*http.Request) (*url.URL, error), control func(network, address string, c syscall.RawConn) error) func(*http.Request) (*url.URL, error) {
	if base == nil || control == nil {
		return base
	}
	return func(req *http.Request) (*url.URL, error) {
		if req == nil || req.URL == nil {
			return nil, fmt.Errorf("authz: proxy dial target has no request URL")
		}
		proxyURL, err := base(req)
		if err != nil || proxyURL == nil {
			return proxyURL, err // no proxy for this request; the dial hook sees the real target
		}
		host := req.URL.Hostname()
		if host == "" {
			return nil, fmt.Errorf("authz: proxy dial target has no host")
		}
		port := req.URL.Port()
		if port == "" {
			port = "80"
			if scheme := strings.ToLower(req.URL.Scheme); scheme == "https" || scheme == "wss" {
				port = "443"
			}
		}
		if err := CheckDialTarget(req.Context(), host, port, control); err != nil {
			return nil, err
		}
		return proxyURL, nil
	}
}
