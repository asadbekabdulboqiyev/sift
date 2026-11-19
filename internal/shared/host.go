package shared

import (
	"net"
	"strings"
)

// IsLoopbackHost reports whether a host name (no port, no brackets) names the
// loopback interface. "localhost" is included because browsers and operators
// both use it, and every loopback literal (127.0.0.0/8, ::1) is included
// because the dashboard and the CLI default to 127.0.0.1.
//
// The input is a host, not an address: callers holding "host:port" or
// "[::1]:8888" must strip the port/brackets first (net.SplitHostPort /
// url.Hostname). Brackets are tolerated here because some callers pass a
// hostname taken from a raw URL field.
func IsLoopbackHost(host string) bool {
	h := strings.Trim(host, "[]")
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}
