// dial.go — re-apply the authorization decision to the address actually dialed.
//
// Classify runs before a scan and resolves the target name. The dialer then
// resolves the same name again, and DNS is allowed to answer differently: a
// name that resolved to a public address during the check can resolve to
// 169.254.169.254 (cloud instance metadata) or to an RFC1918 address a moment
// later. The address that matters is the one on the socket, so the decision is
// enforced there too.
//
// The hooks are net.Dialer.Control functions: they run after the socket is
// created but before it connects, with the peer address already resolved, and a
// non-nil error aborts the connection.
package authz

import (
	"fmt"
	"net"
	"syscall"
)

// DialControl returns a net.Dialer.Control hook that refuses a connection whose
// actual peer is classified more restrictively than approved.
//
// approved is the class the gate accepted (Target.Class()). A peer of that
// class or a less restrictive one is allowed, so rotating DNS among public
// addresses, a private target the policy allowed, and metadata an operator
// explicitly authorized all keep working. A peer that is more restrictive than
// what was approved — the rebinding case — is refused.
func DialControl(approved Class) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, _ syscall.RawConn) error {
		ip, ok := peerIP(address)
		if !ok {
			return nil // not an address this hook can judge; the dial reports its own error
		}
		if got := ClassifyIP(ip); got.severity() > approved.severity() {
			return fmt.Errorf("authz: refusing to connect to %s: %s is more restrictive than the approved %s class", ip, got, approved)
		}
		return nil
	}
}

// DenyClasses returns a net.Dialer.Control hook that refuses a connection to
// any of the named classes regardless of what was approved.
//
// Use it where a class is closed unconditionally, not by policy: instance
// metadata on the load-test path is the credential-theft destination and no
// admin unlock opens it.
func DenyClasses(denied ...Class) func(network, address string, c syscall.RawConn) error {
	set := make(map[Class]bool, len(denied))
	for _, c := range denied {
		set[c] = true
	}
	return func(network, address string, _ syscall.RawConn) error {
		ip, ok := peerIP(address)
		if !ok {
			return nil
		}
		if got := ClassifyIP(ip); set[got] {
			return fmt.Errorf("authz: refusing to connect to %s: %s address", ip, got)
		}
		return nil
	}
}

// peerIP extracts the resolved address a Dialer.Control hook is handed. The
// address is always host:port for tcp and udp; anything else is left to the
// dialer to reject.
func peerIP(address string) (net.IP, bool) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, false
	}
	return ip, true
}
