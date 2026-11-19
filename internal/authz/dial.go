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
	"context"
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

// CheckDialTarget applies a DialControl-style hook to a target host directly.
//
// With an HTTP proxy configured, the socket-level hook sees the PROXY address,
// never the destination: a name that resolves to a public IP at gate time can
// rebind to metadata or RFC1918 space and the dial hook cannot see it. Callers
// that dial through a proxy must therefore resolve the destination themselves
// and pass every resolved address through the same authorization hook.
//
// Fail-closed: an empty host/port, a resolution error, an empty answer, or any
// resolved address the hook refuses all produce an error. A caller that ignores
// this error is a caller that did not check.
func CheckDialTarget(ctx context.Context, host, port string, control func(network, address string, c syscall.RawConn) error) error {
	if control == nil {
		return nil
	}
	if host == "" || port == "" {
		return fmt.Errorf("authz: cannot check dial target with empty host or port")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	check := func(ip net.IP) error {
		if err := control("tcp", net.JoinHostPort(ip.String(), port), nil); err != nil {
			return fmt.Errorf("authz: refusing proxy dial to target %s: %w", ip, err)
		}
		return nil
	}

	if literal := net.ParseIP(host); literal != nil {
		return check(literal)
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("authz: cannot resolve proxy dial target %q: %w", host, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("authz: proxy dial target %q resolved to no addresses", host)
	}
	// Every answer is checked: the dialer is free to pick any of them, so one
	// restricted address is enough to refuse the request.
	for _, ip := range ips {
		if err := check(ip.IP); err != nil {
			return err
		}
	}
	return nil
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
