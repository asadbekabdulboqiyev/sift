package coordinator

// register_address.go — the worker self-registration address gate.
//
// Register is reachable by any client that can reach the control-plane port.
// Before this gate, a caller could submit any Address and the master would
// later dial it, Ping it and stream the scenario (with its bearer token) to
// whatever answered. Applying the scanner's address classes here means an
// unauthenticated Register cannot turn the master into a reachability oracle
// or a bridge into internal infrastructure.

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"syscall"

	"github.com/asadbekabdulboqiyev/sift/internal/authz"
)

// workerAddressPolicy is deliberately separate from the auth gate: a token or
// a pinned key authenticates WHO registers, this decides WHERE the master is
// allowed to dial. Both must pass.
type workerAddressPolicy struct {
	allowPrivate bool
}

func (m *Master) addressPolicy() workerAddressPolicy {
	return workerAddressPolicy{allowPrivate: m.cfg.AllowPrivateWorkers}
}

// check requires a strict host:port, then rejects every address class the
// scan gate refuses. A hostname is resolved through authz.CheckDialTarget so
// ALL answers must pass; checking only the first would let DNS rotation pick a
// blocked address at connect time.
func (p workerAddressPolicy) check(ctx context.Context, addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("worker address %q must be host:port: %w", addr, err)
	}
	if host == "" {
		return fmt.Errorf("worker address %q has an empty host", addr)
	}
	if port == "" {
		return fmt.Errorf("worker address %q has no port", addr)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("worker address %q has an invalid port %q", addr, port)
	}

	if ip := net.ParseIP(host); ip != nil {
		if err := p.checkClass(authz.ClassifyIP(ip)); err != nil {
			return fmt.Errorf("worker address %q rejected: %w", addr, err)
		}
		return nil
	}
	if err := authz.CheckDialTarget(ctx, host, port, p.dialControl()); err != nil {
		return fmt.Errorf("worker address %q rejected: %w", addr, err)
	}
	return nil
}

func (p workerAddressPolicy) checkClass(class authz.Class) error {
	switch class {
	case authz.ClassPublic:
		return nil
	case authz.ClassPrivate, authz.ClassLoopback:
		if p.allowPrivate {
			return nil
		}
		// Operators with workers inside their own network must opt in
		// explicitly; the default must never dial RFC1918 or loopback because
		// an anonymous caller asked it to.
		return fmt.Errorf("%s address is refused by default (pass --allow-private-workers to allow it)", class)
	default:
		// Metadata, link-local, CGNAT, multicast and reserved space are not
		// valid worker endpoints even with the private-address opt-in.
		return fmt.Errorf("%s address is never allowed for worker registration", class)
	}
}

// dialControl reuses the scanner's hooks so the registration check and the
// connect check classify an address identically. DialControl(ClassPrivate)
// also permits loopback, which is the less restrictive class and is covered
// by the same operator opt-in.
func (p workerAddressPolicy) dialControl() func(network, address string, c syscall.RawConn) error {
	approved := authz.ClassPublic
	if p.allowPrivate {
		approved = authz.ClassPrivate
	}
	gate := authz.DialControl(approved)
	never := authz.DenyClasses(
		authz.ClassCGNAT,
		authz.ClassLinkLocal,
		authz.ClassMulticast,
		authz.ClassReserved,
		authz.ClassMetadata,
	)
	return func(network, address string, c syscall.RawConn) error {
		if err := never(network, address, c); err != nil {
			return err
		}
		return gate(network, address, c)
	}
}

// gatedDialWorker repeats the policy check at connect time. A registration is
// only a snapshot: DNS can answer differently later and a re-registration can
// race run assembly. Static --workers addresses are operator-configured and
// deliberately keep the plain dialer (see Master.Connect).
func (m *Master) gatedDialWorker(ctx context.Context, addr string) (net.Conn, error) {
	checkCtx, cancel := context.WithTimeout(ctx, dialAttemptTimeout)
	defer cancel()
	if err := m.addressPolicy().check(checkCtx, addr); err != nil {
		return nil, fmt.Errorf("coordinator: refusing worker dial: %w", err)
	}
	return dialWorker(ctx, addr)
}
