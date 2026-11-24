// h3_dns.go — fail-closed DNS handling for controlled QUIC dials.
//
// A name can resolve to several UDP addresses. Checking only the first answer
// (or letting the dialer re-resolve the name) leaves a rebinding gap: the
// socket may reach an address the gate never approved. Every answer is checked
// here, then one checked literal is dialed with the socket hook still active.
package http3

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"

	quic "github.com/quic-go/quic-go"
)

// dialControlFunc is the net.Dialer.Control / net.ListenConfig.Control shape
// used by the gate. Alias (not a distinct type) so existing hook signatures
// and ProbeOptions.DialControl remain assignable unchanged.
type dialControlFunc = func(network, address string, c syscall.RawConn) error

type lookupIPAddrFunc func(ctx context.Context, host string) ([]net.IPAddr, error)

type quicDialFunc func(ctx context.Context, peer *net.UDPAddr, tlsCfg *tls.Config, cfg *quic.Config, control dialControlFunc) (string, error)

// Test seams. Production uses the standard resolver and the real socket dial;
// tests replace them to prove every DNS answer is checked before a dial.
// Tests touching these MUST NOT run in parallel.
var (
	lookupIPAddrs   lookupIPAddrFunc = net.DefaultResolver.LookupIPAddr
	dialCheckedQUIC quicDialFunc     = dialQUICWithControlSocket
)

// checkedUDPAddrs resolves host to UDP peers and runs control over EVERY
// answer. It is the UDP counterpart of authz.CheckedDialIPs: fail-closed on an
// empty answer set, a resolution error, an invalid address, or any refusal.
// The hook receives a nil RawConn here because no socket exists yet; the real
// RawConn is supplied by dialQUICWithControlSocket at connect time.
func checkedUDPAddrs(ctx context.Context, host string, port int, control dialControlFunc) ([]*net.UDPAddr, error) {
	if control == nil {
		return nil, errors.New("http3: DialControl is nil; QUIC dial cannot be authorized")
	}
	if host == "" {
		return nil, errors.New("http3: empty QUIC target host")
	}

	check := func(peer *net.UDPAddr) error {
		if peer.IP == nil || peer.IP.To16() == nil {
			return fmt.Errorf("http3: invalid UDP answer for %q", host)
		}
		if err := control("udp", gateAddress(peer), nil); err != nil {
			return fmt.Errorf("http3: refusing QUIC dial to %s: %w", gateAddress(peer), err)
		}
		return nil
	}

	// Pre-resolved literals (v4, v6, and v6 with a zone) skip DNS entirely but
	// still go through the gate.
	if literal, ok := literalUDPAddr(host, port); ok {
		if err := check(literal); err != nil {
			return nil, err
		}
		return []*net.UDPAddr{literal}, nil
	}

	if ctx == nil {
		ctx = context.Background()
	}
	answers, err := lookupIPAddrs(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("http3: cannot resolve QUIC target %q: %w", host, err)
	}
	if len(answers) == 0 {
		return nil, fmt.Errorf("http3: QUIC target %q resolved to no addresses", host)
	}

	// Check the whole answer set even after a refusal, then fail closed: a
	// dialer is free to pick any answer, so checking only a subset would leave
	// a rebinding gap. No socket is opened until every answer has passed.
	peers := make([]*net.UDPAddr, 0, len(answers))
	var refused error
	for _, answer := range answers {
		peer := &net.UDPAddr{IP: answer.IP, Port: port, Zone: answer.Zone}
		if err := check(peer); err != nil {
			if refused == nil {
				refused = err
			}
			continue
		}
		peers = append(peers, peer)
	}
	if refused != nil {
		return nil, refused
	}
	return peers, nil
}

// gateAddress renders a peer as host:port for the authorization hook. The zone
// is omitted because gate hooks parse the host with net.ParseIP, which rejects
// a zone suffix; the zone stays on the UDPAddr used for the real dial.
func gateAddress(peer *net.UDPAddr) string {
	return net.JoinHostPort(peer.IP.String(), strconv.Itoa(peer.Port))
}

// literalUDPAddr reports whether host is already an IP literal and, if so,
// returns its literal UDP address without consulting DNS.
func literalUDPAddr(host string, port int) (*net.UDPAddr, bool) {
	if ip := net.ParseIP(host); ip != nil {
		return &net.UDPAddr{IP: ip, Port: port}, true
	}
	// IPv6 link-local literals may carry a zone: fe80::1%en0.
	if i := strings.LastIndexByte(host, '%'); i > 0 {
		if ip := net.ParseIP(host[:i]); ip != nil {
			return &net.UDPAddr{IP: ip, Zone: host[i+1:], Port: port}, true
		}
	}
	return nil, false
}

// dialQUICWithControlSocket hands quic-go a UDP socket created with a Control
// hook. In quic-go v0.59.1 DialAddr opens its own socket and offers no control
// option; Dial is a method on Transport (there is no Transport.Dial field), so
// the controlled net.PacketConn is installed through Transport.Conn.
//
// peer MUST already have passed checkedUDPAddrs. The wildcard bind follows the
// peer's family: binding only 0.0.0.0 would make IPv6 answers unreachable.
func dialQUICWithControlSocket(ctx context.Context, peer *net.UDPAddr, tlsCfg *tls.Config, cfg *quic.Config, control dialControlFunc) (string, error) {
	// ListenConfig passes the LOCAL address to Control. The gate contract
	// expects the peer, so hand it the checked literal while still using the
	// real socket's RawConn.
	lc := net.ListenConfig{Control: func(network, _ string, c syscall.RawConn) error {
		return control(network, gateAddress(peer), c)
	}}
	local := "0.0.0.0:0"
	if peer.IP.To4() == nil {
		local = "[::]:0"
	}
	pc, err := lc.ListenPacket(ctx, "udp", local)
	if err != nil {
		return "", err
	}
	udpConn, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		return "", errors.New("http3: UDP listen did not return a *net.UDPConn")
	}
	tr := &quic.Transport{Conn: udpConn}
	// quic-go does not own a PacketConn created outside the library, so the
	// socket and the transport must both be released here (on dial errors too).
	defer func() {
		_ = tr.Close()
		_ = udpConn.Close()
	}()
	sess, err := tr.Dial(ctx, peer, tlsCfg, cfg)
	if err != nil {
		return "", err
	}
	negotiated := sess.ConnectionState().TLS.NegotiatedProtocol
	_ = sess.CloseWithError(0, "probe complete")
	return negotiated, nil
}
