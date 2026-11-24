package authz

import (
	"fmt"
	"net"
	"syscall"
)

// neverApprovedClasses are network classes that no authorization rule and no
// admin unlock may put on a replay socket. Link-local holds every cloud
// instance-metadata address as well as the 169.254.0.0/16 block; metadata is
// listed separately so the refusal names the credential-theft path explicitly.
var neverApprovedClasses = [...]Class{
	ClassMetadata,
	ClassCGNAT,
	ClassLinkLocal,
	ClassMulticast,
	ClassReserved,
}

// ApprovedPeers is the destination set a socket may connect to. IPs are exact
// addresses resolved when the gate ran; Nets are optional CIDR blocks for
// callers that approved a range rather than a list of addresses.
//
// Keeping both in one value matters for replay: the gate approves a target
// (host + resolved IPs), but the socket is handed a possibly different address
// after a second DNS resolution. Only an address inside this set may pass.
type ApprovedPeers struct {
	IPs  []net.IP
	Nets []*net.IPNet
}

// Control returns a net.Dialer.Control hook enforcing the approved set.
//
// Three rules, in this order:
//
//  1. a peer whose address cannot be parsed is refused (fail closed);
//  2. a peer in a never-approved class is refused unconditionally;
//  3. a peer outside the approved set is refused, even if its class is public.
//
// Rule 3 is deliberate: allowing "anything public" would let a name approved
// at gate time rebind to a different public host and exfiltrate captured
// Authorization/Cookie headers there. Rebinding to loopback, RFC1918 space or
// metadata is covered by rules 1 and 2.
func (a ApprovedPeers) Control() func(network, address string, c syscall.RawConn) error {
	ips := append([]net.IP(nil), a.IPs...)
	nets := append([]*net.IPNet(nil), a.Nets...)
	return func(_, address string, _ syscall.RawConn) error {
		ip, ok := peerIP(address)
		if !ok {
			return fmt.Errorf("authz: refusing to connect to %q: cannot determine the socket peer", address)
		}
		class := ClassifyIP(ip)
		for _, denied := range neverApprovedClasses {
			if class == denied {
				return fmt.Errorf("authz: refusing to connect to %s: %s addresses are never approved", ip, denied)
			}
		}
		for _, approved := range ips {
			if approved.Equal(ip) {
				return nil
			}
		}
		for _, block := range nets {
			if block != nil && block.Contains(ip) {
				return nil
			}
		}
		return fmt.Errorf("authz: refusing to connect to %s: peer is not in the approved destination set", ip)
	}
}

// ApprovedPeersControl is the exact-IP form of ApprovedPeers.Control. It is the
// hook installed by the replay CLI from the gate's approved IP list.
func ApprovedPeersControl(approved ...net.IP) func(network, address string, c syscall.RawConn) error {
	return ApprovedPeers{IPs: approved}.Control()
}
