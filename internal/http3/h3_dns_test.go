package http3

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	quic "github.com/quic-go/quic-go"
)

// withQUICSeams installs test-only resolver/dial seams and restores them after
// the test. Tests using it MUST NOT call t.Parallel.
func withQUICSeams(t *testing.T, lookup lookupIPAddrFunc, dial quicDialFunc) {
	t.Helper()
	oldLookup, oldDial := lookupIPAddrs, dialCheckedQUIC
	lookupIPAddrs, dialCheckedQUIC = lookup, dial
	t.Cleanup(func() {
		lookupIPAddrs, dialCheckedQUIC = oldLookup, oldDial
	})
}

// TestDialQUICWithControlChecksEveryDNSAnswer is the §9.5 residual regression:
// a name with several UDP answers must have EVERY answer checked before any
// socket is dialed. The blocked answer is last so an early-return
// implementation would be caught by the seen list.
func TestDialQUICWithControlChecksEveryDNSAnswer(t *testing.T) {
	answers := []net.IPAddr{
		{IP: net.ParseIP("93.184.216.34")},
		{IP: net.ParseIP("2001:db8::1")},
		{IP: net.ParseIP("169.254.169.254")}, // metadata: blocked by the gate
	}
	var seen []string
	lookup := func(_ context.Context, host string) ([]net.IPAddr, error) {
		if host != "multi.example" {
			t.Errorf("resolver host = %q, want multi.example", host)
		}
		return answers, nil
	}
	control := func(network, address string, _ syscall.RawConn) error {
		seen = append(seen, network+"|"+address)
		if strings.HasPrefix(address, "169.254.169.254:") {
			return errors.New("blocked by gate")
		}
		return nil
	}
	dialCalls := 0
	dial := func(_ context.Context, _ *net.UDPAddr, _ *tls.Config, _ *quic.Config, _ dialControlFunc) (string, error) {
		dialCalls++
		return "", errors.New("socket dial must not be attempted")
	}
	withQUICSeams(t, lookup, dial)

	_, err := dialQUICWithControl(context.Background(), "multi.example:443", &tls.Config{}, &quic.Config{}, control)
	if err == nil {
		t.Fatal("a blocked DNS answer did not refuse the QUIC dial")
	}
	if !strings.Contains(err.Error(), "blocked by gate") {
		t.Errorf("error = %q, want the gate refusal", err)
	}
	if dialCalls != 0 {
		t.Errorf("socket dial called %d time(s), want 0", dialCalls)
	}
	wantSeen := []string{
		"udp|93.184.216.34:443",
		"udp|[2001:db8::1]:443",
		"udp|169.254.169.254:443",
	}
	if !slices.Equal(seen, wantSeen) {
		t.Errorf("checked answers = %v, want %v", seen, wantSeen)
	}
}

// TestDialQUICWithControlNoApprovedAddresses covers empty answers, resolution
// failures, and every answer refused: all must error without a socket dial.
func TestDialQUICWithControlNoApprovedAddresses(t *testing.T) {
	tests := []struct {
		name         string
		answers      []net.IPAddr
		lookupErr    error
		blockAll     bool
		wantErrPart  string
		wantControls int
	}{
		{name: "zero answers", wantErrPart: "resolved to no addresses"},
		{name: "resolution failure", lookupErr: errors.New("resolver offline"), wantErrPart: "resolver offline"},
		{
			name: "all answers blocked",
			answers: []net.IPAddr{
				{IP: net.ParseIP("10.0.0.1")},
				{IP: net.ParseIP("10.0.0.2")},
			},
			blockAll:     true,
			wantErrPart:  "refusing QUIC dial",
			wantControls: 2, // the whole answer set is checked before failing
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lookup := func(_ context.Context, _ string) ([]net.IPAddr, error) {
				return tc.answers, tc.lookupErr
			}
			controlCalls := 0
			control := func(_, _ string, _ syscall.RawConn) error {
				controlCalls++
				if tc.blockAll {
					return errors.New("blocked by gate")
				}
				return nil
			}
			dialCalls := 0
			dial := func(_ context.Context, _ *net.UDPAddr, _ *tls.Config, _ *quic.Config, _ dialControlFunc) (string, error) {
				dialCalls++
				return "", errors.New("socket dial must not be attempted")
			}
			withQUICSeams(t, lookup, dial)

			_, err := dialQUICWithControl(context.Background(), "none.example:443", &tls.Config{}, &quic.Config{}, control)
			if err == nil {
				t.Fatal("expected an error with no approved addresses")
			}
			if !strings.Contains(err.Error(), tc.wantErrPart) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantErrPart)
			}
			if controlCalls != tc.wantControls {
				t.Errorf("hook called %d time(s), want %d", controlCalls, tc.wantControls)
			}
			if dialCalls != 0 {
				t.Errorf("socket dial called %d time(s), want 0", dialCalls)
			}
		})
	}
}

// TestDialQUICWithControlDialsCheckedLiteral proves IPv4 and IPv6 literals
// bypass DNS but still pass the gate, and that a checked literal from a
// hostname's answer set is what reaches the socket dial with the hook intact.
func TestDialQUICWithControlDialsCheckedLiteral(t *testing.T) {
	tests := []struct {
		name        string
		host        string
		wantLookup  int
		wantChecked []string
		wantPeer    string
	}{
		{
			name:        "ipv4 literal",
			host:        "127.0.0.1",
			wantChecked: []string{"udp|127.0.0.1:8443"},
			wantPeer:    "127.0.0.1:8443",
		},
		{
			name:        "ipv6 literal",
			host:        "::1",
			wantChecked: []string{"udp|[::1]:8443"},
			wantPeer:    "[::1]:8443",
		},
		{
			// The gate gets a parseable IP; the dial keeps the zone.
			name:        "ipv6 literal with zone",
			host:        "fe80::1%lo0",
			wantChecked: []string{"udp|[fe80::1]:8443"},
			wantPeer:    "[fe80::1%lo0]:8443",
		},
		{
			name:       "hostname with mixed answers",
			host:       "mixed.example",
			wantLookup: 1,
			wantChecked: []string{
				"udp|93.184.216.34:8443",
				"udp|[2001:db8::2]:8443",
			},
			wantPeer: "93.184.216.34:8443",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lookupCalls := 0
			lookup := func(_ context.Context, _ string) ([]net.IPAddr, error) {
				lookupCalls++
				return []net.IPAddr{
					{IP: net.ParseIP("93.184.216.34")},
					{IP: net.ParseIP("2001:db8::2")},
				}, nil
			}
			var seen []string
			control := func(network, address string, _ syscall.RawConn) error {
				seen = append(seen, network+"|"+address)
				return nil
			}
			dialCalls := 0
			dial := func(_ context.Context, peer *net.UDPAddr, _ *tls.Config, _ *quic.Config, hook dialControlFunc) (string, error) {
				dialCalls++
				if hook == nil {
					t.Error("socket dial lost the Control hook")
				}
				if peer.String() != tc.wantPeer {
					t.Errorf("dial peer = %q, want %q", peer.String(), tc.wantPeer)
				}
				return "h3", nil
			}
			withQUICSeams(t, lookup, dial)

			got, err := dialQUICWithControl(context.Background(), net.JoinHostPort(tc.host, "8443"), &tls.Config{}, &quic.Config{}, control)
			if err != nil {
				t.Fatalf("dialQUICWithControl: %v", err)
			}
			if got != "h3" {
				t.Errorf("negotiated = %q, want h3", got)
			}
			if lookupCalls != tc.wantLookup {
				t.Errorf("resolver called %d time(s), want %d", lookupCalls, tc.wantLookup)
			}
			if !slices.Equal(seen, tc.wantChecked) {
				t.Errorf("checked addresses = %v, want %v", seen, tc.wantChecked)
			}
			if dialCalls != 1 {
				t.Errorf("socket dial called %d time(s), want 1", dialCalls)
			}
		})
	}
}

// TestProbeWithOptionsIPv6LiteralControl exercises the real socket path for an
// IPv6 peer: the Control-installed PacketConn must be bound to an IPv6 wildcard
// or quic-go cannot reach ::1.
func TestProbeWithOptionsIPv6LiteralControl(t *testing.T) {
	host, port := startTestQUICServerOn(t, "::1")

	var udpAddress atomic.Value
	control := func(network, address string, _ syscall.RawConn) error {
		if strings.HasPrefix(network, "udp") {
			udpAddress.Store(address)
		}
		return nil
	}

	res, err := ProbeWithOptions(host, port, ProbeOptions{
		InsecureSkipVerify: true,
		DialControl:        control,
	})
	if err != nil {
		t.Fatalf("ProbeWithOptions: %v", err)
	}
	if !res.H3Reachable {
		t.Fatalf("controlled IPv6 QUIC dial failed: %s", res.Error)
	}
	want := net.JoinHostPort("::1", strconv.Itoa(port))
	if got, _ := udpAddress.Load().(string); got != want {
		t.Errorf("UDP Control address = %q, want %q", got, want)
	}
}

// TestProbeWithGateRequiresControl pins the misuse-resistant API: no hook, no
// probe.
func TestProbeWithGateRequiresControl(t *testing.T) {
	res, err := ProbeWithGate("127.0.0.1", 443, nil, true)
	if err == nil {
		t.Fatal("ProbeWithGate accepted a nil control")
	}
	if res != nil {
		t.Errorf("result = %+v, want nil on a rejected call", res)
	}
	if !strings.Contains(err.Error(), "non-nil DialControl") {
		t.Errorf("error = %q, want the missing-control explanation", err)
	}
}

// TestProbeWithGateDelegatesToOptions proves the safe wrapper installs the
// supplied hook on both the Alt-Svc TCP leg and the QUIC UDP socket.
func TestProbeWithGateDelegatesToOptions(t *testing.T) {
	host, port := startTestQUICServer(t)

	var tcpCalls, udpCalls atomic.Int64
	control := func(network, _ string, _ syscall.RawConn) error {
		switch {
		case strings.HasPrefix(network, "tcp"):
			tcpCalls.Add(1)
		case strings.HasPrefix(network, "udp"):
			udpCalls.Add(1)
		}
		return nil
	}

	res, err := ProbeWithGate(host, port, control, true)
	if err != nil {
		t.Fatalf("ProbeWithGate: %v", err)
	}
	if !res.H3Reachable {
		t.Fatalf("QUIC unreachable through ProbeWithGate: %s", res.Error)
	}
	if tcpCalls.Load() == 0 {
		t.Error("control never reached the Alt-Svc TCP leg")
	}
	if udpCalls.Load() == 0 {
		t.Error("control never reached the QUIC UDP dial")
	}
}
