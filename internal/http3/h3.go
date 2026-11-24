// Package http3 provides HTTP/3 (QUIC) probing for the Sift scanner.
//
// HTTP/3 support lets Sift measure targets that only speak QUIC/H3,
// and report whether the target advertises H3 via Alt-Svc. This is a passive
// detection layer: it does not perform a full H3 load test, but it tells the
// operator whether H3 is available so they can decide whether to run one.
//
// Production-grade H3 load generation (many concurrent QUIC streams) is a
// follow-up item — see docs/ROADMAP.md.
//
// SCAN PATHS MUST USE ProbeWithGate. The Probe/ProbeWithOptions-without-control
// wrappers and checkAltSvc exist only for tests and lab use: they issue
// uncontrolled dials. No scanning code currently calls any H3 probe; wiring one
// up is a separate feature decision.
package http3

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"

	quic "github.com/quic-go/quic-go"
)

// ProbeResult describes what we learned about a target's HTTP/3 support.
type ProbeResult struct {
	Host        string        `json:"host"`
	Port        int           `json:"port"`
	AltSvcH3    bool          `json:"alt_svc_h3"`   // target advertises h3 in Alt-Svc
	H3Reachable bool          `json:"h3_reachable"` // QUIC handshake succeeded
	H3Latency   time.Duration `json:"h3_latency"`   // QUIC handshake latency
	Negotiated  string        `json:"negotiated"`   // ALPN negotiated (h3 or "")
	Error       string        `json:"error,omitempty"`
}

// ProbeOptions configures a Probe.
type ProbeOptions struct {
	// InsecureSkipVerify disables TLS certificate verification for both the
	// Alt-Svc HTTPS probe and the QUIC handshake. It is off by default: a
	// target presenting an untrusted or self-signed certificate is reported as
	// unreachable rather than silently trusted. Only set it for lab targets you
	// own, where the self-signed certificate is expected.
	InsecureSkipVerify bool

	// DialControl is the runtime-only socket-level authorization hook. It is
	// installed on the Alt-Svc TCP dial and on the UDP socket used for the QUIC
	// handshake so a scan-time decision is re-checked against the address a
	// socket actually reaches. It is also applied to EVERY resolved UDP answer
	// before any socket is dialed.
	//
	// Nil preserves the original uncontrolled dials FOR TESTS/LAB USE ONLY.
	// Scan paths MUST supply a non-nil hook (prefer ProbeWithGate).
	DialControl func(network, address string, c syscall.RawConn) error
}

// Probe checks whether host:port supports HTTP/3 over QUIC with secure TLS
// verification. It is ProbeWithOptions with the zero (secure) options.
//
// TESTS/LAB ONLY — MUST NOT be called on a scan path. There is no authorization
// hook on either the TCP or the UDP dial. Scan paths MUST call ProbeWithGate
// (or ProbeWithOptions with DialControl set from the gate).
//
// It first tries to read the Alt-Svc header over HTTPS (port 443 by default),
// then attempts a QUIC handshake to confirm H3 is actually reachable.
func Probe(host string, port int) (*ProbeResult, error) {
	return ProbeWithOptions(host, port, ProbeOptions{})
}

// ProbeWithGate is the scan-path API: it REQUIRES the gate's socket-level
// authorization hook and returns an error when none is supplied. It delegates
// to ProbeWithOptions with that hook installed, so both the Alt-Svc TCP leg and
// every resolved UDP answer are checked before a socket connects.
//
// Future scan paths MUST use this helper instead of Probe or an uncontrolled
// ProbeWithOptions call. It is not itself wired into the scanner: H3 is still a
// planned feature (docs/ROADMAP.md).
func ProbeWithGate(host string, port int, control func(network, address string, c syscall.RawConn) error, insecure bool) (*ProbeResult, error) {
	if control == nil {
		return nil, errors.New("http3: ProbeWithGate requires a non-nil DialControl; use Probe only in tests/lab")
	}
	return ProbeWithOptions(host, port, ProbeOptions{
		InsecureSkipVerify: insecure,
		DialControl:        control,
	})
}

// ProbeWithOptions is Probe with explicit TLS options. See ProbeOptions.
//
// TESTS/LAB ONLY when opts.DialControl is nil: that path performs uncontrolled
// dials and MUST NOT be called from a scan path. Scan paths MUST call
// ProbeWithGate, or set ProbeOptions.DialControl from the gate themselves.
func ProbeWithOptions(host string, port int, opts ProbeOptions) (*ProbeResult, error) {
	if port == 0 {
		port = 443
	}
	res := &ProbeResult{Host: host, Port: port}

	// 1. Check Alt-Svc via TLS handshake to the standard HTTPS port.
	altSvc, err := checkAltSvcWithControl(host, port, opts.InsecureSkipVerify, opts.DialControl)
	if err == nil {
		res.AltSvcH3 = altSvc
	}

	// 2. Attempt a QUIC handshake to confirm H3 reachability.
	start := time.Now()
	cfg := &quic.Config{
		HandshakeIdleTimeout:  5 * time.Second,
		MaxIdleTimeout:        5 * time.Second,
		KeepAlivePeriod:       0,
		Allow0RTT:             false,
		EnableDatagrams:       false,
		MaxIncomingStreams:    10,
		MaxIncomingUniStreams: 10,
	}
	tlsCfg := quicTLSConfig(host, opts)

	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	var negotiated string
	var quicErr error
	if opts.DialControl == nil {
		negotiated, quicErr = dialQUIC(ctx, addr, tlsCfg, cfg)
	} else {
		negotiated, quicErr = dialQUICWithControl(ctx, addr, tlsCfg, cfg, opts.DialControl)
	}
	res.H3Latency = time.Since(start)
	if quicErr != nil {
		res.H3Reachable = false
		res.Error = quicErr.Error()
	} else {
		res.H3Reachable = true
		res.Negotiated = negotiated
	}

	return res, nil
}

// dialQUIC keeps the original quic-go convenience path for callers without a
// control hook: DialAddr creates the UDP socket itself and closes it with the
// session. Keeping it separate makes the nil-control behavior unchanged.
func dialQUIC(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (string, error) {
	sess, err := quic.DialAddr(ctx, addr, tlsCfg, cfg)
	if err != nil {
		return "", err
	}
	negotiated := sess.ConnectionState().TLS.NegotiatedProtocol
	_ = sess.CloseWithError(0, "probe complete")
	return negotiated, nil
}

// dialQUICWithControl resolves ALL UDP answers for the target and applies the
// authorization hook to every one of them before opening any socket. Only a
// checked literal is dialed, with the Control hook still installed so the
// socket-level decision is re-applied to the address actually connected.
//
// Fail-closed: one refused answer, an empty answer set, or a resolution error
// aborts the probe. This mirrors authz.CheckedDialIPs, but uses "udp" for the
// hook's network and an injectable resolver so scan-time gates that inspect
// the network can be tested without real DNS.
func dialQUICWithControl(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config, control dialControlFunc) (string, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("http3: invalid QUIC target %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return "", fmt.Errorf("http3: invalid QUIC port %q", portStr)
	}

	peers, err := checkedUDPAddrs(ctx, host, port, control)
	if err != nil {
		return "", err
	}
	if len(peers) == 0 {
		return "", fmt.Errorf("http3: no approved UDP addresses for %q", host)
	}

	// Dial the checked literal; dialCheckedQUIC keeps the socket-level hook in
	// place so a resolve/connect race cannot change the address after the gate
	// decided.
	return dialCheckedQUIC(ctx, peers[0], tlsCfg, cfg, control)
}

// quicTLSConfig builds the TLS config for the QUIC handshake. Verification is
// controlled by opts; ServerName is set explicitly so SNI and certificate
// checking use the requested host rather than an empty value.
func quicTLSConfig(host string, opts ProbeOptions) *tls.Config {
	return &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: opts.InsecureSkipVerify, // #nosec G402 -- caller opts in for self-signed lab targets
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"h3"},
	}
}

// Timeouts for the Alt-Svc probe. Without them a silent server would block
// Probe forever: tls.Dial and conn.Read have no deadline by default.
const (
	altSvcDialTimeout = 3 * time.Second
	altSvcReadTimeout = 5 * time.Second
	altSvcMaxHeader   = 64 << 10
)

// hostHeader validates and renders the Host header value for the Alt-Svc GET.
// A raw CR or LF would let a hostile host value inject extra request headers;
// a bare IPv6 literal must be bracketed to be a valid HTTP/1.1 Host.
func hostHeader(host string) (string, error) {
	if host == "" {
		return "", errors.New("http3: empty host")
	}
	if strings.ContainsAny(host, "\r\n") {
		return "", errors.New("http3: host contains CR or LF")
	}
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return "[" + host + "]", nil
	}
	return host, nil
}

// checkAltSvc is the nil-control wrapper kept for existing tests. TESTS/LAB
// ONLY: it has no authorization hook; scan paths must use checkAltSvcWithControl
// with the gate's hook (as ProbeWithGate does).
func checkAltSvc(host string, port int, insecure bool) (bool, error) {
	return checkAltSvcWithControl(host, port, insecure, nil)
}

// checkAltSvcWithControl attempts a TLS handshake and reads the Alt-Svc header
// to see if the server advertises HTTP/3. Returns true if "h3=" or "h3-29="
// appears. insecure must be opted into explicitly; the default verifies the
// certificate. control, when non-nil, is installed on the TCP socket before it
// connects so the gate sees the resolved peer address.
func checkAltSvcWithControl(host string, port int, insecure bool, control func(network, address string, c syscall.RawConn) error) (bool, error) {
	hostHeaderValue, err := hostHeader(host)
	if err != nil {
		return false, err
	}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	dialer := &net.Dialer{Timeout: altSvcDialTimeout, Control: control}
	cfg := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: insecure, // #nosec G402 -- caller opts in for self-signed lab targets
		MinVersion:         tls.VersionTLS12,
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, cfg)
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(altSvcReadTimeout))

	// Alt-Svc is a response header, so we need an HTTP response. Send a minimal
	// GET and read the header block.
	req := "GET / HTTP/1.1\r\nHost: " + hostHeaderValue + "\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return false, err
	}

	br := bufio.NewReader(io.LimitReader(conn, altSvcMaxHeader))
	for {
		line, readErr := br.ReadString('\n')
		if line != "" && isAltSvcH3(line) {
			return true, nil
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return false, nil // headers ended without an H3 advertisement
			}
			return false, readErr
		}
		if line == "\r\n" || line == "\n" {
			return false, nil // end of header block
		}
	}
}

func isAltSvcH3(line string) bool {
	// Alt-Svc: h3=":443"; ma=86400  or  h3-29=":443"; ma=86400
	l := lower(line)
	return contains(l, "alt-svc") && (contains(l, "h3=\"") || contains(l, "h3-29=\""))
}

func lower(s string) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		b = append(b, c)
	}
	return string(b)
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
