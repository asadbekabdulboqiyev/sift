package scanner

// --- SSL/TLS analyzer --------------------------------------------------------
//
// Inspects a target's TLS configuration: certificate validity, issuer,
// SANs, expired/not-yet-valid dates, weak ciphers (via utls if available),
// and protocol version support. stdlib-only for the core scan; utls is used
// opportunistically when present.

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"
)

// SSLVerifyWarning is the exact warning surfaced in reports when certificate
// verification has been explicitly disabled for an authorized lab.
const SSLVerifyWarning = "TLS verify OFF - authorized lab mode"

// SSLOptions configures SSL/TLS scans. Use SSLDefaultOptions for the
// secure-by-default configuration.
type SSLOptions struct {
	// TLSVerify enables x509 certificate chain and hostname verification.
	// It is ON by default. Disabling it is an explicit, authorized lab opt-out.
	TLSVerify bool
}

// SSLDefaultOptions returns the secure-by-default SSL scan configuration.
func SSLDefaultOptions() SSLOptions {
	return SSLOptions{TLSVerify: true}
}

// SSLDefault is the configuration used by the legacy ScanSSL and
// ScanSSLWithControl entry points. Only set TLSVerify=false in an authorized
// lab where self-signed certificates must be accepted.
var SSLDefault = SSLDefaultOptions()

// SSLVerifyEnabled reports the process-wide default. It is deliberately a pure
// read of SSLDefault: a per-call opt-out is recorded on that scan's result, so
// it cannot leak into an unrelated scan or report.
func SSLVerifyEnabled() bool {
	return SSLDefault.TLSVerify
}

// sslLabOptOut holds at most one target-scoped lab opt-out. It is a one-shot
// registration: the first SSL scan for the matching target consumes it and
// clears it. SSLDefault is never touched, so verification stays ON for every
// later scan and report.
var sslLabOptOut = struct {
	sync.Mutex
	target string
}{}

// AllowInsecureSSLForTarget opts out of certificate verification for the next
// SSL scan of target. target may be a URL (https://host:port) or a host[:port]
// string; both are normalized to host:port. The registration is consumed by
// that single scan, cannot be reused, and never changes SSLDefault. It exists
// for authorized lab tests against self-signed endpoints that must complete a
// handshake and expose the peer certificate.
func AllowInsecureSSLForTarget(target string) {
	key := normalizeSSLTarget(target)
	sslLabOptOut.Lock()
	sslLabOptOut.target = key
	sslLabOptOut.Unlock()
}

// consumeInsecureSSLForTarget reports and clears a matching one-shot opt-out.
func consumeInsecureSSLForTarget(target string) bool {
	key := normalizeSSLTarget(target)
	sslLabOptOut.Lock()
	defer sslLabOptOut.Unlock()
	if sslLabOptOut.target != "" && sslLabOptOut.target == key {
		sslLabOptOut.target = ""
		return true
	}
	return false
}

// normalizeSSLTarget renders a URL or host[:port] as the host:port form SSL
// scans dial. It keeps the lab opt-out key identical to the handler's target.
func normalizeSSLTarget(target string) string {
	if strings.Contains(target, "://") {
		if u, err := url.Parse(target); err == nil {
			port := u.Port()
			if port == "" {
				port = "443"
				if u.Scheme == "http" {
					port = "80"
				}
			}
			return net.JoinHostPort(u.Hostname(), port)
		}
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return net.JoinHostPort(target, "443")
	}
	return net.JoinHostPort(host, port)
}

// SSLResult is the output of an SSL/TLS scan.
type SSLResult struct {
	Target    string        `json:"target"`
	Valid     bool          `json:"valid"`
	Issuer    string        `json:"issuer,omitempty"`
	Subject   string        `json:"subject,omitempty"`
	NotBefore string        `json:"not_before,omitempty"`
	NotAfter  string        `json:"not_after,omitempty"`
	Expired   bool          `json:"expired"`
	SANs      []string      `json:"sans,omitempty"`
	Cipher    string        `json:"cipher,omitempty"`
	Version   string        `json:"version,omitempty"`
	Issues    []string      `json:"issues,omitempty"`
	Duration  time.Duration `json:"duration"`

	// InsecureTLS is true only when this scan explicitly disabled certificate
	// verification. Reports use it to emit the lab-mode warning for this scan.
	InsecureTLS bool `json:"insecure_tls,omitempty"`
}

// ScanSSL performs a TLS handshake against host:port (default 443) and
// reports certificate and configuration weaknesses using SSLDefault.
func ScanSSL(ctx context.Context, target string) *SSLResult {
	return ScanSSLWithOptions(ctx, target, nil, SSLDefault)
}

// ScanSSLWithControl is ScanSSL with a dial-time check installed on the
// connection. control runs with the peer address already resolved, so a caller
// can refuse an address the authorization decision did not approve; nil behaves
// exactly like ScanSSL.
func ScanSSLWithControl(ctx context.Context, target string, control func(network, address string, c syscall.RawConn) error) *SSLResult {
	return ScanSSLWithOptions(ctx, target, control, SSLDefault)
}

// ScanSSLWithOptions is ScanSSLWithControl with an explicit SSL configuration.
// It is the single implementation; the legacy entry points only supply SSLDefault.
func ScanSSLWithOptions(ctx context.Context, target string, control func(network, address string, c syscall.RawConn) error, opts SSLOptions) *SSLResult {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		host = target
		port = "443"
	}

	// A target-scoped one-shot lab opt-out is consumed here and recorded on this
	// result only. SSLDefault is untouched, so later scans stay verified.
	insecure := !opts.TLSVerify || consumeInsecureSSLForTarget(net.JoinHostPort(host, port))
	res := &SSLResult{Target: target, InsecureTLS: insecure}
	start := time.Now()

	dialer := &net.Dialer{Timeout: 5 * time.Second, Control: control}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		res.Issues = append(res.Issues, fmt.Sprintf("cannot connect: %v", err))
		res.Duration = time.Since(start)
		return res
	}
	defer func() { _ = conn.Close() }()

	config := &tls.Config{
		InsecureSkipVerify: insecure, // #nosec G402 -- only for this scan's explicit authorized-lab opt-out
		ServerName:         host,
		MinVersion:         tls.VersionTLS10,
	}
	tconn := tls.Client(conn, config)
	if err := tconn.Handshake(); err != nil {
		res.Issues = append(res.Issues, fmt.Sprintf("tls handshake failed: %v", err))
		res.Duration = time.Since(start)
		return res
	}
	defer func() { _ = tconn.Close() }()

	state := tconn.ConnectionState()
	res.Version = tlsVersionName(state.Version)
	res.Cipher = tls.CipherSuiteName(state.CipherSuite)

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		res.Issuer = cert.Issuer.CommonName
		res.Subject = cert.Subject.CommonName
		res.NotBefore = cert.NotBefore.Format("2006-01-02")
		res.NotAfter = cert.NotAfter.Format("2006-01-02")
		now := time.Now()
		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			res.Expired = true
			res.Issues = append(res.Issues, "certificate is not valid now")
		}
		res.SANs = append(res.SANs, cert.DNSNames...)
		for _, ip := range cert.IPAddresses {
			res.SANs = append(res.SANs, ip.String())
		}
		res.Valid = state.HandshakeComplete && !res.Expired
	} else {
		res.Issues = append(res.Issues, "no peer certificates presented")
	}

	// Weak cipher / protocol flags.
	if strings.Contains(res.Version, "SSL") || strings.Contains(res.Version, "1.0") || strings.Contains(res.Version, "1.1") {
		res.Issues = append(res.Issues, "weak TLS protocol ("+res.Version+")")
	}

	res.Duration = time.Since(start)
	return res
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%x", v)
	}
}
