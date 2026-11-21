// Package tls implements TLS/SSL scanning for the Sift scanner.
package tls

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/scanner/core"
)

// TLSVerifyWarning is the exact warning surfaced in reports when certificate
// verification has been explicitly disabled for an authorized lab.
const TLSVerifyWarning = "TLS verify OFF - authorized lab mode"

// Options configures TLS scans. The zero value is not used directly; callers
// should use DefaultOptions for the secure-by-default configuration.
type Options struct {
	// TLSVerify enables x509 certificate chain and hostname verification.
	// It is ON by default. Disabling it is an explicit, authorized lab opt-out.
	TLSVerify bool
}

// DefaultOptions returns the secure-by-default TLS scan configuration.
func DefaultOptions() Options {
	return Options{TLSVerify: true}
}

// Default is the configuration used by the legacy ScanTLS and
// ScanTLSWithControl entry points. Only set TLSVerify=false in an authorized
// lab where self-signed certificates must be accepted.
var Default = DefaultOptions()

// TLSVerifyEnabled reports the process-wide default. It is deliberately a pure
// read of Default: an explicit per-call opt-out is recorded on that scan's
// result, never here, so it cannot leak into an unrelated scan or report.
//
//nolint:revive // reason: renaming exported identifier would break the public API
func TLSVerifyEnabled() bool {
	return Default.TLSVerify
}

// ScanResult pairs a TLS scan with the verification state used for that one
// call. InsecureTLS is true only when the caller explicitly disabled
// verification; reports use it to emit the lab-mode warning for that scan.
// Keeping it on the result avoids process-wide "sticky" opt-out state.
type ScanResult struct {
	Info        *core.TLSInfo
	InsecureTLS bool
}

// KnownCiphers lists known TLS cipher suites.
var KnownCiphers = map[uint16]core.CipherInfo{
	// TLS 1.3
	0x1301: {Name: "TLS_AES_128_GCM_SHA256", Grade: "A", FS: true, AEAD: true},
	0x1302: {Name: "TLS_AES_256_GCM_SHA384", Grade: "A", FS: true, AEAD: true},
	0x1303: {Name: "TLS_CHACHA20_POLY1305_SHA256", Grade: "A", FS: true, AEAD: true},
	// ECDHE
	0xc02b: {Name: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", Grade: "A", FS: true, AEAD: true},
	0xc02c: {Name: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", Grade: "A", FS: true, AEAD: true},
	0xc02f: {Name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", Grade: "A", FS: true, AEAD: true},
	0xc030: {Name: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", Grade: "A", FS: true, AEAD: true},
	0xcca8: {Name: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305", Grade: "A", FS: true, AEAD: true},
	0xcca9: {Name: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305", Grade: "A", FS: true, AEAD: true},
	// Non-FS (weaker)
	0x009c: {Name: "TLS_RSA_WITH_AES_128_GCM_SHA256", Grade: "B", FS: false, AEAD: true},
	0x009d: {Name: "TLS_RSA_WITH_AES_256_GCM_SHA384", Grade: "B", FS: false, AEAD: true},
	// Insecure
	0x0005: {Name: "TLS_RSA_WITH_RC4_128_SHA", Grade: "F", FS: false, AEAD: false},
	0x000a: {Name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", Grade: "D", FS: false, AEAD: false},
	0x0004: {Name: "TLS_RSA_WITH_RC4_128_MD5", Grade: "F", FS: false, AEAD: false},
	0x0016: {Name: "TLS_RSA_WITH_IDEA_CBC_SHA", Grade: "D", FS: false, AEAD: false},
	0x0013: {Name: "TLS_RSA_WITH_DES_CBC_SHA", Grade: "F", FS: false, AEAD: false},
}

// InsecurePatterns lists insecure cipher name patterns.
var InsecurePatterns = []string{
	"RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon",
}

// ScanTLS performs a full TLS scan on the target host:port using Default.
func ScanTLS(host string, port int) (*core.TLSInfo, error) {
	return ScanTLSWithOptions(host, port, nil, Default)
}

// ScanTLSWithControl is ScanTLS with a dial-time check on every TLS handshake.
// Every dialer used by the scan carries the control, including session-resumption
// retries, so an address the authorization check did not approve cannot be
// reached by any part of the TLS phase.
func ScanTLSWithControl(host string, port int, control func(network, address string, c syscall.RawConn) error) (*core.TLSInfo, error) {
	return ScanTLSWithOptions(host, port, control, Default)
}

// ScanTLSWithOptions is ScanTLSWithControl with an explicit TLS configuration.
// It is the single implementation; the legacy entry points only supply Default.
func ScanTLSWithOptions(host string, port int, control func(network, address string, c syscall.RawConn) error, opts Options) (*core.TLSInfo, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: 5 * time.Second, Control: control}

	info := &core.TLSInfo{
		SupportedVersions: make([]string, 0),
		SupportedCiphers:  make([]core.CipherInfo, 0),
		Vulnerabilities:   make([]string, 0),
	}

	tlsVersions := []struct {
		name string
		min  uint16
		max  uint16
	}{
		{"TLS 1.3", tls.VersionTLS13, tls.VersionTLS13},
		{"TLS 1.2", tls.VersionTLS12, tls.VersionTLS12},
		{"TLS 1.1", tls.VersionTLS11, tls.VersionTLS11},
		{"TLS 1.0", tls.VersionTLS10, tls.VersionTLS10},
	}

	for _, tv := range tlsVersions {
		config := &tls.Config{
			InsecureSkipVerify: !opts.TLSVerify, // #nosec G402 -- only when explicitly disabled for an authorized lab
			MinVersion:         tv.min,
			MaxVersion:         tv.max,
		}

		conn, err := tls.DialWithDialer(dialer, "tcp", addr, config)
		if err != nil {
			continue
		}

		info.SupportedVersions = append(info.SupportedVersions, tv.name)

		if len(info.SupportedVersions) == 1 {
			state := conn.ConnectionState()
			info.Version = tv.name

			if state.CipherSuite != 0 {
				cipher := KnownCiphers[state.CipherSuite]
				if cipher.Name == "" {
					cipher = core.CipherInfo{
						Name:  fmt.Sprintf("UNKNOWN_%d", state.CipherSuite),
						ID:    state.CipherSuite,
						Grade: "B",
					}
				}
				info.CipherSuite = cipher.Name
				info.CipherSuiteID = state.CipherSuite
				info.ForwardSecrecy = cipher.FS

				info.IsSecure = true
				for _, p := range InsecurePatterns {
					if strings.Contains(strings.ToUpper(cipher.Name), p) {
						info.IsSecure = false
						info.Vulnerabilities = append(info.Vulnerabilities, fmt.Sprintf("Insecure cipher: %s", cipher.Name))
						break
					}
				}
			}

			if len(state.PeerCertificates) > 0 {
				certInfo := extractCertInfo(state.PeerCertificates[0])
				info.Certificate = &certInfo
				for _, cert := range state.PeerCertificates {
					ci := extractCertInfo(cert)
					info.CertificateChain = append(info.CertificateChain, ci)
				}
			}

			info.HTTP2Supported = state.NegotiatedProtocol == "h2"
		}

		_ = conn.Close()
	}

	// Session resumption check: only report true when the handshake actually
	// resumed a previous session/ticket, not merely when a second connect succeeds.
	resumeCfg := &tls.Config{
		InsecureSkipVerify: !opts.TLSVerify, // #nosec G402 -- only when explicitly disabled for an authorized lab
		ClientSessionCache: tls.NewLRUClientSessionCache(1),
	}
	conn1, err := tls.DialWithDialer(dialer, "tcp", addr, resumeCfg)
	if err == nil {
		_ = conn1.Close()
		conn2, err := tls.DialWithDialer(dialer, "tcp", addr, resumeCfg)
		if err == nil {
			info.SessionResumption = conn2.ConnectionState().DidResume
			_ = conn2.Close()
		}
	}

	return info, nil
}

// ScanTLSWithOptionsResult is ScanTLSWithOptions plus the verification state
// of that one call. Use it when the caller needs to report whether an
// authorized lab opt-out was used; unlike a package flag, the state cannot
// affect any other scan.
func ScanTLSWithOptionsResult(host string, port int, control func(network, address string, c syscall.RawConn) error, opts Options) (*ScanResult, error) {
	info, err := ScanTLSWithOptions(host, port, control, opts)
	if err != nil {
		return nil, err
	}
	return &ScanResult{Info: info, InsecureTLS: !opts.TLSVerify}, nil
}

func extractCertInfo(cert *x509.Certificate) core.CertInfo {
	info := core.CertInfo{
		Subject:      cert.Subject.CommonName,
		Issuer:       cert.Issuer.CommonName,
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		IsExpired:    time.Now().After(cert.NotAfter),
		SerialNumber: cert.SerialNumber.String(),
		SANs:         cert.DNSNames,
		SignatureAlg: cert.SignatureAlgorithm.String(),
	}

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		info.KeyType = "RSA"
		info.KeySize = pub.N.BitLen()
	case *ecdsa.PublicKey:
		info.KeyType = "ECDSA"
		info.KeySize = pub.Curve.Params().BitSize
	default:
		info.KeyType = "Unknown"
	}

	info.IsSelfSigned = cert.Issuer.CommonName == cert.Subject.CommonName

	return info
}
