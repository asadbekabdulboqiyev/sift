package http3

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
)

// TestCheckAltSvcWithControlInvokesTCPHook proves the Alt-Svc leg reaches the
// supplied Control with the resolved TCP peer and a real socket.
func TestCheckAltSvcWithControlInvokesTCPHook(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Alt-Svc", `h3=":443"; ma=86400`)
	}))
	defer srv.Close()
	host, port := splitTestAddr(t, srv.Listener.Addr().String())

	var calls atomic.Int64
	var network, address atomic.Value
	var gotRawConn atomic.Bool
	control := func(n, a string, c syscall.RawConn) error {
		calls.Add(1)
		network.Store(n)
		address.Store(a)
		gotRawConn.Store(c != nil)
		return nil
	}

	got, err := checkAltSvcWithControl(host, port, true, control)
	if err != nil {
		t.Fatalf("checkAltSvcWithControl: %v", err)
	}
	if !got {
		t.Fatal("Alt-Svc h3 advertisement was not detected")
	}
	if calls.Load() != 1 {
		t.Fatalf("Control called %d times, want 1", calls.Load())
	}
	if n, _ := network.Load().(string); !strings.HasPrefix(n, "tcp") {
		t.Errorf("Control network = %q, want a tcp network", n)
	}
	wantAddr := net.JoinHostPort(host, strconv.Itoa(port))
	if a, _ := address.Load().(string); a != wantAddr {
		t.Errorf("Control address = %q, want %q", a, wantAddr)
	}
	if !gotRawConn.Load() {
		t.Error("Control received a nil RawConn")
	}
}

// TestCheckAltSvcWithControlDeniesDial proves a refusal reaches the dial, not
// just the callback counter.
func TestCheckAltSvcWithControlDeniesDial(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Alt-Svc", `h3=":443"; ma=86400`)
	}))
	defer srv.Close()
	host, port := splitTestAddr(t, srv.Listener.Addr().String())

	control := func(_, _ string, _ syscall.RawConn) error { return errors.New("blocked by gate") }
	got, err := checkAltSvcWithControl(host, port, true, control)
	if err == nil || got {
		t.Fatalf("blocked dial: got reachable=%v err=%v, want an error", got, err)
	}
}

// TestCheckAltSvcNilControlMatchesLegacy pins the wrapper: passing nil must be
// the same call as the original helper.
func TestCheckAltSvcNilControlMatchesLegacy(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Alt-Svc", `h3=":443"; ma=86400`)
	}))
	defer srv.Close()
	host, port := splitTestAddr(t, srv.Listener.Addr().String())

	want, wantErr := checkAltSvc(host, port, true)
	got, gotErr := checkAltSvcWithControl(host, port, true, nil)
	if want != got || (wantErr == nil) != (gotErr == nil) {
		t.Fatalf("nil control changed result: legacy=(%v,%v), with-control=(%v,%v)", want, wantErr, got, gotErr)
	}
}

// TestProbeWithOptionsNilControlDialsQUIC proves the original quic.DialAddr
// path still works when no control hook is supplied.
func TestProbeWithOptionsNilControlDialsQUIC(t *testing.T) {
	host, port := startTestQUICServer(t)

	res, err := ProbeWithOptions(host, port, ProbeOptions{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("ProbeWithOptions: %v", err)
	}
	if !res.H3Reachable {
		t.Fatalf("nil control made QUIC unreachable: %s", res.Error)
	}
	if res.Negotiated != "h3" {
		t.Errorf("negotiated = %q, want h3", res.Negotiated)
	}
}

// TestProbeWithOptionsControlReachesQUICSocket proves the gate reaches the UDP
// socket quic-go actually uses, with the destination address (not the local
// ephemeral bind address) as the hook's address argument.
func TestProbeWithOptionsControlReachesQUICSocket(t *testing.T) {
	host, port := startTestQUICServer(t)

	var udpCalls, tcpCalls atomic.Int64
	var udpAddress atomic.Value
	var gotRawConn atomic.Bool
	control := func(network, address string, c syscall.RawConn) error {
		switch {
		case strings.HasPrefix(network, "udp"):
			udpCalls.Add(1)
			udpAddress.Store(address)
			gotRawConn.Store(c != nil)
		case strings.HasPrefix(network, "tcp"):
			// The Alt-Svc leg shares the hook; its UDP port has no TCP server.
			tcpCalls.Add(1)
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
		t.Fatalf("controlled QUIC dial failed: %s", res.Error)
	}
	if udpCalls.Load() == 0 {
		t.Fatal("Control was never invoked for the QUIC UDP socket")
	}
	wantAddr := net.JoinHostPort(host, strconv.Itoa(port))
	if a, _ := udpAddress.Load().(string); a != wantAddr {
		t.Errorf("UDP Control address = %q, want %q", a, wantAddr)
	}
	if !gotRawConn.Load() {
		t.Error("UDP Control received a nil RawConn")
	}
	if tcpCalls.Load() == 0 {
		t.Error("Control was not invoked for the Alt-Svc TCP leg")
	}
}

// TestProbeWithOptionsControlDeniesQUIC proves a gate refusal on the UDP
// socket aborts the handshake rather than being ignored.
func TestProbeWithOptionsControlDeniesQUIC(t *testing.T) {
	host, port := startTestQUICServer(t)

	control := func(network, _ string, _ syscall.RawConn) error {
		if strings.HasPrefix(network, "udp") {
			return errors.New("blocked by gate")
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
	if res.H3Reachable {
		t.Fatal("QUIC dial succeeded despite the gate refusing its UDP socket")
	}
	if !strings.Contains(res.Error, "blocked by gate") {
		t.Errorf("error = %q, want the gate refusal", res.Error)
	}
}

func splitTestAddr(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %q: %v", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port %q: %v", portStr, err)
	}
	return host, port
}

// startTestQUICServer starts an in-process IPv4 QUIC listener so the
// controlled dial can be exercised without external network access.
func startTestQUICServer(t *testing.T) (string, int) {
	t.Helper()
	return startTestQUICServerOn(t, "127.0.0.1")
}

// startTestQUICServerOn is startTestQUICServer bound to a specific loopback
// host (e.g. ::1 for the IPv6 socket path).
func startTestQUICServerOn(t *testing.T, host string) (string, int) {
	t.Helper()
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(host), Port: 0})
	if err != nil {
		t.Skipf("%s UDP loopback unavailable: %v", host, err)
	}
	ln, err := quic.Listen(udpConn, testQUICServerTLS(t), nil)
	if err != nil {
		_ = udpConn.Close()
		t.Fatalf("quic.Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
		_ = udpConn.Close()
	})
	go func() {
		for {
			conn, err := ln.Accept(ctx)
			if err != nil {
				return
			}
			go func() { <-conn.Context().Done() }()
		}
	}()
	return splitTestAddr(t, ln.Addr().String())
}

func testQUICServerTLS(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{"h3"},
	}
}
