package http3

import (
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"testing"
	"time"
)

func TestCheckAltSvcAdvertisesH3(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", `h3=":443"; ma=86400`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	got, err := checkAltSvc(host, port, true) // httptest uses a self-signed cert
	if err != nil {
		t.Fatalf("checkAltSvc: %v", err)
	}
	if !got {
		t.Error("server with Alt-Svc h3= must be detected as H3-capable")
	}
}

func TestCheckAltSvcNoH3(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()

	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	got, err := checkAltSvc(host, port, true) // httptest uses a self-signed cert
	if err != nil {
		t.Fatalf("checkAltSvc: %v", err)
	}
	if got {
		t.Error("server without Alt-Svc must not be flagged")
	}
}

func TestCheckAltSvcUnreachable(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := lis.Addr().String()
	lis.Close()

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	got, err := checkAltSvc(host, port, false)
	if err == nil || got {
		t.Fatalf("unreachable target must produce an error, got reachable=%v err=%v", got, err)
	}
}

func TestProbeUnreachableTarget(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := lis.Addr().String()
	lis.Close()

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	res, err := Probe(host, port)
	if err != nil {
		t.Fatalf("Probe must not error on an unreachable target: %v", err)
	}
	if res.H3Reachable {
		t.Error("H3 must not be reachable on a closed port")
	}
	if res.Error == "" {
		t.Error("expected an error message on the probe result")
	}
}

// TestCheckAltSvcVerifiesCertificateByDefault is the CWE-295 fix: a self-signed
// target is no longer trusted silently. The same target is readable only when
// the caller explicitly opts in.
func TestCheckAltSvcVerifiesCertificateByDefault(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Alt-Svc", `h3=":443"; ma=86400`)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	got, err := checkAltSvc(host, port, false)
	if err == nil || got {
		t.Fatalf("self-signed target with secure defaults: got reachable=%v err=%v, want a verification error", got, err)
	}

	got, err = checkAltSvc(host, port, true)
	if err != nil || !got {
		t.Fatalf("self-signed target with InsecureSkipVerify: got reachable=%v err=%v, want detected", got, err)
	}
}

// TestQUICTLSConfigVerificationDefaultsSecure covers the QUIC half of the fix
// without needing a live QUIC server: the config must verify certificates by
// default, send the requested host as SNI, and opt in only when asked.
func TestQUICTLSConfigVerificationDefaultsSecure(t *testing.T) {
	secure := quicTLSConfig("example.com", ProbeOptions{})
	if secure.InsecureSkipVerify {
		t.Error("QUIC probe skipped certificate verification by default")
	}
	if secure.ServerName != "example.com" {
		t.Errorf("ServerName = %q, want example.com", secure.ServerName)
	}
	if !slices.Equal(secure.NextProtos, []string{"h3"}) {
		t.Errorf("NextProtos = %v, want [h3]", secure.NextProtos)
	}

	insecure := quicTLSConfig("example.com", ProbeOptions{InsecureSkipVerify: true})
	if !insecure.InsecureSkipVerify {
		t.Error("explicit InsecureSkipVerify was ignored")
	}
}

// --- Host header hardening (audit §5.6) -------------------------------------

func TestHostHeader(t *testing.T) {
	cases := []struct {
		name    string
		host    string
		want    string
		wantErr bool
	}{
		{"ipv6 literal is bracketed", "::1", "[::1]", false},
		{"full ipv6 literal is bracketed", "2001:db8::1", "[2001:db8::1]", false},
		{"ipv4 literal stays bare", "127.0.0.1", "127.0.0.1", false},
		{"dns name stays bare", "example.com", "example.com", false},
		{"empty host", "", "", true},
		{"crlf injection", "example.com\r\nX-Evil: 1", "", true},
		{"lf injection", "example.com\nX-Evil: 1", "", true},
		{"bare cr", "example.com\rX", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := hostHeader(tc.host)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("hostHeader(%q) = %q, want an error", tc.host, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("hostHeader(%q): %v", tc.host, err)
			}
			if got != tc.want {
				t.Errorf("hostHeader(%q) = %q, want %q", tc.host, got, tc.want)
			}
		})
	}
}

// TestCheckAltSvcRejectsUnsafeHost verifies validation happens before any dial.
func TestCheckAltSvcRejectsUnsafeHost(t *testing.T) {
	for _, host := range []string{"", "example.com\r\nHost: evil.example", "example.com\nX-Evil: 1"} {
		t.Run(strconv.Quote(host), func(t *testing.T) {
			got, err := checkAltSvc(host, 443, true)
			if err == nil {
				t.Fatal("checkAltSvc must reject an unsafe host before dialing")
			}
			if got {
				t.Error("checkAltSvc must not report H3 for an unsafe host")
			}
		})
	}
}

// TestCheckAltSvcIPv6HostHeader checks the value that actually reaches the wire.
// It skips on machines without an IPv6 loopback listener.
func TestCheckAltSvcIPv6HostHeader(t *testing.T) {
	lis, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}

	hosts := make(chan string, 1)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case hosts <- r.Host:
		default:
		}
		w.Header().Set("Alt-Svc", `h3=":443"; ma=86400`)
		w.WriteHeader(http.StatusOK)
	}))
	_ = srv.Listener.Close()
	srv.Listener = lis
	srv.StartTLS()
	defer srv.Close()

	_, portStr, err := net.SplitHostPort(lis.Addr().String())
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	got, err := checkAltSvc("::1", port, true)
	if err != nil {
		t.Fatalf("checkAltSvc: %v", err)
	}
	if !got {
		t.Error("expected the h3 Alt-Svc advertisement to be detected")
	}
	select {
	case host := <-hosts:
		if host != "[::1]" {
			t.Errorf("request Host = %q, want [::1]", host)
		}
	case <-time.After(time.Second):
		t.Fatal("the probe never reached the server")
	}
}
