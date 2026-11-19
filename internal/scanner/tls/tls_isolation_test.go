package tls

// Regression coverage for the B8 TLS opt-out isolation fix. A per-call opt-out
// must be recorded on that scan's result only; it must never set sticky package
// state that leaks into later scans or reports.

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func TestTLSVerifyOptOutIsIsolated(t *testing.T) {
	if !TLSVerifyEnabled() {
		t.Fatal("TLSVerifyEnabled() = false at start, want the secure default true")
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	addr := srv.URL[len("https://"):]
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	// Opt out for this one call only.
	lab, err := ScanTLSWithOptionsResult(host, port, nil, Options{TLSVerify: false})
	if err != nil {
		t.Fatalf("opt-out scan: %v", err)
	}
	if lab == nil || lab.Info == nil {
		t.Fatal("opt-out scan returned no result")
	}
	if !lab.InsecureTLS {
		t.Fatal("opt-out scan result InsecureTLS = false, want true")
	}
	if len(lab.Info.SupportedVersions) == 0 {
		t.Fatal("opt-out scan did not complete a TLS handshake")
	}

	// The opt-out must not change the process-wide default. With the old sticky
	// atomic flag this assertion failed: TLSVerifyEnabled() stayed false forever.
	if !TLSVerifyEnabled() {
		t.Fatal("per-call opt-out leaked into the package default")
	}

	// A following default scan carries no opt-out state of its own.
	def, err := ScanTLSWithOptionsResult(host, port, nil, DefaultOptions())
	if err != nil {
		t.Fatalf("default scan: %v", err)
	}
	if def == nil {
		t.Fatal("default scan returned no result")
	}
	if def.InsecureTLS {
		t.Fatal("default scan inherited the earlier opt-out")
	}
	if !TLSVerifyEnabled() {
		t.Fatal("default scan changed the package default")
	}
}
