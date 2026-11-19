package scanner

// Regression coverage for the isolated, target-scoped SSL lab opt-out used by
// dashboard tests against self-signed endpoints. The opt-out is one-shot and
// must never change SSLDefault or leak into a later scan.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSSLTargetOptOutIsOneShotAndIsolated(t *testing.T) {
	if !SSLVerifyEnabled() {
		t.Fatal("SSLVerifyEnabled() = false at start, want the secure default true")
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	hostPort := strings.TrimPrefix(srv.URL, "https://")

	// Register with the URL form (what a dashboard test has at hand); the scan
	// dials host:port, and both forms must normalize to the same key.
	AllowInsecureSSLForTarget(srv.URL)

	first := ScanSSLWithOptions(context.Background(), hostPort, nil, SSLDefaultOptions())
	if !first.InsecureTLS {
		t.Fatal("first scan InsecureTLS = false, want true")
	}
	if first.Cipher == "" || first.Version == "" {
		t.Fatalf("first scan did not complete a handshake: issues=%v", first.Issues)
	}
	if len(first.SANs) == 0 {
		t.Fatalf("first scan returned no certificate SANs: %+v", first)
	}
	if !SSLVerifyEnabled() {
		t.Fatal("target-scoped opt-out changed the package default")
	}

	// The same target scanned again is verified: the opt-out was consumed once.
	second := ScanSSLWithOptions(context.Background(), hostPort, nil, SSLDefaultOptions())
	if second.InsecureTLS {
		t.Fatal("one-shot opt-out leaked into the next scan")
	}
	if second.Cipher != "" {
		t.Fatalf("verified scan against a self-signed endpoint unexpectedly completed: %+v", second)
	}
	if !SSLVerifyEnabled() {
		t.Fatal("second scan changed the package default")
	}
}
