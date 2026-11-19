package scanner

import (
	"syscall"
	"testing"

	scannertls "github.com/asadbekabdulboqiyev/sift/internal/scanner/tls"
)

// TestScanWithControlWithOptionsRecordsTLSVerifyState pins that an authorized
// per-call TLS opt-out is visible on the top-level scan result. Without it a
// caller cannot tell whether certificate verification was disabled for this
// scan, which is exactly the false-warning bug B8 removed from global state.
func TestScanWithControlWithOptionsRecordsTLSVerifyState(t *testing.T) {
	control := func(_ string, _ string, _ syscall.RawConn) error { return nil }

	lab, err := ScanWithControlWithOptions("127.0.0.1", 1, control, scannertls.Options{TLSVerify: false})
	if err != nil {
		t.Fatalf("lab scan: %v", err)
	}
	if !lab.InsecureTLS {
		t.Fatal("opt-out scan: InsecureTLS = false, want true")
	}

	safe, err := ScanWithControlWithOptions("127.0.0.1", 1, control, scannertls.DefaultOptions())
	if err != nil {
		t.Fatalf("secure scan: %v", err)
	}
	if safe.InsecureTLS {
		t.Fatal("secure scan: InsecureTLS = true, want false")
	}
}
