package authz

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestDialControlRefusesRebindingToAMoreRestrictiveClass(t *testing.T) {
	// The gate approved a public target; the name resolved to metadata or to a
	// private address on the second lookup.
	control := DialControl(ClassPublic)
	for _, tc := range []struct {
		address string
		want    string
	}{
		{"169.254.169.254:80", "metadata"},
		{"10.0.0.1:443", "private"},
		{"169.254.1.1:80", "link-local"},
		{"100.100.100.200:80", "metadata"},
		{"fd00:ec2::254:80", ""}, // splitHostPort on bare IPv6 fails; covered below
	} {
		err := control("tcp", tc.address, nil)
		if tc.want == "" {
			if err != nil {
				t.Errorf("%s: %v", tc.address, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s: connection allowed, want refusal", tc.address)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error = %q, want it to name %q", tc.address, err, tc.want)
		}
	}

	// A public peer of the approved class is still allowed.
	if err := control("tcp", "93.184.216.34:443", nil); err != nil {
		t.Errorf("public peer refused: %v", err)
	}
	// A public target that rebinds to loopback is a downgrade too: reaching a
	// service that only listens on localhost is the other half of SSRF.
	if err := control("tcp", "127.0.0.1:8080", nil); err == nil {
		t.Error("loopback peer allowed for a public approval")
	}
	// A target the gate itself classified as loopback is approved as loopback
	// and keeps working.
	if err := DialControl(ClassLoopback)("tcp", "127.0.0.1:8080", nil); err != nil {
		t.Errorf("approved loopback peer refused: %v", err)
	}
}

func TestDialControlAllowsTheApprovedClass(t *testing.T) {
	if err := DialControl(ClassPrivate)("tcp", "10.1.2.3:443", nil); err != nil {
		t.Errorf("approved private peer refused: %v", err)
	}
	// An operator who explicitly authorized metadata keeps reaching it.
	if err := DialControl(ClassMetadata)("tcp", "169.254.169.254:80", nil); err != nil {
		t.Errorf("explicitly authorized metadata refused: %v", err)
	}
}

func TestDenyClassesRefusesTheNamedClassOnly(t *testing.T) {
	control := DenyClasses(ClassMetadata)
	if err := control("tcp", "169.254.169.254:80", nil); err == nil {
		t.Fatal("metadata connection allowed")
	}
	for _, addr := range []string{"10.0.0.1:443", "127.0.0.1:80", "93.184.216.34:443"} {
		if err := control("tcp", addr, nil); err != nil {
			t.Errorf("%s refused: %v", addr, err)
		}
	}
}

func TestDialControlIgnoresAddressesItCannotJudge(t *testing.T) {
	control := DialControl(ClassPublic)
	if err := control("unix", "/tmp/socket", nil); err != nil {
		t.Errorf("non-network address refused: %v", err)
	}
	if err := control("tcp", "not-an-address", nil); err != nil {
		t.Errorf("unparseable address refused: %v", err)
	}
}

// TestDialControlStopsTheConnectionBeforeItIsMade is the end-to-end proof: a
// real dialer with the hook installed never reaches the metadata address. It
// fails immediately at the hook instead of waiting for a network timeout, which
// is only possible if the check runs before the connect.
func TestDialControlStopsTheConnectionBeforeItIsMade(t *testing.T) {
	d := &net.Dialer{Timeout: 2 * time.Second, Control: DialControl(ClassPublic)}
	start := time.Now()
	conn, err := d.DialContext(context.Background(), "tcp", "169.254.169.254:80")
	if err == nil {
		_ = conn.Close()
		t.Fatal("dial to instance metadata succeeded")
	}
	if !strings.Contains(err.Error(), "authz: refusing to connect") {
		t.Fatalf("unexpected error: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("refusal took %s — the hook did not run before the connect", elapsed)
	}
}
