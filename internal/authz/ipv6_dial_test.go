package authz

// QA-1: the IPv6 AWS metadata address was listed in the test table in a form
// net.SplitHostPort cannot parse ("fd00:ec2::254:80") with a comment claiming
// it was "covered below". Nothing below covered it, so the dial-time refusal
// for IPv6 metadata was never exercised. Check the real, bracketed form here.

import (
	"net"
	"strings"
	"testing"
)

func TestDialControlRefusesIPv6MetadataRebind(t *testing.T) {
	if got := ClassifyIP(net.ParseIP("fd00:ec2::254")); got != ClassMetadata {
		t.Fatalf("ClassifyIP(fd00:ec2::254) = %v, want metadata", got)
	}

	control := DialControl(ClassPublic)
	for _, address := range []string{
		"[fd00:ec2::254]:80",
		"[fd00:ec2::254]:443",
	} {
		err := control("tcp", address, nil)
		if err == nil {
			t.Errorf("%s: connection allowed under a public approval", address)
			continue
		}
		if !strings.Contains(err.Error(), "metadata") {
			t.Errorf("%s: error = %q, want it to name metadata", address, err)
		}
	}

	// An operator who explicitly authorized this address keeps it working.
	if err := DialControl(ClassMetadata)("tcp", "[fd00:ec2::254]:80", nil); err != nil {
		t.Errorf("approved metadata peer refused: %v", err)
	}

	// A malformed bare IPv6 address stays outside the hook's judgement; the
	// dialer itself rejects it. Pin that behaviour so the table entry above
	// cannot be mistaken for coverage.
	if err := control("tcp", "fd00:ec2::254:80", nil); err != nil {
		t.Errorf("unparsable address was judged by the hook: %v", err)
	}
}
