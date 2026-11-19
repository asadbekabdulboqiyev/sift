package main

// SEC-A360-01 regression coverage at the CLI boundary. The dial-control chain
// ranks classes strictly:
//
//	public(0) < loopback(1) < private(2) < cgnat(3) < link-local(4) <
//	reserved(5) < multicast(6) < metadata(7)
//
// A peer exactly one rank above the approved class must be refused; the
// approved class and everything below it must still pass. Reordering any two
// classes in authz.Class.severity breaks one of these adjacent pairs.

import (
	"net"
	"strings"
	"testing"

	"github.com/asadbekabdulboqiyev/sift/internal/authz"
)

func dialChainClasses() []struct {
	name    string
	class   authz.Class
	address string
} {
	return []struct {
		name    string
		class   authz.Class
		address string
	}{
		{name: "public", class: authz.ClassPublic, address: "93.184.216.34:443"},
		{name: "loopback", class: authz.ClassLoopback, address: "127.0.0.1:8080"},
		{name: "private", class: authz.ClassPrivate, address: "10.1.2.3:443"},
		{name: "cgnat", class: authz.ClassCGNAT, address: "100.64.0.1:443"},
		{name: "link-local", class: authz.ClassLinkLocal, address: "169.254.1.1:443"},
		{name: "reserved", class: authz.ClassReserved, address: "0.0.0.0:443"},
		{name: "multicast", class: authz.ClassMulticast, address: "224.0.0.1:443"},
		{name: "metadata", class: authz.ClassMetadata, address: "169.254.169.254:80"},
	}
}

func TestDialControlClassSeverityChain(t *testing.T) {
	steps := dialChainClasses()

	// Arrange check: each representative address must really classify as the
	// class it stands for, otherwise the chain test would assert against the
	// wrong inputs.
	for _, step := range steps {
		host, _, err := net.SplitHostPort(step.address)
		if err != nil {
			t.Fatalf("split %q: %v", step.address, err)
		}
		if got := authz.ClassifyIP(net.ParseIP(host)); got != step.class {
			t.Fatalf("ClassifyIP(%s) = %s, want %s", host, got, step.class)
		}
	}

	// Act and assert, one adjacent pair at a time.
	for i, approved := range steps {
		control := authz.DialControl(approved.class)
		for j := 0; j <= i; j++ {
			if err := control("tcp", steps[j].address, nil); err != nil {
				t.Errorf("approval %s refused %s: %v", approved.name, steps[j].name, err)
			}
		}
		if i+1 < len(steps) {
			next := steps[i+1]
			if err := control("tcp", next.address, nil); err == nil {
				t.Errorf("approval %s allowed more restrictive peer %s", approved.name, next.name)
			}
		}
	}
}

func TestDialControlPublicApprovalRefusesMetadataAndNamesTheClass(t *testing.T) {
	// Arrange.
	control := authz.DialControl(authz.ClassPublic)

	// Act.
	err := control("tcp", "169.254.169.254:80", nil)

	// Assert: the credential-theft destination must be refused, and the error
	// must name the class so the operator can see why the dial was blocked.
	if err == nil {
		t.Fatal("public approval allowed a dial to instance metadata")
	}
	if !strings.Contains(err.Error(), "metadata") {
		t.Fatalf("refusal error = %q, want it to name metadata", err)
	}
}
