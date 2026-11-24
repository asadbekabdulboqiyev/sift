package main

import (
	"testing"

	"github.com/asadbekabdulboqiyev/sift/internal/authz"
)

// TestApprovedDashDialClassRefusesClassificationFailure verifies the in-process
// dashboard launcher refuses a run whose target cannot be classified (reserved
// .invalid TLD), instead of installing a dial control from a public fallback.
func TestApprovedDashDialClassRefusesClassificationFailure(t *testing.T) {
	class, err := approvedDashDialClass("http://sift-unresolvable-target.invalid/")
	if err == nil {
		t.Fatal("approvedDashDialClass(unresolvable) error = nil, want classification failure")
	}
	if class != authz.ClassPublic {
		t.Errorf("approvedDashDialClass(unresolvable) class = %v, want %v on error", class, authz.ClassPublic)
	}
}

// TestApprovedDashDialClassAcceptsLiteralPublicIP keeps ordinary public load
// tests working through the strict launcher seam.
func TestApprovedDashDialClassAcceptsLiteralPublicIP(t *testing.T) {
	class, err := approvedDashDialClass("http://93.184.216.34/")
	if err != nil {
		t.Fatalf("approvedDashDialClass(public IP) error = %v, want nil", err)
	}
	if class != authz.ClassPublic {
		t.Fatalf("approvedDashDialClass(public IP) = %v, want %v", class, authz.ClassPublic)
	}
}
