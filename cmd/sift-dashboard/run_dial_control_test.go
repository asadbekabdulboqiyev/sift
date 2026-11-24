package main

import (
	"testing"

	"github.com/asadbekabdulboqiyev/sift/internal/authz"
)

// TestApprovedRunDialClassRefusesClassificationFailure verifies the launcher's
// refusal seam: an unresolvable target (reserved .invalid TLD) must return an
// error so startRun aborts before installing a fallback-class dial control.
func TestApprovedRunDialClassRefusesClassificationFailure(t *testing.T) {
	class, err := approvedRunDialClass("http://sift-unresolvable-target.invalid/")
	if err == nil {
		t.Fatal("approvedRunDialClass(unresolvable) error = nil, want classification failure")
	}
	if class != authz.ClassPublic {
		t.Errorf("approvedRunDialClass(unresolvable) class = %v, want %v on error", class, authz.ClassPublic)
	}
}

// TestApprovedRunDialClassAcceptsLiteralPublicIP keeps ordinary public load
// tests working through the strict launcher seam.
func TestApprovedRunDialClassAcceptsLiteralPublicIP(t *testing.T) {
	class, err := approvedRunDialClass("http://93.184.216.34/")
	if err != nil {
		t.Fatalf("approvedRunDialClass(public IP) error = %v, want nil", err)
	}
	if class != authz.ClassPublic {
		t.Fatalf("approvedRunDialClass(public IP) = %v, want %v", class, authz.ClassPublic)
	}
}
