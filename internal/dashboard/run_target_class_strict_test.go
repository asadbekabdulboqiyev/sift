package dashboard

import (
	"strings"
	"testing"

	"github.com/asadbekabdulboqiyev/sift/internal/authz"
)

// TestRunTargetClassStrictLiteralPublicIP proves the strict classifier still
// resolves DNS-free literal addresses without an error.
func TestRunTargetClassStrictLiteralPublicIP(t *testing.T) {
	class, err := RunTargetClassStrict("http://93.184.216.34/")
	if err != nil {
		t.Fatalf("RunTargetClassStrict(public IP) error = %v, want nil", err)
	}
	if class != authz.ClassPublic {
		t.Fatalf("RunTargetClassStrict(public IP) = %v, want %v", class, authz.ClassPublic)
	}
}

// TestRunTargetClassStrictClassificationFailure proves a target that cannot be
// classified is reported as an error, not silently turned into a public class.
func TestRunTargetClassStrictClassificationFailure(t *testing.T) {
	// .invalid is reserved by RFC 2606 and must never resolve.
	targets := []string{
		"http://sift-unresolvable-target.invalid/",
		"",
	}
	for _, target := range targets {
		t.Run(target, func(t *testing.T) {
			class, err := RunTargetClassStrict(target)
			if err == nil {
				t.Fatalf("RunTargetClassStrict(%q) error = nil, want a classification failure", target)
			}
			if !strings.Contains(err.Error(), "classify run target") {
				t.Errorf("RunTargetClassStrict(%q) error = %q, want wrapped context", target, err.Error())
			}
			// The class is meaningless on error; callers must refuse the run.
			if class != authz.ClassPublic {
				t.Errorf("RunTargetClassStrict(%q) class = %v, want %v on error", target, class, authz.ClassPublic)
			}
		})
	}
}

// TestRunTargetClassStrictPreservesRestrictiveClasses keeps the metadata and
// link-local decisions intact while making the error case explicit.
func TestRunTargetClassStrictPreservesRestrictiveClasses(t *testing.T) {
	cases := []struct {
		target string
		want   authz.Class
	}{
		{"http://169.254.169.254/latest/meta-data/", authz.ClassMetadata},
		{"http://[fe80::1]/", authz.ClassLinkLocal},
		{"http://127.0.0.1:8080/", authz.ClassLoopback},
	}
	for _, tc := range cases {
		t.Run(tc.target, func(t *testing.T) {
			got, err := RunTargetClassStrict(tc.target)
			if err != nil {
				t.Fatalf("RunTargetClassStrict(%q) error = %v, want nil", tc.target, err)
			}
			if got != tc.want {
				t.Fatalf("RunTargetClassStrict(%q) = %v, want %v", tc.target, got, tc.want)
			}
		})
	}
}

// TestRunTargetClassLegacyFallback pins the backwards-compatible wrapper: it
// keeps the historical ClassPublic fallback, while launchers use the strict
// API above.
func TestRunTargetClassLegacyFallback(t *testing.T) {
	if got := RunTargetClass("http://sift-unresolvable-target.invalid/"); got != authz.ClassPublic {
		t.Fatalf("RunTargetClass(unresolvable) = %v, want %v", got, authz.ClassPublic)
	}
}
