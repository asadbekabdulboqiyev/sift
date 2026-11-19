package dashboard

// UI-6: the OWASP handler bound the checker's separate dial path to the
// Guard's dial-time check, but the pentest handler did not. The two handlers
// now share one binding helper so the protection cannot drift apart again.

import (
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/authz"
	"github.com/asadbekabdulboqiyev/sift/internal/scanner"
)

func TestBoundOWASPCheckerCarriesTheDialControl(t *testing.T) {
	control := authz.DialControl(authz.ClassPublic)
	gate, err := scanner.NewGuard(scanner.GuardConfig{
		AllowAll:    true,
		Timeout:     time.Second,
		DialControl: control,
	})
	if err != nil {
		t.Fatalf("NewGuard: %v", err)
	}

	checker := newBoundOWASPChecker("http://127.0.0.1:1/", gate)
	if checker.DialControl == nil {
		t.Fatal("bound checker has no dial control")
	}
	if checker.Requester == nil {
		t.Fatal("bound checker has no requester")
	}

	// The checker's own dial path must refuse an address the approval does
	// not cover — the same decision the Guard applies to HTTP requests.
	if err := checker.DialControl("tcp", "127.0.0.1:1", nil); err == nil {
		t.Fatal("checker dial control allowed a loopback address under a public approval")
	}

	// A Guard without a hook must leave the checker unchanged.
	plain, err := scanner.NewGuard(scanner.GuardConfig{AllowAll: true, Timeout: time.Second})
	if err != nil {
		t.Fatalf("NewGuard: %v", err)
	}
	if got := newBoundOWASPChecker("http://example.com/", plain).DialControl; got != nil {
		t.Fatal("checker installed a dial control the Guard did not have")
	}
}
