package dashboard

import (
	"testing"

	"github.com/asadbekabdulboqiyev/sift/internal/shared"
)

// The browser path and the pentest CLI must apply the same coverage-honesty
// rule. Both delegate to internal/shared; these assertions catch a regression
// where one of them grows a local copy again.
func TestOWASPStatusUsesSharedRule(t *testing.T) {
	for _, status := range []string{"PASS", "WARNING", "FAIL", "NOT TESTED", "", "UNEXPECTED"} {
		for _, coverage := range []int{0, 1, 5} {
			got := owaspStatus(status, coverage)
			want := shared.OWASPStatus(status, coverage)
			if got != want {
				t.Errorf("owaspStatus(%q, %d) = %q, shared = %q", status, coverage, got, want)
			}
		}
	}
}

func TestOWASPWorstStatusUsesSharedRule(t *testing.T) {
	for _, pair := range [][2]string{{"PASS", "FAIL"}, {"FAIL", "PASS"}, {"WARNING", "NOT TESTED"}} {
		got := owaspWorstStatus(pair[0], pair[1])
		want := shared.OWASPWorstStatus(pair[0], pair[1])
		if got != want {
			t.Errorf("owaspWorstStatus(%q, %q) = %q, shared = %q", pair[0], pair[1], got, want)
		}
	}
}
