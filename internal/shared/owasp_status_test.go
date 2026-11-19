package shared

import "testing"

func TestOWASPStatus(t *testing.T) {
	tests := []struct {
		status   string
		coverage int
		want     string
	}{
		{"PASS", 3, "PASS"},
		{"WARNING", 3, "WARNING"},
		{"FAIL", 3, "FAIL"},
		{"PASS", 0, "NOT TESTED"},
		{"", 3, "NOT TESTED"},
		{"NOT TESTED", 3, "NOT TESTED"},
		{"UNKNOWN", 3, "NOT TESTED"},
	}
	for _, tc := range tests {
		if got := OWASPStatus(tc.status, tc.coverage); got != tc.want {
			t.Errorf("OWASPStatus(%q, %d) = %q, want %q", tc.status, tc.coverage, got, tc.want)
		}
	}
}

func TestOWASPWorstStatus(t *testing.T) {
	tests := []struct{ a, b, want string }{
		{"PASS", "FAIL", "FAIL"},
		{"FAIL", "WARNING", "FAIL"},
		{"WARNING", "PASS", "WARNING"},
		{"PASS", "", "PASS"},
		{"NOT TESTED", "WARNING", "WARNING"},
		{"", "", ""},
	}
	for _, tc := range tests {
		if got := OWASPWorstStatus(tc.a, tc.b); got != tc.want {
			t.Errorf("OWASPWorstStatus(%q, %q) = %q, want %q", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestOWASPStatusRank(t *testing.T) {
	if OWASPStatusRank("FAIL") != 3 || OWASPStatusRank("WARNING") != 2 || OWASPStatusRank("PASS") != 1 {
		t.Error("status ranking is wrong")
	}
	if OWASPStatusRank("") != 0 || OWASPStatusRank("NOT TESTED") != 0 {
		t.Error("no-evidence statuses must carry no severity")
	}
}
