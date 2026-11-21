package shared

import "testing"

func TestSeverityRank(t *testing.T) {
	tests := []struct {
		in   string
		want int
	}{
		{"critical", 4},
		{"HIGH", 3},
		{" warning ", 2}, // audit scorer folds warning into medium
		{"fail", 3},      // ...and fail into high
		{"low", 1},
		{"info", 0},
		{"nonsense", 0},
	}
	for _, tc := range tests {
		if got := SeverityRank(tc.in); got != tc.want {
			t.Errorf("SeverityRank(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestFindingSortKey(t *testing.T) {
	tests := []struct {
		in   string
		want int
	}{
		{"critical", 0},
		{"INFO", 4},
		{"low", 3},
		{"medium", 2},
		{"high", 1},
		{"unknown", 4},
	}
	for _, tc := range tests {
		if got := FindingSortKey(tc.in); got != tc.want {
			t.Errorf("FindingSortKey(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestAlertSortKey(t *testing.T) {
	// Host x-ray's vocabulary is critical / warning / info. The relative order
	// must stay critical < warning < info even though the scale differs from
	// FindingSortKey.
	if AlertSortKey("critical") >= AlertSortKey("warning") || AlertSortKey("warning") >= AlertSortKey("info") {
		t.Error("alert severity ordering is wrong")
	}
}
