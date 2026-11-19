package shared

import "testing"

func TestIsLoopbackHost(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"localhost", true},
		{"LOCALHOST", true},
		{"[::1]", true},
		{"::1", true},
		{"127.0.0.1", true},
		{"127.42.0.9", true},
		{"example.com", false},
		{"", false},
		{"[::1]:8080", false}, // callers pass a host, not an address
	}
	for _, tc := range tests {
		if got := IsLoopbackHost(tc.host); got != tc.want {
			t.Errorf("IsLoopbackHost(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}
