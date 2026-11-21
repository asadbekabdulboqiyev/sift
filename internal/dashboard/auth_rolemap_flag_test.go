package dashboard

import (
	"reflect"
	"testing"
)

// TestParseOIDCRoleMap proves the CLI flag parser builds the same
// claim-to-role allowlist both dashboard entry points feed to AuthOptions.
// Raw OIDC claim values are never role names; only the operator's explicit
// mapping may cross that boundary.
func TestParseOIDCRoleMap(t *testing.T) {
	tests := []struct {
		name    string
		entries []string
		want    map[string]string
	}{
		{
			name:    "empty flag yields nil map (fail closed)",
			entries: nil,
			want:    nil,
		},
		{
			name:    "single mapping",
			entries: []string{"analyst=viewer"},
			want:    map[string]string{"analyst": "viewer"},
		},
		{
			name:    "multiple mappings and whitespace trimming",
			entries: []string{" analyst = viewer ", "ops=operator"},
			want:    map[string]string{"analyst": "viewer", "ops": "operator"},
		},
		{
			name:    "last occurrence of a claim wins",
			entries: []string{"role=viewer", "role=operator"},
			want:    map[string]string{"role": "operator"},
		},
		{
			name:    "malformed and blank entries skipped",
			entries: []string{"no-equals", "=role", "claim=", "  ", "good=viewer"},
			want:    map[string]string{"good": "viewer"},
		},
		{
			name:    "value may contain equals (split on first only)",
			entries: []string{"team=a=b"},
			want:    map[string]string{"team": "a=b"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseOIDCRoleMap(tc.entries)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ParseOIDCRoleMap(%q) = %v, want %v", tc.entries, got, tc.want)
			}
		})
	}
}
