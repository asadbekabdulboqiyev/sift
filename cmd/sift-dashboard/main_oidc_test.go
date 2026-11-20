package main

import "testing"

// TestParseOIDCPairs pins the issuer:client_id parsing used by the standalone
// dashboard, including URL issuers with ports. It must stay identical to the
// rule in `sift run --dashboard` (cmd/sift.dashboardAuthOptions).
func TestParseOIDCPairs(t *testing.T) {
	cases := []struct {
		name     string
		entries  []string
		issuer   string
		clientID string
	}{
		{name: "empty"},
		{
			name:     "plain issuer:client",
			entries:  []string{"issuer.example.com:client-a"},
			issuer:   "issuer.example.com",
			clientID: "client-a",
		},
		{
			name:     "url issuer with port splits on last colon",
			entries:  []string{"https://issuer.example.com:8443:client-b"},
			issuer:   "https://issuer.example.com:8443",
			clientID: "client-b",
		},
		{
			name:    "malformed entries skipped",
			entries: []string{"no-colon", ":missing-issuer", "missing-client:"},
		},
		{
			name:     "last valid pair wins",
			entries:  []string{"issuer-a:client-a", "malformed", "issuer-b:client-b"},
			issuer:   "issuer-b",
			clientID: "client-b",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			issuer, clientID := parseOIDCPairs(tc.entries)
			if issuer != tc.issuer || clientID != tc.clientID {
				t.Errorf("parseOIDCPairs(%q) = (%q, %q), want (%q, %q)",
					tc.entries, issuer, clientID, tc.issuer, tc.clientID)
			}
		})
	}
}
