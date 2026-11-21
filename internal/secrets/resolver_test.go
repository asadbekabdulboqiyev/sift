package secrets

import "testing"

// TestResolveEnvReferences pins the package-level Resolve wrapper against the
// environment-expansion contract. Each case runs as its own subtest with
// process-local variables installed through t.Setenv, so the environment is
// restored automatically and the cases are order-independent (no global
// os.Setenv pollution that could leak into other tests in this package).
func TestResolveEnvReferences(t *testing.T) {
	const (
		setVar   = "SIFT_QA_RESOLVE_SET"
		emptyVar = "SIFT_QA_RESOLVE_EMPTY"
	)
	// Arrange: install process-local variables for the whole group. t.Setenv
	// forbids t.Parallel and restores the previous values when the test ends.
	t.Setenv(setVar, "hello")
	t.Setenv(emptyVar, "")

	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "set variable",
			in:   "${" + setVar + "}",
			want: "hello",
		},
		{
			name: "set variable embedded in a path",
			in:   "${" + setVar + "}/world",
			want: "hello/world",
		},
		{
			name: "unset variable uses default",
			in:   "${SIFT_QA_RESOLVE_MISSING:-fallback}",
			want: "fallback",
		},
		{
			name: "empty variable uses default",
			in:   "${" + emptyVar + ":-fallback}",
			want: "fallback",
		},
		{
			name: "set variable wins over default",
			in:   "${" + setVar + ":-fallback}",
			want: "hello",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			got := Resolve(tc.in)

			// Assert
			if got != tc.want {
				t.Fatalf("Resolve(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
