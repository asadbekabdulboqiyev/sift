package secrets

import "testing"

// Compile-time guard: the environment-backed resolver must remain usable
// wherever the package exposes only the Resolver interface.
var _ Resolver = EnvResolver{}

// TestEnvResolverResolveTable pins the ${VAR} and ${VAR:-default} expansion
// rules with process-local environment variables. t.Setenv restores the
// environment after each subtest, so the cases are order-independent.
func TestEnvResolverResolveTable(t *testing.T) {
	const (
		setVar     = "SIFT_QA_SECRET_SET"
		emptyVar   = "SIFT_QA_SECRET_EMPTY"
		missingVar = "SIFT_QA_SECRET_MISSING"
	)
	t.Setenv(setVar, "alpha")
	t.Setenv(emptyVar, "")

	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty input", in: "", want: ""},
		{name: "literal without references", in: "plain-text", want: "plain-text"},
		{name: "set variable", in: "${" + setVar + "}", want: "alpha"},
		{name: "set variable inside path", in: "db://${" + setVar + "}/sift", want: "db://alpha/sift"},
		{name: "unset variable expands to empty", in: "x${" + missingVar + "}y", want: "xy"},
		{name: "unset variable uses default", in: "${" + missingVar + ":-fallback}", want: "fallback"},
		{name: "empty variable uses default", in: "${" + emptyVar + ":-fallback}", want: "fallback"},
		{name: "set variable wins over default", in: "${" + setVar + ":-fallback}", want: "alpha"},
		{name: "default may contain a colon", in: "${" + missingVar + ":-a:-b}", want: "a:-b"},
		{name: "multiple references in one value", in: "${" + setVar + "}-${" + missingVar + ":-fb}", want: "alpha-fb"},
		{name: "empty default is allowed", in: "${" + missingVar + ":-}", want: ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange: environment installed above via t.Setenv.
			// Act
			got := EnvResolver{}.Resolve(tc.in)

			// Assert
			if got != tc.want {
				t.Fatalf("EnvResolver.Resolve(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestResolveWrapperMatchesEnvResolver keeps the package-level convenience
// function in sync with the type it delegates to.
func TestResolveWrapperMatchesEnvResolver(t *testing.T) {
	// Arrange
	t.Setenv("SIFT_QA_SECRET_WRAPPER", "wrapped")
	inputs := []string{
		"",
		"${SIFT_QA_SECRET_WRAPPER}",
		"${SIFT_QA_SECRET_WRAPPER:-fallback}",
		"${SIFT_QA_SECRET_WRAPPER_ABSENT:-fallback}",
	}

	// Act & Assert
	var r EnvResolver
	for _, in := range inputs {
		if got, want := Resolve(in), r.Resolve(in); got != want {
			t.Errorf("Resolve(%q) = %q, EnvResolver.Resolve = %q", in, got, want)
		}
	}
}
