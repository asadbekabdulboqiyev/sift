package main

// cli_group_alias_test.go - in-process coverage for the additive command
// groups (test / secure / evidence). A group is only a shortcut: it must reach
// the exact same command function with the exact same argv as the direct form.
// An unknown subcommand must fail in the dispatcher, before any command runs.

import (
	"strings"
	"testing"
)

// TestInprocGroupAliasesMatchDirectCommands proves that each alias produces
// the same exit status and the same output as its direct equivalent. --help
// keeps every case offline while still exercising the real command function.
func TestInprocGroupAliasesMatchDirectCommands(t *testing.T) {
	scanCLIHome(t)

	cases := []struct {
		name   string
		alias  []string
		direct string
		want   string
	}{
		{name: "test run", alias: []string{"test", "run", "--help"}, direct: "run", want: "Sift run"},
		{name: "secure pentest", alias: []string{"secure", "pentest", "--help"}, direct: "pentest", want: "pentest"},
		{name: "evidence verify", alias: []string{"evidence", "verify", "--help"}, direct: "verify", want: "Sift verify"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			aliased := runCLIInProcess(t, tc.alias...)
			direct := runCLIInProcess(t, tc.direct, "--help")

			if aliased.code != 0 {
				t.Fatalf("alias exit = %d, want 0 (stderr: %s)", aliased.code, aliased.stderr)
			}
			if direct.code != 0 {
				t.Fatalf("direct exit = %d, want 0 (stderr: %s)", direct.code, direct.stderr)
			}
			if aliased.code != direct.code || aliased.stdout != direct.stdout || aliased.stderr != direct.stderr {
				t.Fatalf("alias and direct differ:\n alias: code=%d stdout=%q stderr=%q\n direct: code=%d stdout=%q stderr=%q",
					aliased.code, aliased.stdout, aliased.stderr,
					direct.code, direct.stdout, direct.stderr)
			}
			if joined := aliased.stdout + aliased.stderr; !strings.Contains(joined, tc.want) {
				t.Errorf("output = %q, want it to name %q", joined, tc.want)
			}
		})
	}
}

// TestInprocGroupRunKeepsArgvShape targets the special run path, which shifts
// os.Args itself. Reaching the version output proves flags still reach cmdRun
// after resolving the alias.
func TestInprocGroupRunKeepsArgvShape(t *testing.T) {
	scanCLIHome(t)

	res := runCLIInProcess(t, "test", "run", "--version")
	if res.code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", res.code, res.stderr)
	}
	if !strings.Contains(res.stdout, "Sift v"+buildVersion) {
		t.Errorf("stdout = %q, want the version line", res.stdout)
	}
}

// TestInprocGroupUnknownSubcommand checks that a bad subcommand is rejected by
// the group dispatcher: exit 2, no command output, and a message naming every
// subcommand in that group. No scanner or load-test path is entered.
func TestInprocGroupUnknownSubcommand(t *testing.T) {
	scanCLIHome(t)

	cases := []struct {
		group string
		want  []string
	}{
		{group: "test", want: []string{"run", "replay", "simulate", "healthcheck"}},
		{group: "secure", want: []string{"scan", "pentest", "xray", "fuzz", "dirbust", "jwt", "graphql", "websocket", "crawl", "subdomain", "portscan", "sslscan", "bounty", "audit360"}},
		{group: "evidence", want: []string{"keygen", "trust", "verify", "certificate", "audit", "authorize"}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.group, func(t *testing.T) {
			res := runCLIInProcess(t, tc.group, "definitely-not-a-subcommand")
			if res.code != 2 {
				t.Fatalf("exit = %d, want 2 (stderr: %s)", res.code, res.stderr)
			}
			if !strings.Contains(res.stderr, "unknown command") || !strings.Contains(res.stderr, "Available subcommands") {
				t.Errorf("stderr = %q, want a group-specific error message", res.stderr)
			}
			for _, c := range tc.want {
				if !strings.Contains(res.stderr, "Sift "+tc.group+" "+c) {
					t.Errorf("stderr does not list 'Sift %s %s': %q", tc.group, c, res.stderr)
				}
			}
			// A real command would print a usage/requirement error instead.
			if strings.Contains(res.stderr, "--target is required") || strings.Contains(res.stderr, "--bundle is required") {
				t.Errorf("stderr looks like a command was dispatched: %q", res.stderr)
			}
		})
	}
}

// TestInprocGroupMissingSubcommand covers the bare group form, which must fail
// the same way as an unknown subcommand rather than falling back to run.
func TestInprocGroupMissingSubcommand(t *testing.T) {
	scanCLIHome(t)

	for _, group := range []string{"test", "secure", "evidence"} {
		group := group
		t.Run(group, func(t *testing.T) {
			res := runCLIInProcess(t, group)
			if res.code != 2 {
				t.Fatalf("exit = %d, want 2 (stderr: %s)", res.code, res.stderr)
			}
			if !strings.Contains(res.stderr, "requires a subcommand") {
				t.Errorf("stderr = %q, want a missing-subcommand message", res.stderr)
			}
		})
	}
}

// TestInprocGroupNamesAreSuggestable verifies the groups were added to
// knownCommands, so the unknown-command listing can suggest them.
func TestInprocGroupNamesAreSuggestable(t *testing.T) {
	scanCLIHome(t)

	res := runCLIInProcess(t, "definitely-not-a-command")
	if res.code != 2 {
		t.Fatalf("exit = %d, want 2 (stderr: %s)", res.code, res.stderr)
	}
	for _, group := range []string{"test", "secure", "evidence"} {
		if !strings.Contains(res.stderr, "   "+group+"\n") {
			t.Errorf("unknown-command listing does not contain group %q: %q", group, res.stderr)
		}
	}
}
