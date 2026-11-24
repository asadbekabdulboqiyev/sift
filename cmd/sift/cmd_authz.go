package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/authz"
	"github.com/asadbekabdulboqiyev/sift/internal/config"
	"github.com/asadbekabdulboqiyev/sift/internal/gate"
)

// authzDeniedExitCode is returned when a run is blocked by the authorization
// policy. It is distinct from 1 (runtime error) and 2 (bad usage) so CI can
// tell "the tool broke" from "the policy refused".
const authzDeniedExitCode = gate.DeniedExitCode

// gateOptions is the CLI surface of the authorization layer.
type gateOptions struct {
	policyPath   string
	auditPath    string
	webhook      string
	allowPrivate bool
	authorized   string

	// adminBypass reports whether the local, time-limited admin unlock is
	// active. nil means "ask the real adminlock store".
	//
	// It is a field rather than a direct adminlock.Active() call so tests can
	// pin it: the gate's behaviour must be a function of its inputs, never of
	// whatever unlock happens to be open on the machine running the tests.
	adminBypass func() bool
}

// bypassActive resolves the admin-unlock seam, defaulting to the host store.
// Kept as a method so existing callers and tests that pin the seam still work;
// the shared gate honours the same function through Config.AdminBypass.
func (g gateOptions) bypassActive() bool {
	return g.gateConfig().Bypass()
}

// gateConfig projects this CLI's option struct onto the shared gate config.
func (g gateOptions) gateConfig() gate.Config {
	return gate.Config{
		PolicyPath:   g.policyPath,
		AuditPath:    g.auditPath,
		Webhook:      g.webhook,
		AllowPrivate: g.allowPrivate,
		Authorized:   g.authorized,
		AdminBypass:  g.adminBypass,
	}
}

// gateHooks supplies cmd/sift's process seams to the shared gate.
func gateHooks() gate.Hooks {
	return gate.Hooks{
		Exit:    exitProcess,
		Fatal:   fatal,
		Version: buildVersion,
	}
}

// addAuthzFlags registers the shared authorization flags on a FlagSet.
func addAuthzFlags(fs *flag.FlagSet, g *gateOptions) {
	gate.BindFlags(fs, gate.Bindings{
		Authorized:   &g.authorized,
		AllowPrivate: &g.allowPrivate,
		PolicyPath:   &g.policyPath,
		AuditPath:    &g.auditPath,
		Webhook:      &g.webhook,
	})
}

// configHome returns the directory holding Sift's local state.
// configHome, defaultPolicyPath and defaultAuditPath delegate to the authz
// package so the CLI, the scan binary and the dashboard resolve the same
// policy and the same audit trail. The bodies used to live here and in
// cmd/sift-scan as two hand-kept copies.
func configHome() string {
	return authz.ConfigHome()
}

func defaultPolicyPath() string {
	return authz.DefaultPolicyPath()
}

func defaultAuditPath() string {
	return authz.DefaultAuditPath()
}

// authzOutcome is the aggregate verdict for a run. The type now lives in the
// shared gate so cmd/sift and cmd/sift-replay cannot disagree about fields.
type authzOutcome = gate.Outcome

// evaluateAuthz classifies every target and applies the policy. A denial is an
// outcome, not an error; error is reserved for infrastructure failures.
func evaluateAuthz(op authz.Operation, targets []string, g gateOptions) (authzOutcome, error) {
	return gate.Evaluate(op, targets, g.gateConfig())
}

// enforceAuthz gates a run: it classifies the targets, writes an audit record,
// and either returns or terminates with the denial exit code.
func enforceAuthz(op authz.Operation, targets []string, argv []string, g gateOptions) authzOutcome {
	return gate.Enforce(op, targets, argv, g.gateConfig(), gateHooks())
}

// authzDecision evaluates the policy and appends the audit record, without
// deciding what to do about a denial. enforceAuthz is the version that stops
// the program; `pentest --dry-run` calls this one so it can show the decision
// as part of the plan instead of refusing to show the plan at all.
func authzDecision(op authz.Operation, targets []string, argv []string, g gateOptions) authzOutcome {
	return gate.Decision(op, targets, argv, g.gateConfig(), gateHooks())
}

// printAuthzDenial explains a refusal and what would lift it.
func printAuthzDenial(targets []string, out authzOutcome) {
	gate.PrintDenial(targets, out, gateHooks())
}

func recordAuthz(e authz.Entry, auditPath, webhook string) {
	_ = gate.Record(e, gate.Config{AuditPath: auditPath, Webhook: webhook}, gateHooks())
}

func scenarioTargets(sc *config.Scenario) []string {
	if sc == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(u string) {
		u = strings.TrimSpace(u)
		if u == "" || !strings.Contains(u, "://") || seen[u] {
			return
		}
		seen[u] = true
		out = append(out, u)
	}
	add(sc.BaseURL)
	// Walk nested steps as well: a type:"if" branch can contain the only real
	// network targets of a scenario (its own URL is empty). Extracting only
	// top-level steps would classify zero targets, make enforceAuthz() return
	// Allowed with no policy decision and no audit record, and let the engine
	// dial those nested targets under a permissive ClassPublic gate.
	var walk func([]config.Step)
	walk = func(steps []config.Step) {
		for _, s := range steps {
			add(s.URL)
			walk(s.Steps)
		}
	}
	walk(sc.Steps)
	return out
}

func runAuthorizeWithGate(sc *config.Scenario, op authz.Operation, g gateOptions) {
	enforceAuthz(op, scenarioTargets(sc), os.Args, g)
}

// ── CLI: authorize ──────────────────────────────────────────────────────────

func cmdAuthorize() {
	args := os.Args[2:]
	if len(args) == 0 {
		authorizeUsage()
		exitProcess(2)
	}
	switch args[0] {
	case "add":
		authorizeAdd(args[1:])
	case "list", "ls":
		authorizeList(args[1:])
	case "remove", "rm":
		authorizeRemove(args[1:])
	case "verify":
		authorizeVerify(args[1:])
	case "help", "--help", "-h":
		authorizeUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown authorize subcommand %q\n\n", args[0])
		authorizeUsage()
		exitProcess(2)
	}
}

func authorizeUsage() {
	fmt.Fprint(os.Stderr, `usage: Sift authorize <add|list|remove|verify> [flags]

Authorization entries define which targets may be tested and by whose approval.
They are stored in `+defaultPolicyPath()+`.

  add     --pattern <host|ip|*.domain|cidr|*> [--until RFC3339] [--approver NAME]
          [--ticket ID] [--reason TEXT] [--policy PATH]
  list    [--policy PATH]
  remove  --pattern <pattern> [--policy PATH]
  verify  [--policy PATH]

A pentest (and --authorized <ticket>) needs an entry that names the target:
a host or an IP. "*.domain" and CIDR entries scope load tests and scans; they
never authorize a pentest against the hosts inside them.
`)
}

func authorizeAdd(args []string) {
	fs := flag.NewFlagSet("authorize add", flag.ContinueOnError)
	pattern := fs.String("pattern", "", "target pattern: host, ip, *.domain, CIDR, or * (pentest needs host/ip)")
	until := fs.String("until", "", "expiry as RFC3339 (default: no expiry)")
	approver := fs.String("approver", "", "who approved this authorization")
	ticket := fs.String("ticket", "", "change/incident ticket id")
	reason := fs.String("reason", "", "why this target is authorized")
	policyPath := fs.String("policy", defaultPolicyPath(), "policy file")
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			authorizeUsage()
			return
		}
		fatal(err)
	}
	if strings.TrimSpace(*pattern) == "" {
		fatal(fmt.Errorf("--pattern is required"))
	}

	r := authz.Rule{Pattern: strings.TrimSpace(*pattern), Approver: *approver, Ticket: *ticket, Reason: *reason}
	if *until != "" {
		ts, err := time.Parse(time.RFC3339, *until)
		if err != nil {
			fatal(fmt.Errorf("--until must be RFC3339 (e.g. 2026-12-31T00:00:00Z): %w", err))
		}
		r.Until = ts
	}

	pol, err := authz.LoadPolicyOrDefault(*policyPath)
	if err != nil {
		fatal(err)
	}
	replaced := false
	for i := range pol.Rules {
		if pol.Rules[i].Pattern == r.Pattern {
			pol.Rules[i] = r
			replaced = true
			break
		}
	}
	if !replaced {
		pol.Rules = append(pol.Rules, r)
	}
	if err := savePolicy(*policyPath, pol); err != nil {
		fatal(err)
	}

	verb := "added"
	if replaced {
		verb = "updated"
	}
	fmt.Printf("%s authorization: %s", verb, r.Pattern)
	if !r.Until.IsZero() {
		fmt.Printf(" (until %s)", r.Until.Format(time.RFC3339))
	}
	if r.Ticket != "" {
		fmt.Printf(" ticket=%s", r.Ticket)
	}
	fmt.Printf("\npolicy: %s\n", *policyPath)
}

func authorizeList(args []string) {
	fs := flag.NewFlagSet("authorize list", flag.ContinueOnError)
	policyPath := fs.String("policy", defaultPolicyPath(), "policy file")
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			authorizeUsage()
			return
		}
		fatal(err)
	}
	pol, err := authz.LoadPolicyOrDefault(*policyPath)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("policy: %s\nmode: %s (allow_private=%v)\n", *policyPath, modeName(pol.Mode), pol.AllowPrivate)
	if len(pol.Rules) == 0 {
		fmt.Println("rules: (none)")
		return
	}
	now := time.Now()
	fmt.Println("rules:")
	for _, r := range pol.Rules {
		state := "active"
		if !r.Until.IsZero() && now.After(r.Until) {
			state = "EXPIRED " + r.Until.Format(time.RFC3339)
		} else if !r.Until.IsZero() {
			state = "until " + r.Until.Format(time.RFC3339)
		}
		fmt.Printf("  %-32s %-28s approver=%-14s ticket=%s\n", r.Pattern, state, orDash(r.Approver), orDash(r.Ticket))
	}
}

func authorizeRemove(args []string) {
	fs := flag.NewFlagSet("authorize remove", flag.ContinueOnError)
	pattern := fs.String("pattern", "", "pattern to remove")
	policyPath := fs.String("policy", defaultPolicyPath(), "policy file")
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			authorizeUsage()
			return
		}
		fatal(err)
	}
	if *pattern == "" {
		fatal(fmt.Errorf("--pattern is required"))
	}
	pol, err := authz.LoadPolicyOrDefault(*policyPath)
	if err != nil {
		fatal(err)
	}
	kept := pol.Rules[:0]
	removed := 0
	for _, r := range pol.Rules {
		if r.Pattern == *pattern {
			removed++
			continue
		}
		kept = append(kept, r)
	}
	pol.Rules = kept
	if err := savePolicy(*policyPath, pol); err != nil {
		fatal(err)
	}
	fmt.Printf("removed %d rule(s) matching %q from %s\n", removed, *pattern, *policyPath)
}

func authorizeVerify(args []string) {
	fs := flag.NewFlagSet("authorize verify", flag.ContinueOnError)
	policyPath := fs.String("policy", defaultPolicyPath(), "policy file")
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			authorizeUsage()
			return
		}
		fatal(err)
	}
	pol, err := authz.LoadPolicy(*policyPath)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("policy %s is valid: mode=%s, %d rule(s)\n", *policyPath, modeName(pol.Mode), len(pol.Rules))
}

// ── CLI: audit ──────────────────────────────────────────────────────────────

func cmdAudit() {
	args := os.Args[2:]
	if len(args) == 0 {
		auditUsage()
		exitProcess(2)
	}
	switch args[0] {
	case "show", "ls":
		auditShow(args[1:])
	case "verify":
		auditVerify(args[1:])
	case "help", "--help", "-h":
		auditUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown audit subcommand %q\n\n", args[0])
		auditUsage()
		exitProcess(2)
	}
}

func auditUsage() {
	fmt.Fprint(os.Stderr, `usage: Sift audit <show|verify> [flags]

  show    [--log PATH] [--limit N]   print recorded decisions
  verify  [--log PATH]               verify the hash chain (detect tampering)
`)
}

func auditShow(args []string) {
	fs := flag.NewFlagSet("audit show", flag.ContinueOnError)
	logPath := fs.String("log", defaultAuditPath(), "audit log file")
	limit := fs.Int("limit", 20, "show the last N entries (0 = all)")
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			auditUsage()
			return
		}
		fatal(err)
	}
	entries, err := authz.ReadAll(*logPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("no audit log at %s\n", *logPath)
			return
		}
		fatal(err)
	}
	if *limit > 0 && len(entries) > *limit {
		entries = entries[len(entries)-*limit:]
	}
	fmt.Printf("audit log: %s (%d record(s) shown)\n", *logPath, len(entries))
	for _, e := range entries {
		verdict := "ALLOW"
		if !e.Allowed {
			verdict = "DENY "
		}
		fmt.Printf("  #%-4d %s %s %-7s %-11s targets=%s\n",
			e.Seq, e.Time.Format(time.RFC3339), verdict, e.Action, e.Class, strings.Join(e.Targets, ","))
	}
}

func auditVerify(args []string) {
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	logPath := fs.String("log", defaultAuditPath(), "audit log file")
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			auditUsage()
			return
		}
		fatal(err)
	}
	n, err := authz.Verify(*logPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "TAMPERED or corrupt: %v (verified %d record(s) before the break)\n", err, n)
		exitProcess(1)
	}
	fmt.Printf("OK: %d record(s), hash chain intact (%s)\n", n, *logPath)
}

// ── helpers ─────────────────────────────────────────────────────────────────

func savePolicy(path string, pol authz.Policy) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	raw, err := json.MarshalIndent(pol, "", "  ")
	if err != nil {
		return err
	}
	if err := atomicWriteFile(path, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	return nil
}

func modeName(m authz.Mode) string {
	if m == authz.ModeStrict {
		return "strict"
	}
	return "permissive"
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
