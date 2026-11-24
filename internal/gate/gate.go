// Package gate is the single authorization decision point shared by every
// Sift CLI that can send traffic.
//
// cmd/sift used to own the whole gate (policy load, target classification,
// audit write, denial output) while cmd/sift-replay built a weaker, local
// socket control from --base-url alone. Two copies of a security decision
// drift: the replay binary ended up with no policy, no ticket and no audit at
// all. Both entry points now call Evaluate/Enforce here and differ only in the
// operation they pass and in their process seams (exit, fatal, version).
package gate

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/adminlock"
	"github.com/asadbekabdulboqiyev/sift/internal/authz"
)

// DeniedExitCode is distinct from 1 (runtime error) and 2 (bad usage), so CI
// can tell "the policy refused" from "the tool broke".
const DeniedExitCode = 3

// Config is the operator-facing authorization configuration. It is the
// transportable form of cmd/sift's gateOptions and the replay flags alike.
type Config struct {
	PolicyPath   string
	AuditPath    string
	Webhook      string
	AllowPrivate bool
	Authorized   string

	// StrictAudit makes an unwritable audit log a hard failure. cmd/sift keeps
	// the historical warn-and-continue behaviour; replay must never run
	// without a record of what it sent, so it sets this to true.
	StrictAudit bool

	// AdminBypass resolves the local, time-limited admin unlock. nil means
	// "ask the real store". Tests pin it so host state cannot decide a case.
	AdminBypass func() bool
}

// Bypass resolves the admin-unlock seam, defaulting to the host store.
func (c Config) Bypass() bool {
	if c.AdminBypass != nil {
		return c.AdminBypass()
	}
	return adminlock.Active()
}

func (c Config) bypassActive() bool { return c.Bypass() }

func (c Config) policyPath() string {
	if p := strings.TrimSpace(c.PolicyPath); p != "" {
		return p
	}
	return authz.DefaultPolicyPath()
}

func (c Config) auditPath() string {
	if p := strings.TrimSpace(c.AuditPath); p != "" {
		return p
	}
	return authz.DefaultAuditPath()
}

// Hooks injects process behaviour. Production callers pass exits that
// terminate the process; tests pass panics so a refusal can be asserted.
type Hooks struct {
	Exit    func(int)
	Fatal   func(error)
	Stderr  func() io.Writer
	Version string
}

func (h Hooks) stderr() io.Writer {
	if h.Stderr != nil {
		if w := h.Stderr(); w != nil {
			return w
		}
	}
	return os.Stderr
}

func (h Hooks) exit(code int) {
	if h.Exit != nil {
		h.Exit(code)
		return
	}
	os.Exit(code)
}

func (h Hooks) fatal(err error) {
	if h.Fatal != nil {
		h.Fatal(err)
		return
	}
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}

// Outcome is the aggregate verdict for one run.
type Outcome struct {
	Allowed bool
	Class   string
	// ClassValue is the same class as Class, kept typed so callers can hand it
	// to authz.DialControl and have the decision re-applied to the address the
	// socket actually connects to.
	ClassValue authz.Class
	Rule       string
	Reason     string
	Targets    []string
	IPs        []string
	// ApprovedIPs are the addresses of the targets that were allowed. The
	// replay CLI builds its non-nil socket control from exactly this set.
	ApprovedIPs []net.IP
}

// Bindings points at the storage for the five shared flags. It lets a caller
// with its own configuration struct (cmd/sift's gateOptions) reuse the exact
// same flag names and help text without duplicating them.
type Bindings struct {
	Authorized   *string
	AllowPrivate *bool
	PolicyPath   *string
	AuditPath    *string
	Webhook      *string
}

// BindFlags registers the shared authorization flags against b.
func BindFlags(fs *flag.FlagSet, b Bindings) {
	fs.StringVar(b.Authorized, "authorized", "", "authorization ticket id granted by an approver (required for pentest)")
	fs.BoolVar(b.AllowPrivate, "allow-private", false, "allow RFC1918/private targets without an explicit authorization entry")
	fs.StringVar(b.PolicyPath, "policy", "", "authorization policy JSON (default ~/.Sift/authz.json)")
	fs.StringVar(b.AuditPath, "audit-log", "", "append-only audit log path (default ~/.Sift/audit.jsonl)")
	fs.StringVar(b.Webhook, "notify-webhook", "", "webhook URL to notify on every authorization decision")
}

// AddFlags registers the five shared authorization flags on fs.
func AddFlags(fs *flag.FlagSet, c *Config) {
	BindFlags(fs, Bindings{
		Authorized:   &c.Authorized,
		AllowPrivate: &c.AllowPrivate,
		PolicyPath:   &c.PolicyPath,
		AuditPath:    &c.AuditPath,
		Webhook:      &c.Webhook,
	})
}

// OperationName is the audit/action name for an operation. It lives here
// because OpReplay was added after authz.Operation.String() was frozen: the
// existing method returns "op(3)" for it, which would make audit records
// unreadable and break the CLI's output contract.
func OperationName(op authz.Operation) string {
	if authz.IsReplayOperation(op) {
		return "replay"
	}
	return op.String()
}

// Evaluate classifies every target and applies the policy. A denial is an
// outcome, not an error; error is reserved for infrastructure failures.
func Evaluate(op authz.Operation, targets []string, c Config) (Outcome, error) {
	pol, err := authz.LoadPolicyOrDefault(c.policyPath())
	if err != nil {
		return Outcome{}, err
	}
	if c.AllowPrivate {
		pol.AllowPrivate = true
	}
	if env := os.Getenv("SIFT_ALLOW"); env != "" {
		if err := pol.AddEnvRules(env); err != nil {
			return Outcome{}, err
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out := Outcome{Allowed: true, Targets: targets}
	worst := authz.ClassPublic
	// The admin bypass is a local, time-limited override. It never unlocks
	// cloud instance metadata: that path hands out credentials and stays
	// closed no matter what the operator toggled on.
	bypass := c.bypassActive()
	now := time.Now()

	for _, raw := range targets {
		tgt, err := authz.Classify(ctx, raw, nil)
		if err != nil {
			return Outcome{}, err
		}
		for _, ip := range tgt.IPs {
			out.IPs = append(out.IPs, ip.String())
		}
		worst = authz.Worst(worst, tgt.Class())

		var d authz.Decision
		switch {
		case tgt.Class() == authz.ClassMetadata:
			// Instance metadata hands out temporary IAM credentials to
			// anything that can reach it. No bypass, ticket or wildcard
			// opens it.
			d = authz.Decision{Class: tgt.Class(),
				Reason: fmt.Sprintf("refusing to send traffic to cloud instance metadata (%s) — this is the credential-theft path and the admin bypass does not unlock it", tgt.Host)}
		case authz.IsReplayOperation(op) && neverApprovedReplayClass(tgt.Class()):
			// Replay resends captured headers verbatim. Carrier-grade NAT,
			// link-local, multicast and reserved addresses are never a
			// legitimate replay destination, even with an admin unlock.
			d = authz.Decision{Class: tgt.Class(),
				Reason: fmt.Sprintf("refusing to replay to %s target (%s)", tgt.Class(), tgt.Host)}
		case bypass:
			d = authz.Decision{Allowed: true, Class: tgt.Class(), Rule: "admin-unlock",
				Reason: "admin bypass active — authorization checks temporarily bypassed from this host"}
		case authz.IsReplayOperation(op):
			// Replay is as sensitive as a pentest for non-public targets:
			// it re-sends captured Authorization/Cookie/X-Api-Key headers.
			// A ticket must name the target; --allow-private alone does not
			// authorize a replay against the runner's own network.
			switch tgt.Class() {
			case authz.ClassLoopback, authz.ClassPrivate:
				d = replayTicketDecision(c, pol, tgt, now)
			default:
				// Public destinations follow the ordinary policy, including
				// strict mode and explicit allow-list rules.
				d = pol.Check(tgt, authz.OpLoadTest, now)
			}
		case op == authz.OpPentest:
			// Offensive operation: an approval entry must exist in the policy
			// AND the operator must name its ticket. Neither alone is enough.
			if strings.TrimSpace(c.Authorized) == "" {
				d = authz.Decision{Class: tgt.Class(),
					Reason: fmt.Sprintf("pentest against %s requires --authorized <ticket> naming an entry approved with `authorize add`", tgt.Host)}
			} else if pat, ok := pol.AuthorizedBy(tgt, c.Authorized, now); ok {
				d = authz.Decision{Allowed: true, Class: tgt.Class(), Rule: pat,
					Reason: fmt.Sprintf("authorization ticket %q (%s)", c.Authorized, pat)}
			} else {
				d = authz.Decision{Class: tgt.Class(),
					Reason: fmt.Sprintf("no active authorization with ticket %q covers %s", c.Authorized, tgt.Host)}
			}
		case strings.TrimSpace(c.Authorized) != "":
			// The operator named a ticket: it must actually cover the target.
			if pat, ok := pol.AuthorizedBy(tgt, c.Authorized, now); ok {
				d = authz.Decision{Allowed: true, Class: tgt.Class(), Rule: pat,
					Reason: fmt.Sprintf("authorization ticket %q (%s)", c.Authorized, pat)}
			} else {
				d = authz.Decision{Class: tgt.Class(),
					Reason: fmt.Sprintf("no active authorization with ticket %q covers %s", c.Authorized, tgt.Host)}
			}
		default:
			d = pol.Check(tgt, op, now)
		}

		if !d.Allowed {
			// The first refusal wins. Evaluating more targets must not turn a
			// metadata denial into an unrelated "authorized" explanation.
			if out.Allowed {
				out.Reason = d.Reason
				out.Rule = d.Rule
			}
			out.Allowed = false
		} else {
			// Once a target has been refused, later targets must not replace
			// the reason: the audit record and denial banner have to explain
			// the target that actually stopped the run.
			if out.Allowed {
				if out.Rule == "" {
					out.Rule = d.Rule
					out.Reason = d.Reason
				}
				for _, ip := range tgt.IPs {
					if !containsIP(out.ApprovedIPs, ip) {
						out.ApprovedIPs = append(out.ApprovedIPs, ip)
					}
				}
			}
		}
	}
	out.Class = worst.String()
	out.ClassValue = worst
	return out, nil
}

func replayTicketDecision(c Config, pol authz.Policy, tgt authz.Target, now time.Time) authz.Decision {
	if strings.TrimSpace(c.Authorized) == "" {
		return authz.Decision{Class: tgt.Class(),
			Reason: fmt.Sprintf("replay against %s requires --authorized <ticket> naming an entry approved with `authorize add`", tgt.Host)}
	}
	if pat, ok := pol.AuthorizedBy(tgt, c.Authorized, now); ok {
		return authz.Decision{Allowed: true, Class: tgt.Class(), Rule: pat,
			Reason: fmt.Sprintf("authorization ticket %q (%s)", c.Authorized, pat)}
	}
	return authz.Decision{Class: tgt.Class(),
		Reason: fmt.Sprintf("no active authorization with ticket %q covers %s", c.Authorized, tgt.Host)}
}

func neverApprovedReplayClass(c authz.Class) bool {
	switch c {
	case authz.ClassCGNAT, authz.ClassLinkLocal, authz.ClassMulticast, authz.ClassReserved:
		return true
	default:
		return false
	}
}

func containsIP(ips []net.IP, ip net.IP) bool {
	for _, got := range ips {
		if got.Equal(ip) {
			return true
		}
	}
	return false
}

// Enforce gates a run: evaluates, audits, and either returns or terminates
// with the denial exit code. Zero targets are a no-op, matching cmd/sift's
// historical behaviour for scenarios with no network steps; the replay CLI
// checks for a derivable destination before it gets here.
func Enforce(op authz.Operation, targets, argv []string, c Config, h Hooks) Outcome {
	if len(targets) == 0 {
		return Outcome{Allowed: true, ClassValue: authz.ClassPublic}
	}
	out := Decision(op, targets, argv, c, h)

	if out.Allowed {
		if out.Rule == "admin-unlock" {
			fmt.Fprintln(h.stderr(), "════════════════════════════════════════════════════════════════")
			fmt.Fprintln(h.stderr(), " WARNING: ADMIN BYPASS ACTIVE — authorization checks are OFF")
			fmt.Fprintln(h.stderr(), " This run was allowed by the local admin unlock, not by a ticket.")
			fmt.Fprintln(h.stderr(), " Restore the gate now:  Sift admin lock")
			fmt.Fprintln(h.stderr(), "════════════════════════════════════════════════════════════════")
		}
		if out.Rule != "" {
			fmt.Fprintf(h.stderr(), "authorization: ok (class=%s, rule=%s)\n", out.Class, out.Rule)
		} else {
			fmt.Fprintf(h.stderr(), "authorization: ok (class=%s)\n", out.Class)
		}
		return out
	}

	PrintDenial(targets, out, h)
	h.exit(DeniedExitCode)
	return Outcome{}
}

// Decision evaluates the policy and appends the audit record without deciding
// what to do about a denial. `pentest --dry-run` uses it to show the decision
// as part of the plan; replay uses Enforce.
func Decision(op authz.Operation, targets, argv []string, c Config, h Hooks) Outcome {
	out, err := Evaluate(op, targets, c)
	if err != nil {
		h.fatal(err)
	}

	if err := Record(authz.Entry{
		Action:  OperationName(op),
		Targets: targets,
		IPs:     out.IPs,
		Class:   out.Class,
		Allowed: out.Allowed,
		Rule:    out.Rule,
		Reason:  out.Reason,
		Version: h.Version,
		Argv:    argv,
	}, c, h); err != nil {
		h.fatal(err)
	}
	return out
}

// PrintDenial explains a refusal and what would lift it.
func PrintDenial(targets []string, out Outcome, h Hooks) {
	w := h.stderr()
	fmt.Fprintf(w, "\nBLOCKED by authorization policy\n")
	fmt.Fprintf(w, "  target: %s\n", strings.Join(targets, ", "))
	fmt.Fprintf(w, "  reason: %s\n\n", out.Reason)
	fmt.Fprintln(w, "To authorize a test, have the approver add an entry:")
	fmt.Fprintln(w, "  Sift authorize add --pattern <host-or-ip> --approver <name> --ticket <id>")
	fmt.Fprintln(w, "then re-run with --authorized <id>.")
}

// Record appends one hash-chained audit entry and, when configured, notifies a
// webhook. An audit write failure is returned: callers with StrictAudit set
// must abort. A webhook failure is best-effort and only warned about.
func Record(e authz.Entry, c Config, h Hooks) error {
	log, err := authz.Open(c.auditPath())
	if err != nil {
		fmt.Fprintf(h.stderr(), "warning: cannot write audit log: %v\n", err)
		if c.StrictAudit {
			return err
		}
		return nil
	}
	stored, appendErr := log.Append(e)
	_ = log.Close()
	if appendErr != nil {
		fmt.Fprintf(h.stderr(), "warning: cannot write audit log: %v\n", appendErr)
		if c.StrictAudit {
			return appendErr
		}
		return nil
	}

	if strings.TrimSpace(c.Webhook) == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), authz.DefaultNotifyTimeout)
	defer cancel()
	if err := (authz.Notifier{URL: c.Webhook}).Notify(ctx, stored); err != nil {
		fmt.Fprintf(h.stderr(), "warning: audit webhook failed: %v\n", err)
	}
	return nil
}
