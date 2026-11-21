package dashboard

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/asadbekabdulboqiyev/sift/internal/authz"
	"github.com/asadbekabdulboqiyev/sift/internal/rbac"
)

// ErrRunCommandDenied marks a start/stop command rejected by the shared run
// gate. Keeping a sentinel lets the WebSocket loop report the authorization
// decision to the caller without treating a denial as a broken socket.
var ErrRunCommandDenied = errors.New("run command denied")

// RunAuthorization is the outcome of the load-test authorization gate shared
// by the HTTP start endpoint and the WebSocket command path.
type RunAuthorization struct {
	Allowed bool
	Class   string
	IPs     []string
	Rule    string
	Reason  string
}

// authorizeRunTarget applies the full OpLoadTest policy gate and writes the
// audit trail, exactly as the HTTP start endpoint does. Both entry points call
// this one function so a browser client cannot pick a weaker gate. An audit
// write failure fails closed: an incomplete trail must never approve a run.
func authorizeRunTarget(target, ticket, source, actor string) (RunAuthorization, error) {
	// Build the audit entry once so both a completed decision and a failed
	// policy lookup leave the same attributable trail. When actor is empty
	// (no auth enrolled) authz falls back to the process user.
	entry := authz.Entry{
		Action:  authz.OpLoadTest.String(),
		Targets: []string{target},
		Actor:   actor,
		Argv:    []string{"Sift dashboard", source},
	}
	decision, err := owaspGate(authz.OpLoadTest, target, ticket)
	if err != nil {
		// A failed gate check is still an attempt: record it as denied
		// rather than dropping the event on the floor. Fail closed in all
		// cases, and report both failures if the audit write fails too.
		entry.Allowed = false
		entry.Reason = "policy check failed: " + err.Error()
		if auditErr := owaspAudit(entry); auditErr != nil {
			return RunAuthorization{}, fmt.Errorf("policy check failed (%v); audit unavailable (%w)", err, auditErr)
		}
		return RunAuthorization{}, err
	}
	entry.IPs = decision.IPs
	entry.Class = decision.Class
	entry.Allowed = decision.Allowed
	entry.Rule = decision.Rule
	entry.Reason = decision.Reason
	if auditErr := owaspAudit(entry); auditErr != nil {
		return RunAuthorization{}, auditErr
	}
	return RunAuthorization{
		Allowed: decision.Allowed,
		Class:   decision.Class,
		IPs:     decision.IPs,
		Rule:    decision.Rule,
		Reason:  decision.Reason,
	}, nil
}

// runTargetFromArgs extracts the authoritative target and ticket from a run
// command's config object. Both dashboard binaries build the engine target
// from args["config"]["target_url"], so this is the only shape that may be
// gated: accepting a different field would let a caller pass the gate with one
// value while the engine starts against another.
func runTargetFromArgs(args map[string]interface{}) (target, ticket string) {
	cfg, ok := args["config"].(map[string]interface{})
	if !ok {
		return "", ""
	}
	target, _ = cfg["target_url"].(string)
	ticket, _ = cfg["authorized"].(string)
	return strings.TrimSpace(target), strings.TrimSpace(ticket)
}

// authorizeRunPermission enforces the tests:run permission at command dispatch
// time. The WebSocket upgrade is a GET and therefore only requires tests:view,
// so without this check a viewer could drive the load engine. When no auth is
// enrolled the dashboard is open by the operator's explicit bind-address
// choice and the check is a no-op, matching rbacAllowed's disabled behavior.
func (s *Server) authorizeRunPermission(ctx context.Context) error {
	if s.auth == nil {
		// No auth at all means the operator deliberately exposed an open
		// dashboard (loopback bind), so keep the historical no-op behavior.
		// A custom middleware, however, cannot be evaluated by rbacAllowed:
		// it may authenticate but never populate *Auth. Fail closed rather
		// than silently skipping tests:run on the WS path, matching the
		// admin-bypass precedent in audit360.go.
		if s.authMiddleware == nil {
			return nil
		}
		return fmt.Errorf("%w: run authorization unavailable for custom auth middleware", ErrRunCommandDenied)
	}
	subject, roles, ok := PrincipalAndRolesFromContext(ctx)
	if !ok {
		return fmt.Errorf("%w: no authenticated principal on the connection", ErrRunCommandDenied)
	}
	if !s.auth.rbacAllowed(subject, roles, rbac.PermRun) {
		return fmt.Errorf("%w: tests:run permission required", ErrRunCommandDenied)
	}
	return nil
}

// authorizeRunCommand gates a WebSocket start/stop command before dispatch.
// Stop needs only the control-plane permission; start additionally requires an
// explicit http(s) target that passes the same policy gate as the HTTP endpoint.
func (s *Server) authorizeRunCommand(ctx context.Context, command string, args map[string]interface{}) error {
	if command != "start" && command != "stop" {
		return nil
	}
	if err := s.authorizeRunPermission(ctx); err != nil {
		return err
	}
	if command == "stop" {
		return nil
	}

	target, ticket := runTargetFromArgs(args)
	if target == "" {
		return fmt.Errorf("%w: start requires config.target_url (use POST /api/run/start)", ErrRunCommandDenied)
	}
	if u, err := url.Parse(target); err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("%w: config.target_url must be an http(s) URL", ErrRunCommandDenied)
	}
	actor, _, _ := PrincipalAndRolesFromContext(ctx)
	result, err := authorizeRunTarget(target, ticket, "WS start", actor)
	if err != nil {
		return fmt.Errorf("%w: authorization check failed: %v", ErrRunCommandDenied, err)
	}
	if !result.Allowed {
		return fmt.Errorf("%w: %s", ErrRunCommandDenied, result.Reason)
	}
	return nil
}
