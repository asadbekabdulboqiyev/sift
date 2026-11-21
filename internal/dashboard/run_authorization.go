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
func authorizeRunTarget(target, ticket, source string) (RunAuthorization, error) {
	decision, err := owaspGate(authz.OpLoadTest, target, ticket)
	if err != nil {
		return RunAuthorization{}, err
	}
	if auditErr := owaspAudit(authz.Entry{
		Action:  authz.OpLoadTest.String(),
		Targets: []string{target},
		IPs:     decision.IPs,
		Class:   decision.Class,
		Allowed: decision.Allowed,
		Rule:    decision.Rule,
		Reason:  decision.Reason,
		Argv:    []string{"Sift dashboard", source},
	}); auditErr != nil {
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
		return nil
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
	result, err := authorizeRunTarget(target, ticket, "WS start")
	if err != nil {
		return fmt.Errorf("%w: authorization check failed: %v", ErrRunCommandDenied, err)
	}
	if !result.Allowed {
		return fmt.Errorf("%w: %s", ErrRunCommandDenied, result.Reason)
	}
	return nil
}
