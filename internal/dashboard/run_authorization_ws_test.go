package dashboard

// run_authorization_ws_test.go pins the WebSocket run gate: a WS start must
// clear the same OpLoadTest policy and tests:run permission as the HTTP start
// endpoint. Before this gate, GET /ws only required tests:view and dispatched
// start straight to the engine, so a viewer could probe internal and metadata
// targets with no policy decision recorded.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/asadbekabdulboqiyev/sift/internal/authz"
	"github.com/asadbekabdulboqiyev/sift/internal/rbac"
)

// isolateWSGateEnv points policy, allow rules and the audit log at a temp dir
// so the tests exercise the default policy, not the developer host's config.
func isolateWSGateEnv(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("SIFT_POLICY", filepath.Join(dir, "no-policy.json"))
	t.Setenv("SIFT_ALLOW", "")
	audit := filepath.Join(dir, "audit.jsonl")
	t.Setenv("SIFT_AUDIT_LOG", audit)
	return audit
}

func readWSCommandFrame(t *testing.T, conn *websocket.Conn) map[string]any {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	_, raw, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read ws frame: %v", err)
	}
	var frame map[string]any
	if err := json.Unmarshal(raw, &frame); err != nil {
		t.Fatalf("decode ws frame: %v\n%s", err, raw)
	}
	return frame
}

func assertCommandError(t *testing.T, frame map[string]any, command string) {
	t.Helper()
	if frame["type"] != "command_error" {
		t.Errorf("frame type = %v, want command_error (frame: %v)", frame["type"], frame)
	}
	if frame["command"] != command {
		t.Errorf("frame command = %v, want %q", frame["command"], command)
	}
	if msg, _ := frame["error"].(string); msg == "" {
		t.Errorf("command_error has no reason: %v", frame)
	}
}

func wsStartJSON(t *testing.T, conn *websocket.Conn, target string) {
	t.Helper()
	if err := conn.WriteJSON(map[string]any{
		"type": "start",
		"args": map[string]any{"config": map[string]any{"target_url": target}},
	}); err != nil {
		t.Fatalf("write start: %v", err)
	}
}

func TestWSStartRefusesUnsafeTargets(t *testing.T) {
	isolateWSGateEnv(t)

	s := NewServer()
	var mu sync.Mutex
	var commands []string
	s.SetCommandHandler(func(cmd string, args map[string]interface{}) {
		mu.Lock()
		defer mu.Unlock()
		commands = append(commands, cmd)
	})

	srv := httptest.NewServer(s)
	defer srv.Close()
	conn := dialDashboardWS(t, srv)
	defer conn.Close()
	_ = readWSCommandFrame(t, conn) // init frame

	targets := []string{
		// Cloud metadata and link-local credential-theft destinations.
		"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
		"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
		"http://[fe80::1]/",
		// Private, loopback, CGNAT and reserved ranges the default load-test
		// policy refuses just like the HTTP endpoint.
		"http://10.0.0.5:9200",
		"http://192.168.1.1/",
		"http://127.0.0.1:6379",
		"http://[::1]:6379/",
		"http://100.64.0.1/",
		"http://224.0.0.1/",
	}
	for _, target := range targets {
		wsStartJSON(t, conn, target)
		assertCommandError(t, readWSCommandFrame(t, conn), "start")
	}

	mu.Lock()
	got := append([]string(nil), commands...)
	mu.Unlock()
	if len(got) != 0 {
		t.Fatalf("dispatched commands = %v, want none for unsafe targets", got)
	}

	// The read loop survived every denial: a valid stop still reaches the
	// handler. This also proves a denied start does not tear down the socket.
	if err := conn.WriteJSON(map[string]any{"type": "stop"}); err != nil {
		t.Fatalf("write stop: %v", err)
	}
	waitFor(t, "stop to dispatch after denials", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(commands) == 1 && commands[0] == "stop"
	})
}

func TestWSStartRequiresExplicitTarget(t *testing.T) {
	isolateWSGateEnv(t)

	s := NewServer()
	var mu sync.Mutex
	var commands []string
	s.SetCommandHandler(func(cmd string, args map[string]interface{}) {
		mu.Lock()
		defer mu.Unlock()
		commands = append(commands, cmd)
	})

	srv := httptest.NewServer(s)
	defer srv.Close()

	cases := []struct {
		name string
		args map[string]any
	}{
		{"no args", nil},
		{"legacy target field is not authoritative", map[string]any{"target": "http://93.184.216.34/"}},
		{"empty target", map[string]any{"config": map[string]any{"target_url": "  "}}},
		{"non-http scheme", map[string]any{"config": map[string]any{"target_url": "file:///etc/passwd"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn := dialDashboardWS(t, srv)
			defer conn.Close()
			_ = readWSCommandFrame(t, conn) // init
			if err := conn.WriteJSON(map[string]any{"type": "start", "args": tc.args}); err != nil {
				t.Fatalf("write start: %v", err)
			}
			assertCommandError(t, readWSCommandFrame(t, conn), "start")
		})
	}

	mu.Lock()
	got := append([]string(nil), commands...)
	mu.Unlock()
	if len(got) != 0 {
		t.Fatalf("dispatched commands = %v, want none for malformed targets", got)
	}
}

func TestWSRunCommandRequiresPermRun(t *testing.T) {
	audit := isolateWSGateEnv(t)

	const viewerToken = "ws-viewer-token"
	const runnerToken = "ws-runner-token"
	viewerSubject := "bearer:" + shortID(HashKey(viewerToken))
	runnerSubject := "bearer:" + shortID(HashKey(runnerToken))

	s := NewServer()
	a := s.ApplyAuth(AuthOptions{
		Tokens:      []string{viewerToken, runnerToken},
		RBACEnabled: true,
	})
	if a == nil {
		t.Fatal("ApplyAuth returned nil with tokens enrolled")
	}
	defer a.Close()
	// Bearer subjects are hash-keyed and contain a colon, so set them directly
	// instead of via the "subject:role" flag parser (the same approach the
	// middleware permission tests use). Built-in viewer = tests:view only,
	// engineer = tests:run + tests:view.
	a.rbacRoles[viewerSubject] = []string{rbac.RoleViewer}
	a.rbacRoles[runnerSubject] = []string{rbac.RoleEngineer}

	var mu sync.Mutex
	var commands []string
	s.SetCommandHandler(func(cmd string, args map[string]interface{}) {
		mu.Lock()
		defer mu.Unlock()
		commands = append(commands, cmd)
	})

	srv := httptest.NewServer(s)
	defer srv.Close()
	bearerHeader := func(token string) http.Header {
		return http.Header{"Authorization": []string{"Bearer " + token}}
	}

	// GET /ws only requires tests:view, so the viewer upgrade succeeds. The
	// command-level check must still refuse both start and stop.
	viewer := dialDashboardWSWithHeaders(t, srv, bearerHeader(viewerToken))
	defer viewer.Close()
	_ = readWSCommandFrame(t, viewer) // init
	wsStartJSON(t, viewer, "http://93.184.216.34/")
	assertCommandError(t, readWSCommandFrame(t, viewer), "start")
	if err := viewer.WriteJSON(map[string]any{"type": "stop"}); err != nil {
		t.Fatalf("viewer write stop: %v", err)
	}
	assertCommandError(t, readWSCommandFrame(t, viewer), "stop")

	mu.Lock()
	got := append([]string(nil), commands...)
	mu.Unlock()
	if len(got) != 0 {
		t.Fatalf("viewer dispatched commands = %v, want none", got)
	}

	// A principal with tests:run can drive both commands, and the policy
	// decision is written to the shared audit trail with its WS source marker.
	runner := dialDashboardWSWithHeaders(t, srv, bearerHeader(runnerToken))
	defer runner.Close()
	_ = readWSCommandFrame(t, runner) // init
	wsStartJSON(t, runner, "http://93.184.216.34/")
	waitFor(t, "runner start to dispatch", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(commands) == 1 && commands[0] == "start"
	})
	if err := runner.WriteJSON(map[string]any{"type": "stop"}); err != nil {
		t.Fatalf("runner write stop: %v", err)
	}
	waitFor(t, "runner stop to dispatch", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(commands) == 2 && commands[1] == "stop"
	})

	raw, err := os.ReadFile(audit)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if !strings.Contains(string(raw), "WS start") {
		t.Errorf("audit log has no WS start entry: %s", raw)
	}
	// The decision must be attributable to the authenticated bearer subject,
	// not the process user. Without an explicit Actor the audit falls back to
	// the OS user and a WS start cannot be tied to its caller.
	if !strings.Contains(string(raw), `"actor":"`+runnerSubject+`"`) {
		t.Errorf("audit log has no actor %q for the runner: %s", runnerSubject, raw)
	}
}

// TestRunStartAuditConcurrentHTTPAndWS fires HTTP and WS starts at once and
// verifies the shared trail stays a valid chain. Each entry point opens a
// fresh authz.Log, so this is the real path that exposed the tail()/Write
// race; a broken chain here would mean a tampered-trail false positive.
func TestRunStartAuditConcurrentHTTPAndWS(t *testing.T) {
	audit := isolateWSGateEnv(t)

	const starts = 8
	s := NewServer()
	// onCommand runs only after the gate wrote its audit entry, so one signal
	// per start is a deterministic barrier for "this audit write completed".
	dispatched := make(chan struct{}, starts*2)
	s.SetCommandHandler(func(cmd string, args map[string]interface{}) {
		dispatched <- struct{}{}
	})

	srv := httptest.NewServer(s)
	defer srv.Close()

	var wg sync.WaitGroup
	errs := make(chan error, starts*2)

	for i := 0; i < starts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body := `{"target_url":"http://93.184.216.34/","users":1,"duration_seconds":1}`
			resp, err := http.Post(srv.URL+"/api/run/start", "application/json", strings.NewReader(body))
			if err != nil {
				errs <- err
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				errs <- fmt.Errorf("HTTP start status = %d, want 200", resp.StatusCode)
				return
			}
			select {
			case <-dispatched:
			case <-time.After(5 * time.Second):
				errs <- fmt.Errorf("HTTP start did not reach the handler")
			}
		}()
	}

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	for i := 0; i < starts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
			if err != nil {
				errs <- err
				return
			}
			defer conn.Close()
			_ = readWSCommandFrame(t, conn) // init
			wsStartJSON(t, conn, "http://93.184.216.34/")
			// The handler sends no reply frame, so wait on the dispatch
			// barrier instead of a second read.
			select {
			case <-dispatched:
			case <-time.After(5 * time.Second):
				errs <- fmt.Errorf("WS start did not reach the handler")
			}
		}()
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent run start: %v", err)
	}

	n, err := authz.Verify(audit)
	if err != nil {
		t.Fatalf("concurrent audit chain is invalid: %v", err)
	}
	if n != starts*2 {
		t.Fatalf("verified %d audit entries, want %d", n, starts*2)
	}
}

// TestWSRunDeniedWithCustomAuthMiddleware covers the embedder footgun: a
// custom auth middleware can authenticate and inject roles into the request
// context without populating Server.auth. rbacAllowed cannot evaluate that
// setup, so start/stop must fail closed instead of skipping the tests:run
// check. The intentionally-open dashboard (no middleware) keeps working.
func TestWSRunDeniedWithCustomAuthMiddleware(t *testing.T) {
	isolateWSGateEnv(t)

	s := NewServer()
	s.SetAuthMiddleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(WithPrincipalAndRoles(
				r.Context(), "custom-engineer", []string{rbac.RoleEngineer})))
		})
	})

	var mu sync.Mutex
	var commands []string
	s.SetCommandHandler(func(cmd string, args map[string]interface{}) {
		mu.Lock()
		defer mu.Unlock()
		commands = append(commands, cmd)
	})

	srv := httptest.NewServer(s)
	defer srv.Close()
	conn := dialDashboardWS(t, srv)
	defer conn.Close()
	_ = readWSCommandFrame(t, conn) // init

	wsStartJSON(t, conn, "http://93.184.216.34/")
	assertCommandError(t, readWSCommandFrame(t, conn), "start")
	if err := conn.WriteJSON(map[string]any{"type": "stop"}); err != nil {
		t.Fatalf("write stop: %v", err)
	}
	assertCommandError(t, readWSCommandFrame(t, conn), "stop")

	mu.Lock()
	got := append([]string(nil), commands...)
	mu.Unlock()
	if len(got) != 0 {
		t.Fatalf("custom middleware dispatched commands = %v, want none", got)
	}
}

// TestAuthorizeRunTargetAuditsGateError pins the fail-closed audit path: a
// broken policy makes owaspGate fail before it can return a decision. The run
// is still refused, but the attempt must be recorded as a denied entry with
// the caller's actor and a reason, not silently dropped.
func TestAuthorizeRunTargetAuditsGateError(t *testing.T) {
	dir := t.TempDir()
	badPolicy := filepath.Join(dir, "invalid-policy.json")
	if err := os.WriteFile(badPolicy, []byte("{not-json"), 0o600); err != nil {
		t.Fatalf("write invalid policy: %v", err)
	}
	t.Setenv("SIFT_POLICY", badPolicy)
	t.Setenv("SIFT_ALLOW", "")
	audit := filepath.Join(dir, "audit.jsonl")
	t.Setenv("SIFT_AUDIT_LOG", audit)

	if _, err := authorizeRunTarget("http://93.184.216.34/", "", "WS start", "runner-subject"); err == nil {
		t.Fatal("authorizeRunTarget with an invalid policy succeeded, want fail-closed error")
	}

	raw, err := os.ReadFile(audit)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	line := strings.TrimSpace(string(raw))
	if line == "" {
		t.Fatal("audit log is empty: the failed gate check was not recorded")
	}
	var entry struct {
		Actor   string   `json:"actor"`
		Action  string   `json:"action"`
		Allowed bool     `json:"allowed"`
		Reason  string   `json:"reason"`
		Argv    []string `json:"argv"`
	}
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		t.Fatalf("decode audit entry: %v\n%s", err, line)
	}
	if entry.Actor != "runner-subject" {
		t.Errorf("audit actor = %q, want %q", entry.Actor, "runner-subject")
	}
	if entry.Action != "run" {
		t.Errorf("audit action = %q, want run (OpLoadTest)", entry.Action)
	}
	if entry.Allowed {
		t.Error("audit entry allowed a run despite a failed gate check")
	}
	if !strings.Contains(entry.Reason, "policy check failed") {
		t.Errorf("audit reason = %q, want a policy-check failure", entry.Reason)
	}
}
