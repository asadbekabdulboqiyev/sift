package dashboard

// audit360_dialcontrol_test.go — SEC-A360-01. The dashboard audit360 start path
// must carry the gate's approved class into the manager so the scan, engine and
// OWASP dials re-apply the decision to the address the socket actually connects
// to. A name can resolve to a public address during classification and to a more
// restrictive one a moment later at dial time; without the class on the manager
// the gate is only an admission check, not a boundary.

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/audit360"
	"github.com/asadbekabdulboqiyev/sift/internal/authz"
)

// audit360DialControlEnv isolates the policy and audit trail from the real
// install so a test run cannot read or append to a user's files.
func audit360DialControlEnv(t *testing.T) {
	t.Helper()
	t.Setenv("SIFT_HOME", t.TempDir())
	t.Setenv("SIFT_POLICY", "")
	t.Setenv("SIFT_ALLOW", "")
	t.Setenv("SIFT_AUDIT_LOG", "")
}

// selectorChain flattens an expression like decision.ClassValue or
// authz.DialControl into its identifier path, so the wiring assertion does not
// depend on token positions or formatting.
func selectorChain(e ast.Expr) ([]string, bool) {
	switch x := e.(type) {
	case *ast.Ident:
		return []string{x.Name}, true
	case *ast.SelectorExpr:
		prefix, ok := selectorChain(x.X)
		if !ok {
			return nil, false
		}
		return append(prefix, x.Sel.Name), true
	case *ast.CallExpr:
		// Unwrap calls such as context.Background() so chainEquals can match
		// the callee path without caring about the argument list.
		return selectorChain(x.Fun)
	default:
		return nil, false
	}
}

func chainEquals(e ast.Expr, want ...string) bool {
	got, ok := selectorChain(e)
	if !ok || len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// TestAudit360StartPassesGateClassToStartWithControl pins the wiring itself.
// The manager method is concrete and cannot be substituted from this package,
// so the reliable way to prove the approved class reaches audit360 is to parse
// the handler and assert the exact call shape: mgr.StartWithControl(...,
// authz.DialControl(decision.ClassValue)). This fails if the class is dropped,
// hardcoded, or the old Start call is restored.
func TestAudit360StartPassesGateClassToStartWithControl(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	path := filepath.Join(filepath.Dir(file), "audit360.go")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	hasAuthzImport := false
	for _, imp := range parsed.Imports {
		if strings.HasSuffix(strings.Trim(imp.Path.Value, `"`), "/internal/authz") {
			hasAuthzImport = true
		}
	}
	if !hasAuthzImport {
		t.Fatal("audit360.go does not import internal/authz")
	}

	var handler *ast.FuncDecl
	for _, decl := range parsed.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv != nil && fn.Name.Name == "handleAudit360Start" {
			handler = fn
		}
	}
	if handler == nil || handler.Body == nil {
		t.Fatal("handleAudit360Start not found")
	}

	var withControl []*ast.CallExpr
	legacyStarts := 0
	ast.Inspect(handler.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if !chainEquals(sel.X, "mgr") {
			return true
		}
		switch sel.Sel.Name {
		case "StartWithControl":
			withControl = append(withControl, call)
		case "Start":
			legacyStarts++
		}
		return true
	})

	if legacyStarts != 0 {
		t.Fatalf("handleAudit360Start still calls mgr.Start %d time(s); the class boundary must go through StartWithControl", legacyStarts)
	}
	if len(withControl) != 1 {
		t.Fatalf("handleAudit360Start calls mgr.StartWithControl %d time(s), want 1", len(withControl))
	}

	call := withControl[0]
	if len(call.Args) != 6 {
		t.Fatalf("StartWithControl called with %d args, want 6", len(call.Args))
	}
	if !chainEquals(call.Args[0], "context", "Background") {
		t.Fatalf("StartWithControl ctx arg = %s, want context.Background()", renderNode(call.Args[0]))
	}
	controlCall, ok := call.Args[5].(*ast.CallExpr)
	if !ok {
		t.Fatalf("StartWithControl control arg is %T, want authz.DialControl(...)", call.Args[5])
	}
	if !chainEquals(controlCall.Fun, "authz", "DialControl") {
		t.Fatalf("control arg = %s, want authz.DialControl(...)", renderNode(controlCall.Fun))
	}
	if len(controlCall.Args) != 1 {
		t.Fatalf("authz.DialControl called with %d args, want 1", len(controlCall.Args))
	}
	if !chainEquals(controlCall.Args[0], "decision", "ClassValue") {
		t.Fatalf("DialControl class arg = %s, want the gate decision's ClassValue", renderNode(controlCall.Args[0]))
	}
}

// renderNode is only used to make wiring failures readable.
func renderNode(n ast.Node) string {
	var b strings.Builder
	if err := printer.Fprint(&b, nil, n); err != nil {
		return fmt.Sprintf("%T", n)
	}
	return b.String()
}

// TestAudit360GateClassDrivesDialControl proves the value passed by the handler
// is the class the gate actually decided, using a real target through the real
// gate. The resulting control must accept the approved loopback peer and refuse
// a peer in a more restrictive class.
func TestAudit360GateClassDrivesDialControl(t *testing.T) {
	audit360DialControlEnv(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	decision, err := audit360Gate(srv.URL)
	if err != nil {
		t.Fatalf("audit360Gate(%s): %v", srv.URL, err)
	}
	if !decision.Allowed {
		t.Fatalf("audit360Gate(%s) denied an approved target: %+v", srv.URL, decision)
	}
	if decision.ClassValue != authz.ClassLoopback {
		t.Fatalf("gate class = %s, want loopback for %s", decision.ClassValue, srv.URL)
	}

	control := authz.DialControl(decision.ClassValue)
	peer := strings.TrimPrefix(srv.URL, "http://")
	if err := control("tcp", peer, nil); err != nil {
		t.Fatalf("control refused the approved loopback peer %s: %v", peer, err)
	}
	if err := control("tcp", "169.254.169.254:80", nil); err == nil {
		t.Fatal("control allowed instance metadata under a loopback approval")
	}

	// The class is what makes the difference: a public approval would refuse
	// the same loopback peer, so the gate's decision cannot be replaced by a
	// constant without changing behaviour.
	if err := authz.DialControl(authz.ClassPublic)("tcp", peer, nil); err == nil {
		t.Fatal("public approval unexpectedly allowed a loopback peer")
	}
}

// TestAudit360StartWithApprovedTargetStartsJob drives the real handler chain
// with an approved loopback target and confirms the start path still creates and
// tracks a job with the class-carrying call in place.
func TestAudit360StartWithApprovedTargetStartsJob(t *testing.T) {
	audit360DialControlEnv(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	body := fmt.Sprintf(`{"target_url":%q,"mode":"passive","max_duration_sec":10}`, srv.URL)
	req := httptest.NewRequest(http.MethodPost, "/api/audit-360", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s := NewServer()
	s.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("start status = %d, want 202; body=%s", rec.Code, rec.Body.String())
	}
	var out audit360.StartResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode start response: %v; body=%s", err, rec.Body.String())
	}
	if !out.OK || out.JobID == "" {
		t.Fatalf("start response did not create a job: %+v", out)
	}
	if out.StatusURL == "" || out.StreamURL == "" {
		t.Fatalf("start response lost status/stream URLs: %+v", out)
	}

	// The start handler launches the audit in a background goroutine that writes
	// the persistent signing key under SIFT_HOME. Wait for the terminal event so
	// the goroutine finishes writing before t.TempDir cleanup removes the home;
	// otherwise cleanup races the write with "directory not empty".
	ch, cancelSub, ok := s.audit360.Subscribe(out.JobID)
	if !ok {
		t.Fatalf("job %s was not tracked by the manager", out.JobID)
	}
	defer cancelSub()
	deadline := time.After(20 * time.Second)
	for {
		select {
		case ev, open := <-ch:
			if !open {
				t.Fatal("event stream closed before the job reached a terminal state")
			}
			if ev.Type == "completed" || ev.Type == "failed" {
				return
			}
		case <-deadline:
			t.Fatal("job did not reach a terminal state before the deadline")
		}
	}
}
