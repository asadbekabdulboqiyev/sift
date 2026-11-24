package main

import (
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// cleanSource parses a source file without comments and prints the AST back.
// Assertions on the printed form cannot be satisfied by a comment that merely
// mentions the required security wiring.
func cleanSource(t *testing.T, name string) string {
	t.Helper()
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	path := filepath.Join(filepath.Dir(here), name)
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var b strings.Builder
	if err := printer.Fprint(&b, fset, file); err != nil {
		t.Fatalf("print %s: %v", path, err)
	}
	return b.String()
}

func TestFlagStringsStringAndSet(t *testing.T) {
	var fs flagStrings
	if fs.String() != "" {
		t.Errorf("String() = %q, want empty", fs.String())
	}

	if err := fs.Set("a"); err != nil {
		t.Fatal(err)
	}
	if err := fs.Set("b"); err != nil {
		t.Fatal(err)
	}
	if err := fs.Set("c"); err != nil {
		t.Fatal(err)
	}

	got := fs.String()
	want := "a,b,c"
	if got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
	if len(fs) != 3 {
		t.Errorf("len(fs) = %d, want 3", len(fs))
	}
	if !strings.Contains(got, "b") {
		t.Errorf("String() = %q does not contain b", got)
	}
}

func TestGetString(t *testing.T) {
	m := map[string]interface{}{
		"name": "hello",
		"age":  30,
	}
	if getString(m, "name", "default") != "hello" {
		t.Error("getString string value wrong")
	}
	if getString(m, "missing", "default") != "default" {
		t.Error("getString missing key wrong")
	}
	if getString(m, "age", "default") != "default" {
		t.Error("getString non-string value wrong")
	}
}

func TestGetInt(t *testing.T) {
	m := map[string]interface{}{
		"count": float64(42),
		"name":  "hello",
	}
	if getInt(m, "count", 0) != 42 {
		t.Errorf("getInt float64 value wrong: %d", getInt(m, "count", 0))
	}
	if getInt(m, "missing", 7) != 7 {
		t.Errorf("getInt missing key wrong: %d", getInt(m, "missing", 7))
	}
	if getInt(m, "name", 99) != 99 {
		t.Errorf("getInt non-numeric value wrong: %d", getInt(m, "name", 99))
	}
}

func TestGetStringMap(t *testing.T) {
	m := map[string]interface{}{
		"headers": map[string]interface{}{
			"Content-Type": "application/json",
			"Count":        float64(5),
			"Active":       true,
			"Other":        []string{"a"},
		},
	}
	out := getStringMap(m, "headers")
	if out == nil {
		t.Fatal("getStringMap returned nil")
	}
	if out["Content-Type"] != "application/json" {
		t.Errorf("getStringMap string value wrong: %q", out["Content-Type"])
	}
	if out["Count"] != "5" {
		t.Errorf("getStringMap float64 value wrong: %q", out["Count"])
	}
	if out["Active"] != "true" {
		t.Errorf("getStringMap bool value wrong: %q", out["Active"])
	}
	if getStringMap(m, "missing") != nil {
		t.Error("getStringMap missing key should return nil")
	}
}

func TestMarkInactive(t *testing.T) {
	active := true
	markInactive(&sync.Mutex{}, &active)
	if active {
		t.Error("markInactive did not set active to false")
	}
}

// TestDashboardServerRequestTimeouts pins the http.Server hardening: a header
// timeout alone still allows an unbounded body and an unbounded write phase.
func TestDashboardServerRequestTimeouts(t *testing.T) {
	src := cleanSource(t, "main.go")
	for _, field := range []string{"ReadTimeout:", "ReadHeaderTimeout:", "WriteTimeout:", "IdleTimeout:", "MaxHeaderBytes:"} {
		if !strings.Contains(src, field) {
			t.Errorf("main.go http.Server is missing %s", field)
		}
	}
}

// TestDashboardStartRunInstallsDialControl pins the DNS-rebinding boundary: the
// run must classify the target and hand the approved class to the engine so the
// socket re-checks the address it actually connects to.
func TestDashboardStartRunInstallsDialControl(t *testing.T) {
	src := cleanSource(t, "main.go")
	if strings.Contains(src, "engine.New(") {
		t.Error("startRun still calls engine.New; it cannot enforce a dial-time class")
	}
	if !strings.Contains(src, "engine.NewWithControl(") {
		t.Fatal("startRun does not call engine.NewWithControl")
	}
	if !strings.Contains(src, "authz.DialControl(") {
		t.Error("startRun does not build an authz dial control")
	}
	if strings.Contains(src, "dashboard.RunTargetClass(") {
		t.Error("startRun uses the legacy fallback classifier; launchers must use the strict form")
	}
	if !strings.Contains(src, "dashboard.RunTargetClassStrict(") {
		t.Error("dial control is not derived from the strict start-run target classification")
	}
	if !strings.Contains(src, "approvedRunDialClass(config.TargetURL)") {
		t.Error("startRun does not refuse the run when target classification fails")
	}
}

// TestDashboardWiresOIDCRoleMap proves the standalone dashboard registers the
// role-map flag and passes it through the shared parser. An unwired map fails
// closed (safe) but silently disables every claim-derived role, so the wiring
// itself must be asserted.
func TestDashboardWiresOIDCRoleMap(t *testing.T) {
	src := cleanSource(t, "main.go")
	if !strings.Contains(src, "auth-oidc-role-map") {
		t.Error("-auth-oidc-role-map flag is not registered")
	}
	if !strings.Contains(src, "dashboard.ParseOIDCRoleMap(authRoleMap)") {
		t.Error("OIDCRoleMap is not populated in AuthOptions via the shared parser")
	}
}
