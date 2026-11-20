package main

import (
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// cleanCmdSource parses a file without comments and prints it back, so a
// stray comment mentioning a security call cannot satisfy an assertion.
func cleanCmdSource(t *testing.T, name string) string {
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

// TestRunUsesAuthzClassAsDialControl pins the CLI run path: the class decided
// by the authorization gate must be installed on every engine socket, otherwise
// a DNS answer that changes after classification can bypass the gate.
func TestRunUsesAuthzClassAsDialControl(t *testing.T) {
	src := cleanCmdSource(t, "cmd_run.go")
	if !strings.Contains(src, "authDecision := enforceAuthz(") {
		t.Fatal("enforceAuthz return value is discarded; no approved class to re-apply")
	}
	if strings.Contains(src, "engine.New(") {
		t.Error("cmd_run.go still calls engine.New without a dial control")
	}
	if !strings.Contains(src, "engine.NewWithControl(scenario, authz.DialControl(authDecision.ClassValue))") {
		t.Error("engine is not built with the gate's approved class as its dial control")
	}
}

// TestDashModeUsesTargetClassAndServerTimeouts covers the in-process dashboard
// launcher: the browser-supplied target must be classified for the dial hook,
// and the HTTP server must bound every phase of a request.
func TestDashModeUsesTargetClassAndServerTimeouts(t *testing.T) {
	src := cleanCmdSource(t, "dash_mode.go")
	if strings.Contains(src, "engine.New(") {
		t.Error("dash_mode.go still calls engine.New without a dial control")
	}
	if !strings.Contains(src, "engine.NewWithControl(sc, control)") {
		t.Error("dash mode run does not build the engine with a dial control")
	}
	if !strings.Contains(src, "authz.DialControl(dashboard.RunTargetClass(cfg.TargetURL))") {
		t.Error("dash mode dial control is not derived from the run target class")
	}
	for _, field := range []string{"ReadTimeout:", "ReadHeaderTimeout:", "WriteTimeout:", "IdleTimeout:", "MaxHeaderBytes:"} {
		if !strings.Contains(src, field) {
			t.Errorf("dash_mode.go http.Server is missing %s", field)
		}
	}
}

// --- dash_mode.go helpers --------------------------------------------------

func TestGetS(t *testing.T) {
	m := map[string]interface{}{
		"name":  "alice",
		"count": 5,
		"flag":  true,
	}
	if got := getS(m, "name"); got != "alice" {
		t.Errorf("getS(name) = %q, want alice", got)
	}
	if got := getS(m, "missing"); got != "" {
		t.Errorf("getS(missing) = %q, want empty", got)
	}
	if got := getS(m, "count"); got != "" {
		t.Errorf("getS(count) = %q, want empty (not a string)", got)
	}
	if got := getS(m, "flag"); got != "" {
		t.Errorf("getS(flag) = %q, want empty (bool not string)", got)
	}
	if got := getS(nil, "any"); got != "" {
		t.Errorf("getS(nil) = %q, want empty", got)
	}
}

func TestGetI(t *testing.T) {
	m := map[string]interface{}{
		"count": 5,
		"ratio": 3.14,
		"name":  "alice",
		"flag":  true,
	}
	if got := getI(m, "count"); got != 5 {
		t.Errorf("getI(count) = %d, want 5", got)
	}
	if got := getI(m, "ratio"); got != 3 {
		t.Errorf("getI(ratio) = %d, want 3", got)
	}
	if got := getI(m, "missing"); got != 0 {
		t.Errorf("getI(missing) = %d, want 0", got)
	}
	if got := getI(m, "name"); got != 0 {
		t.Errorf("getI(name) = %d, want 0 (string not int)", got)
	}
	if got := getI(nil, "any"); got != 0 {
		t.Errorf("getI(nil) = %d, want 0", got)
	}
}
