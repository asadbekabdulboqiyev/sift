package shared

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tempLeftovers lists the hidden temp files Write creates next to a target.
// A successful or failed publish must always leave none behind.
func tempLeftovers(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}
	var names []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") && strings.Contains(name, ".tmp-") {
			names = append(names, name)
		}
	}
	return names
}

func TestWriteCreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "artifact.json")
	want := []byte(`{"ok":true}` + "\n")

	if err := Write(path, want, 0o600); err != nil {
		t.Fatalf("Write(%s) = %v, want nil", path, err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(got) != string(want) {
		t.Errorf("content = %q, want %q", got, want)
	}
	if left := tempLeftovers(t, dir); len(left) != 0 {
		t.Errorf("temp files left after success: %v", left)
	}
}

func TestWriteReplacesExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "artifact.json")
	if err := os.WriteFile(path, []byte("old contents that are longer"), 0o600); err != nil {
		t.Fatalf("seed %s: %v", path, err)
	}

	want := []byte("new")
	if err := Write(path, want, 0o600); err != nil {
		t.Fatalf("Write(%s) = %v, want nil", path, err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(got) != string(want) {
		t.Errorf("content = %q, want %q (old bytes must not remain)", got, want)
	}
	if left := tempLeftovers(t, dir); len(left) != 0 {
		t.Errorf("temp files left after replace: %v", left)
	}
}

func TestWritePreservesPermissions(t *testing.T) {
	dir := t.TempDir()
	for _, perm := range []os.FileMode{0o600, 0o640, 0o644, 0o755} {
		path := filepath.Join(dir, "mode-"+perm.String())
		if err := Write(path, []byte("x"), perm); err != nil {
			t.Fatalf("Write(%s, %o) = %v, want nil", path, perm, err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if got := info.Mode().Perm(); got != perm {
			t.Errorf("%s mode = %o, want %o", path, got, perm)
		}
	}
}

// Writing over a directory makes os.Rename fail *after* the temp file was
// created, written and synced — the exact path where a deferred cleanup must
// run. On Windows the error type differs, so only the observable contract
// (error returned, no temp file left) is asserted.
func TestWriteCleansUpTempFileOnRenameError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "target")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("create target directory: %v", err)
	}

	err := Write(path, []byte("payload"), 0o600)
	if err == nil {
		t.Fatalf("Write over a directory = nil, want an error")
	}
	// os.Rename reports EEXIST/EISDIR as *os.LinkError on Unix and as
	// *os.PathError on Windows; both must survive the %w chain.
	var linkErr *os.LinkError
	var pathErr *os.PathError
	if !errors.As(err, &linkErr) && !errors.As(err, &pathErr) {
		t.Errorf("error %v does not wrap an *os.LinkError or *os.PathError", err)
	}
	if !strings.Contains(err.Error(), "atomicfile") {
		t.Errorf("error %v is missing the atomicfile context", err)
	}
	if left := tempLeftovers(t, dir); len(left) != 0 {
		t.Errorf("temp files left after rename error: %v", left)
	}
}

func TestWriteReportsTempCreationError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent", "artifact.json")
	err := Write(missing, []byte("x"), 0o600)
	if err == nil {
		t.Fatalf("Write into a missing directory = nil, want an error")
	}
	var pathErr *os.PathError
	if !errors.As(err, &pathErr) {
		t.Errorf("error %v does not wrap *os.PathError", err)
	}
}

func TestWriteDirSyncModes(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name string
		opts []Option
	}{
		{"default", nil},
		{"strict", []Option{WithDirSync(true)}},
		{"best-effort", []Option{WithDirSync(false)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name+".json")
			if err := Write(path, []byte("data"), 0o600, tc.opts...); err != nil {
				t.Fatalf("Write(%s) = %v, want nil", path, err)
			}
		})
	}
}
