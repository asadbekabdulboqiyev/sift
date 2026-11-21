package authz

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// TestAuditConcurrentAppendKeepsChain pins the hash-chain fix: callers open a
// fresh Log per entry, so the per-instance mutex alone cannot serialize
// tail()+Write. Without the path-keyed lock, concurrent appends duplicate Seq
// and break PrevHash, which Verify must then reject.
func TestAuditConcurrentAppendKeepsChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	const handles = 8
	const perHandle = 10

	logs := make([]*Log, 0, handles)
	for range handles {
		l, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		logs = append(logs, l)
		defer func(l *Log) { _ = l.Close() }(l)
	}

	var wg sync.WaitGroup
	errs := make(chan error, handles*perHandle)
	for i, l := range logs {
		wg.Add(1)
		go func(i int, l *Log) {
			defer wg.Done()
			for j := 0; j < perHandle; j++ {
				if _, err := l.Append(Entry{
					Action:  "run",
					Targets: []string{fmt.Sprintf("https://h%d.example", i)},
					Allowed: true,
				}); err != nil {
					errs <- err
				}
			}
		}(i, l)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent append: %v", err)
	}

	want := handles * perHandle
	n, err := Verify(path)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if n != want {
		t.Fatalf("verified %d entries, want %d", n, want)
	}
	entries, err := ReadAll(path)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[int64]bool, want)
	for i, e := range entries {
		if seen[e.Seq] {
			t.Errorf("duplicate seq %d", e.Seq)
		}
		seen[e.Seq] = true
		if e.Seq != int64(i+1) {
			t.Errorf("entry %d seq = %d, want %d", i, e.Seq, i+1)
		}
		if i > 0 && e.PrevHash != entries[i-1].Hash {
			t.Errorf("entry %d has a broken PrevHash link", i)
		}
	}
}

func TestAuditChainAppendAndVerify(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := l.Append(Entry{Action: "run", Targets: []string{"https://a.example"}, Class: "public", Allowed: true}); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	n, err := Verify(path)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if n != 3 {
		t.Fatalf("verified %d entries, want 3", n)
	}

	entries, err := ReadAll(path)
	if err != nil {
		t.Fatal(err)
	}
	if entries[0].PrevHash != "" {
		t.Errorf("first entry prev_hash = %q, want empty", entries[0].PrevHash)
	}
	for i := 1; i < len(entries); i++ {
		if entries[i].PrevHash != entries[i-1].Hash {
			t.Errorf("entry %d not chained to previous", i)
		}
		if entries[i].Seq != int64(i+1) {
			t.Errorf("entry %d seq = %d", i, entries[i].Seq)
		}
	}
}

func TestAuditDetectsTampering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, _ := Open(path)
	for i := 0; i < 3; i++ {
		_, _ = l.Append(Entry{Action: "pentest", Targets: []string{"https://t.example"}, Allowed: true})
	}
	l.Close()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Forge the first record: swap the denial to an allow.
	tampered := strings.Replace(string(raw), `"allowed":true`, `"allowed":true,"forged":true`, 1)
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Verify(path); err == nil {
		t.Fatal("Verify accepted a tampered log")
	}
}

func TestAuditResumesChainAfterReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, _ := Open(path)
	_, _ = l.Append(Entry{Action: "run", Allowed: true})
	l.Close()

	l2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	e, err := l2.Append(Entry{Action: "run", Allowed: false})
	l2.Close()
	if err != nil {
		t.Fatal(err)
	}
	if e.Seq != 2 {
		t.Fatalf("seq = %d, want 2", e.Seq)
	}
	if _, err := Verify(path); err != nil {
		t.Fatalf("verify after reopen: %v", err)
	}
}

func TestAuditFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes are not enforced on Windows (Go reports 0666 for any writable file)")
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, _ := Open(path)
	_, _ = l.Append(Entry{Action: "run"})
	l.Close()

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("audit file mode = %o, want 600", perm)
	}
}
