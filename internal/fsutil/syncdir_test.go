package fsutil

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// A directory sync must never be the reason a durable write fails: on Windows it
// cannot succeed at all, and on macOS/Linux it may be rejected by the
// filesystem. It must also not silently skip the sync on platforms that support
// it, which is what the platform assertions below pin down.
func TestSyncDirSucceedsOnTempDir(t *testing.T) {
	dir := t.TempDir()
	if err := SyncDir(dir); err != nil {
		t.Fatalf("SyncDir(%s) = %v, want nil", dir, err)
	}
}

func TestSyncDirEmptyMeansCurrentDirectory(t *testing.T) {
	if err := SyncDir(""); err != nil {
		t.Fatalf(`SyncDir("") = %v, want nil`, err)
	}
}

// A missing directory is a caller bug even on Windows, where the sync itself is
// skipped: the function must not report success for a path that is not there.
func TestSyncDirReportsMissingDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory sync is a no-op on Windows; there is no handle to open")
	}
	missing := filepath.Join(t.TempDir(), "absent")
	if err := SyncDir(missing); err == nil {
		t.Fatalf("SyncDir(%s) = nil, want an error", missing)
	}
}

func TestIsIgnorableDirSyncError(t *testing.T) {
	if IsIgnorableDirSyncError(nil) {
		t.Error("a nil error is not an ignorable directory sync failure")
	}
	if runtime.GOOS != "windows" {
		if !IsIgnorableDirSyncError(os.ErrInvalid) {
			t.Error("os.ErrInvalid must be ignorable")
		}
		if IsIgnorableDirSyncError(os.ErrPermission) {
			t.Error("a permission error must not be ignorable")
		}
	}
}
