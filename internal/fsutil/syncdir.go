// Package fsutil holds the small filesystem helpers shared by the code that
// must make a write durable before it returns: manifest writers, spool files,
// signed bundles and certificate stores all publish data by writing a temp file,
// syncing it, renaming it into place and then syncing the directory so the
// rename itself survives a crash.
//
// It lives in one package because that last step is the only platform-specific
// part, and the same four bugs kept reappearing in separate copies of it:
//
//   - Windows cannot flush a directory handle at all (FlushFileBuffers fails
//     with "Access is denied"), so a directory sync must be a no-op there
//     instead of an error every writer has to special-case.
//   - On Linux, several filesystems (tmpfs, overlayfs, some network mounts)
//     reject directory fsync with EINVAL or ENOTSUP; that is a property of the
//     filesystem, not a failed write, so it is not fatal.
package fsutil

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// SyncDir fsyncs the directory that contains a just-renamed file so the rename
// is durable on platforms where directory entries need an explicit sync.
//
// On Windows the call is a no-op: the platform has no way to flush a directory
// handle, so the rename's durability is bounded by the file sync the caller
// already performed. Errors from filesystems that do not implement directory
// fsync are treated as success for the same reason.
func SyncDir(dir string) error {
	if dir == "" {
		dir = "."
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	f, err := os.Open(filepath.Clean(dir))
	if err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		if IsIgnorableDirSyncError(err) {
			return nil
		}
		return err
	}
	return f.Close()
}

// IsIgnorableDirSyncError reports whether a directory sync failure means "this
// platform or filesystem does not support the operation" rather than "the data
// may not be durable".
func IsIgnorableDirSyncError(err error) bool {
	if err == nil {
		return false
	}
	if runtime.GOOS == "windows" {
		return true
	}
	msg := strings.ToLower(err.Error())
	return errors.Is(err, os.ErrInvalid) ||
		strings.Contains(msg, "invalid argument") ||
		strings.Contains(msg, "not supported") ||
		strings.Contains(msg, "inappropriate ioctl") ||
		strings.Contains(msg, "operation not supported")
}
