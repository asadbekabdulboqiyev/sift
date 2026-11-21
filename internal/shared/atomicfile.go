// Package shared — atomic file publication.
//
// Every writer that publishes a file a reader may open while it is being
// produced needs the same four steps: create a temp file next to the target,
// write and fsync it, rename it into place, and (for crash-durable artifacts)
// fsync the containing directory so the rename itself survives a power loss.
// Doing those steps inline in a dozen packages produced subtly different
// durability guarantees and error messages; Write is the single copy.
package shared

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/asadbekabdulboqiyev/sift/internal/fsutil"
)

// dirSyncMode controls whether, and how strictly, the containing directory is
// synced after the rename. Syncing the file alone guarantees the bytes are on
// disk; syncing the directory is what makes the *name change* durable.
type dirSyncMode uint8

const (
	// dirSyncNone skips the directory sync entirely. This is the default and
	// matches writers whose data is re-derived on the next run (caches, local
	// UI state, tool output).
	dirSyncNone dirSyncMode = iota //nolint:unused // zero value of dirSyncMode; intentionally has no switch case
	// dirSyncBestEffort attempts the sync but ignores its error, for callers
	// that want the durability on supported filesystems without failing the
	// write on those that reject directory fsync.
	dirSyncBestEffort
	// dirSyncStrict returns a real directory-sync failure to the caller.
	// fsutil.SyncDir already filters out "filesystem does not support this"
	// errors, so strict here means "genuine I/O failure".
	dirSyncStrict
)

// Option configures Write.
type Option func(*options)

type options struct {
	dirSync dirSyncMode
}

// WithDirSync controls the post-rename directory sync.
//
// WithDirSync(true) uses fsutil.SyncDir and returns genuine sync failures.
// WithDirSync(false) still attempts the sync but ignores its error (best
// effort). Omitting the option skips the directory sync. Publishers of
// crash-durable state — signed bundles, keys, trust stores, spools,
// certificates, tamper-evident manifests — should pass true.
func WithDirSync(strict bool) Option {
	return func(o *options) {
		if strict {
			o.dirSync = dirSyncStrict
		} else {
			o.dirSync = dirSyncBestEffort
		}
	}
}

// Write atomically publishes data at path.
//
// The temp file is created with os.CreateTemp in filepath.Dir(path): the name
// is deterministic in shape (hidden, derived from the destination base name)
// while CreateTemp supplies the random suffix that prevents collisions with
// concurrent writers. Keeping it in the destination directory also guarantees
// the final os.Rename never crosses a filesystem boundary.
//
// perm is applied to the temp file before writing and, defensively, to the
// published path afterwards. Pass 0 to leave os.CreateTemp's default 0600
// untouched (matching callers that never chmod at all). Every failure path
// removes the temp file; after a successful rename the destination owns it.
func Write(path string, data []byte, perm fs.FileMode, opts ...Option) error {
	o := options{}
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}

	clean := filepath.Clean(path)
	dir := filepath.Dir(clean)

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(clean)+".tmp-*")
	if err != nil {
		return fmt.Errorf("atomicfile: create temp file for %s: %w", clean, err)
	}
	tmpName := tmp.Name()

	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpName)
		}
	}()

	if perm != 0 {
		if err := tmp.Chmod(perm); err != nil {
			_ = tmp.Close()
			return fmt.Errorf("atomicfile: set mode on temp file for %s: %w", clean, err)
		}
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("atomicfile: write temp file for %s: %w", clean, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("atomicfile: sync temp file for %s: %w", clean, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("atomicfile: close temp file for %s: %w", clean, err)
	}
	if err := os.Rename(tmpName, clean); err != nil {
		return fmt.Errorf("atomicfile: rename %s to %s: %w", tmpName, clean, err)
	}
	committed = true

	if perm != 0 {
		// Rename preserves the temp file's mode on conforming filesystems;
		// re-applying it keeps the original per-caller "chmod after rename"
		// behaviour without changing the result.
		if err := os.Chmod(clean, perm); err != nil {
			return fmt.Errorf("atomicfile: set mode on %s: %w", clean, err)
		}
	}

	switch o.dirSync {
	case dirSyncBestEffort:
		// Best effort by contract: a filesystem without directory fsync must
		// not turn an otherwise successful publish into a failure.
		_ = fsutil.SyncDir(dir)
	case dirSyncStrict:
		if err := fsutil.SyncDir(dir); err != nil {
			return fmt.Errorf("atomicfile: sync directory %s: %w", dir, err)
		}
	}
	return nil
}
