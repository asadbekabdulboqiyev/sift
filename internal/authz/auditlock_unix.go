//go:build !windows

package authz

import (
	"os"

	"golang.org/x/sys/unix"
)

// lockFile takes an exclusive advisory lock on the audit file for one Append.
// The in-process path mutex in audit.go is still required: flock is tied to
// the open file description, so two Open calls inside one process are not
// serialized by flock alone. Together they cover both dashboard goroutines
// and a concurrently running CLI writing the same trail.
func lockFile(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_EX)
}

func unlockFile(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_UN)
}
