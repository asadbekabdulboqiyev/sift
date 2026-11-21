//go:build windows

package authz

import "os"

// Windows has no flock equivalent in this dependency set. The in-process
// path mutex in audit.go still serializes every writer in this process;
// concurrent CLI processes on Windows retain the cross-process residual
// documented in CONTRIBUTING.md.
func lockFile(f *os.File) error   { return nil }
func unlockFile(f *os.File) error { return nil }
