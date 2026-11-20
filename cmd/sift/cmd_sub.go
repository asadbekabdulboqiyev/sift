package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// subBinaryName renders the on-disk name of a sibling sub-binary. Windows
// resolves executables by extension, so a bare "sift-scan" never
// matches "sift-scan.exe": without this the Windows build would always
// miss the shipped sibling and fall through to `go run`, which a distributed
// binary cannot do.
func subBinaryName(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

// subBinaryCandidates lists the on-disk names a subcommand may be shipped as.
// Release archives use capitalized names (Sift-replay), while local installs
// also create lowercase aliases (sift-replay). Linux is case-sensitive, so
// both must be tried before falling back to the Go toolchain.
func subBinaryCandidates(name string) []string {
	short := subCommandBase(name)
	return []string{"sift-" + short, "Sift-" + short}
}

// subCommandBase strips an optional "sift-" prefix so callers may pass either
// a short name ("replay") or a full binary name ("Sift-replay"). Without this
// a full name would become "sift-sift-replay" and never resolve.
func subCommandBase(name string) string {
	short := strings.ToLower(name)
	return strings.TrimPrefix(short, "sift-")
}

// runSubCommand locates and executes a sub-binary by short name ("replay",
// "scan", ...). It first tries the sibling binary next to the current
// executable, then falls back to `go run` from the project root.
func runSubCommand(name string, args []string) {
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot determine executable path: %v\n", err)
		exitProcess(1)
	}
	exe = filepath.Clean(exe)
	binDir := filepath.Dir(exe)

	for _, candidate := range subBinaryCandidates(name) {
		bin := filepath.Join(binDir, subBinaryName(candidate))
		if _, err := os.Stat(bin); err != nil {
			continue
		}
		// Found standalone binary — run it directly
		cmd := exec.Command(bin, args...) // #nosec G204 G702 -- subcommand name comes from trusted internal dispatch and bin is a sibling executable path.
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			exitFromChild(name, bin, "", err)
		}
		return
	}

	// Fallback: run via `go run`. Package directories are lowercase on disk
	// (cmd/sift-replay), even though the shipped binaries are capitalized.
	short := subCommandBase(name)
	pkg := "./cmd/sift-" + short
	goArgs := append([]string{"run", pkg}, args...)
	cmd := exec.Command("go", goArgs...) // #nosec G204 G702 -- subcommand name comes from trusted internal dispatch; args are forwarded CLI arguments.
	cmd.Dir = findProjectRoot()
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		hint := fmt.Sprintf("Error: %s command failed. Build with: go build -o bin/sift-%s ./cmd/sift-%s\n", name, short, short)
		exitFromChild(name, "", hint, err)
	}
}

// exitFromChild turns a failed child process into a truthful exit status. A
// child that was killed by a signal has no exit code at all — reporting one
// (Go returns -1) hides the cause, and on macOS an invalid ad-hoc signature
// shows up exactly that way: the kernel SIGKILLs the binary at launch.
func exitFromChild(name, bin, hint string, err error) {
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		if hint != "" {
			fmt.Fprint(os.Stderr, hint)
		}
		fmt.Fprintf(os.Stderr, "Error: %s command failed: %v\n", name, err)
		exitProcess(1)
	}
	if sig, killed := killedBySignal(exitErr); killed {
		fmt.Fprintf(os.Stderr, "\nError: %s was killed by a signal (%s) before it could report anything.\n", name, sig)
		if sig.String() == "killed" {
			fmt.Fprintln(os.Stderr, "Hint: macOS kills a binary whose code signature does not match the file on disk.")
			if bin != "" {
				fmt.Fprintf(os.Stderr, "      Re-sign it:  codesign --force --sign - %q\n", bin)
			}
			fmt.Fprintln(os.Stderr, "      Or reinstall everything:  make install")
		}
		exitProcess(signalExitCode(sig))
	}
	if hint != "" {
		fmt.Fprint(os.Stderr, hint)
	}
	exitProcess(exitErr.ExitCode())
}

func cmdReplay()    { runSubCommand("replay", os.Args[2:]) }
func cmdScan()      { runSubCommand("scan", os.Args[2:]) }
func cmdDashboard() { runSubCommand("dashboard", os.Args[2:]) }
func cmdMaster()    { runSubCommand("master", os.Args[2:]) }
func cmdWorker()    { runSubCommand("worker", os.Args[2:]) }

func findProjectRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		return "."
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "."
}
