package main

import (
	"flag"
	"io"
	"os"

	"github.com/asadbekabdulboqiyev/sift/internal/gate"
	"github.com/asadbekabdulboqiyev/sift/internal/version"
)

var (
	// replayAdminBypass is a seam for in-process tests: nil means "ask the real
	// admin lock store" through the shared gate.
	replayAdminBypass func() bool

	// replayGateConfig is rebound on every main() invocation so tests that run
	// the CLI repeatedly never inherit flags from the previous run.
	replayGateConfig gate.Config
)

// bindReplayGateFlags registers the shared authorization flags. Replay sets
// StrictAudit because a run that resends captured credentials must never be
// allowed when its decision cannot be recorded.
func bindReplayGateFlags(fs *flag.FlagSet) {
	replayGateConfig = gate.Config{
		StrictAudit: true,
		AdminBypass: replayAdminBypass,
	}
	gate.AddFlags(fs, &replayGateConfig)
}

func currentReplayGateConfig() gate.Config {
	cfg := replayGateConfig
	cfg.StrictAudit = true
	cfg.AdminBypass = replayAdminBypass
	return cfg
}

// replayGateHooks supplies this CLI's process seams to the shared gate. The
// functions are read at call time so the in-process test harness can swap them
// just as it does for the rest of main().
func replayGateHooks() gate.Hooks {
	return gate.Hooks{
		Exit: exitProcess,
		Fatal: func(err error) {
			fatalf("Authorization: %v", err)
		},
		Stderr:  func() io.Writer { return os.Stderr },
		Version: version.Full(),
	}
}
