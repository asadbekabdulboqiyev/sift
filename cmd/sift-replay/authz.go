package main

import (
	"os"
	"syscall"

	"github.com/asadbekabdulboqiyev/sift/internal/authz"
	"github.com/asadbekabdulboqiyev/sift/internal/gate"
)

// replayDialControl runs the shared authorization gate and turns its approved
// IPs into the socket-level control installed on every replay transport.
//
// There is deliberately no nil path: a denial exits through the gate's Exit
// hook, and an empty approval set is a fatal infrastructure error. Callers can
// therefore treat a non-nil return as proof that both policy and audit passed.
func replayDialControl(targets []string) func(network, address string, c syscall.RawConn) error {
	out := gate.Enforce(authz.OpReplay, targets, os.Args, currentReplayGateConfig(), replayGateHooks())
	if !out.Allowed {
		// Enforce's Exit hook does not return in production. Fail closed if a
		// test seam ever does.
		exitProcess(gate.DeniedExitCode)
		return nil
	}
	if len(out.ApprovedIPs) == 0 {
		fatalf("Authorization: gate approved no destination addresses")
		return nil
	}
	return authz.ApprovedPeersControl(out.ApprovedIPs...)
}
