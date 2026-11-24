package authz

// OpReplay is the operation performed by the traffic-replay CLI.
//
// Replay is a distinct operation because it re-sends captured requests verbatim:
// unlike a normal load test it can replay recorded Authorization/Cookie headers
// against hosts the operator never named. It shares pentest's ticket
// requirement for non-public targets (see internal/gate), but public targets
// still follow the policy's ordinary decision.
//
// The value is kept here rather than in the gate so every entry point can name
// the operation without importing a CLI package. This file is additive: the
// existing operations in policy.go are unchanged.
const OpReplay Operation = 3

// IsReplayOperation reports whether op is the replay operation.
func IsReplayOperation(op Operation) bool {
	return op == OpReplay
}
