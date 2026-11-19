# Testing

Sift has two test tiers, separated with the Go build tag `integration`.

## Commands

```sh
# Fast tier (default build): unit tests only. No integration tag.
go test ./... -count=1

# Heavy tier: every test, including the files tagged `//go:build integration`.
go test -tags=integration ./... -count=1

# QA focus packages only (the three packages that own the CLI, report and
# attestation regression tests). This is a subset of the fast tier.
go test ./cmd/sift/... ./internal/report/... ./internal/attest/... -count=1
```

The second command includes the first one's tests as well: the tag adds files,
it does not replace them. Use `-p 1` (or `GOFLAGS=-p=1`) with the heavy tier on
a development machine if other work is running at the same time.

## What lives in each tier

The default tier keeps fast, self-contained tests: pure logic, parsing,
rendering, config/profile helpers, and short handler tests against local
`httptest` servers. These finish in well under a second per package and give a
quick signal while editing.

The `integration` tier holds tests that are genuinely slow or resource-hungry:

- multi-second load runs against local targets (`internal/engine`, and the
  in-process CLI run tests in `cmd/sift`);
- distributed master/worker runs over real gRPC listeners
  (`internal/dist/coordinator`);
- live evidence collection and bundle sealing (`internal/evidence`);
- a scanner check that dials fixed ports on a non-loopback target with long
  timeouts (`internal/scanner/owasp`).

The split skipped and deleted nothing. Comparing all `*_test.go` files at the
parent of commit `5b61ef8` with the commit itself gives 2395 `func Test...`
declarations on both sides, with no name removed or added. Each heavy test was
moved verbatim into a sibling `*_integration_test.go` file whose first line is
`//go:build integration`, followed by a blank line as Go requires. Fast tests
stay in the original files, so they keep running in the default build.

## Why the split exists

Two reasons:

1. **Feedback loop.** An unfiltered `go test ./...` took minutes because a
   handful of packages carried all the wall-clock cost (measured locally:
   `internal/engine` 58s, `internal/dist/coordinator` 27s,
   `internal/evidence` 25s, `internal/scanner/owasp` 19s, `cmd/sift` 23s).
   After the split the same default command takes seconds.

2. **Ephemeral port exhaustion.** The load and protocol tests open many
   loopback connections. A macOS host has a default ephemeral range of only
   16 384 ports and a 15 s TIME_WAIT; running those packages at full parallel
   `-p` can exhaust the range, after which unrelated tests fail while dialing
   their own listeners with `EADDRNOTAVAIL`. Isolating the heavy tests, and
   serializing packages with `-p 1`, keeps that contention out of the fast
   tier. No test was changed to work around the symptom.

## Regression coverage for past fixes

The fixes below have executable regression tests. The tests that guard the
implementation live next to the code they cover; the CLI-boundary checks live
in `cmd/sift` and run in the fast tier:

- Run-scoped finding IDs (`fddef83`): `TestVulnScanner_NextVulnIDIsRunScoped`
  and `TestVulnScanner_NextVulnIDIsSequentialPerInstance` in
  `internal/scanner/vuln_scanner_test.go`.
- TLS verification defaults, one-shot opt-out and no sticky flag (`4912aaf`):
  `TestTLSVerifyOptOutIsIsolated` (`internal/scanner/tls/tls_isolation_test.go`),
  `TestSSLTargetOptOutIsOneShotAndIsolated` (`internal/scanner/ssl_optout_test.go`)
  and `TestRenderWarnsOnlyForTheOptedOutChecker`
  (`internal/scanner/owasp/owasp_optout_test.go`). The report side is covered by
  `pentest_confidence_regression_test.go` in `cmd/sift`: confidence is kept out
  of free-text Evidence, the verified/heuristic/unchecked counts are explicit,
  and reports with no confidence metadata keep the legacy verdict.
- Dial-control class ordering (`SEC-A360-01`):
  `dial_control_chain_regression_test.go` in `cmd/sift` checks every adjacent
  pair of the chain public < loopback < private < cgnat < link-local < reserved
  < multicast < metadata through the exported `authz.DialControl` hook.
- Test tier split (`5b61ef8`): verified by the before/after test-count check
  quoted above; no dedicated test function is needed for a file move.

## CI

`.github/workflows/ci.yml` has two dedicated jobs in addition to the existing
race/coverage job:

- `test-unit` runs `go test ./... -count=1`.
- `test-integration` runs `go test -tags=integration ./... -count=1` with
  `GOFLAGS=-p=1`.
