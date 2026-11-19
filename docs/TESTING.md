# Testing

Sift has two test tiers, separated with the Go build tag `integration`.

## Commands

```sh
# Fast tier (default build): unit tests only. No integration tag.
go test ./... -count=1

# Heavy tier: every test, including the files tagged `//go:build integration`.
go test -tags=integration ./... -count=1
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

Nothing is skipped or deleted. Each heavy test was moved verbatim into a
sibling `*_integration_test.go` file whose first line is
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

## CI

`.github/workflows/ci.yml` has two dedicated jobs in addition to the existing
race/coverage job:

- `test-unit` runs `go test ./... -count=1`.
- `test-integration` runs `go test -tags=integration ./... -count=1` with
  `GOFLAGS=-p=1`.
