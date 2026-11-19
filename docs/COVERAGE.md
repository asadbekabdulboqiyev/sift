# Coverage — Baseline and Policy

This document tracks test coverage status and policy for Sift.

## Baseline (2026-11-05)

| Metric | Value | Notes |
|---|---:|---|
| Aggregate suite (`go test ./... -covermode=atomic -coverpkg=./...`) | **58.7%** | Measured with `-coverpkg=./...`; `-cover` alone only counts the target package |
| Higher-coverage packages (examples) | `attest` 81.9%, `otel` 80.2%, `otel/exporter` 98.0%, `probe` 97.1%, `honor` 94.0%, `rbac` 100.0%, `demostore` 79.1%, `metrics/exporter` 98.0% | Cryptographic/governance-related packages are relatively strong |
| Lower-coverage real packages (examples) | `store/postgres` 78.6%, `siem` 89.0%, `report` 88.8%, `secrets` 91.7%, `legal` 74.6%, `metrics` 81.5% | Varies by subsystem |
| Uncovered/low-covered areas (real code) | `store/memstore` 0%, `tenant` 0%, `version` 0%, `auditdb` 0%, parts of `replay/pcap`, engine internals | Requires targeted tests |
| CLI entrypoints (`cmd/*/main.go`) | 0.0% | Expected; `main()` is typically not exercised by unit tests |

## Current measurement (2026-11-17)

| Metric | Value | How it was measured |
|---|---:|---|
| Aggregate suite | **75.7%** | CI `Coverage gate` job, run [44087015007](https://github.com/asadbekabdulboqiyev/sift/actions/runs/44087015007) on commit `6e65195` |
| Measurement mode | `-race -covermode=atomic -coverpkg=./...` | `test` job produces one profile per package; the gate merges them and runs `go tool cover -func` |
| Floor enforced in CI | 45% | `.github/workflows/ci.yml` |

The 45% CI gate is a minimum floor; measured coverage is higher (75.7% above).
The project target is tracked in `CONTRIBUTING.md`.

The 2026-11-05 baseline (58.7%) and this figure are not a like-for-like
comparison of the same commit: tests were added between the two dates, and the
CI gate merges per-package profiles instead of using a single `go test ./...`
run. The number above is the one CI actually enforces against, so it is the
number quoted when the project states its coverage.

## Local coverage commands

```bash
# Full test run with race detector and aggregate coverage profile
go test -race -timeout 20m -covermode=atomic -coverprofile=coverage.out -coverpkg=./... ./...

# Show aggregate coverage percentage
go tool cover -func=coverage.out | tail -1

# List uncovered functions/files hotspots
go tool cover -func=coverage.out | grep '0.0%'
```

## CI policy

The `coverage` job in `.github/workflows/ci.yml`:

1. Collects `coverage-*.out` artifacts produced by the `test` job (`-coverpkg=./...`).
2. Computes aggregate coverage using `go tool cover -func`.
3. Fails if coverage is below the configured floor (**45%**).

The `test` job runs `go test -race -covermode=atomic -coverpkg=./... ./...`, so coverage artifacts and aggregate checks are based on the same measurement mode.

## Follow-up goals

- Maintain and improve the baseline (58.7%) over time; document meaningful floor changes in this file.
- Add unit/integration tests for currently uncovered real-code packages (e.g. `store/memstore`, `tenant`, `version`, `auditdb`) where practical.
- Treat `main()` coverage gaps as expected unless an integration test strategy is added.
- Monitor flaky behavior in race/coverage runs (especially `internal/engine`) and stabilize tests as needed.

## Test determinism (measured 2026-11-17)

The suite is not safe to run at full package parallelism on every host, and the
reason is environmental rather than a test-ordering bug:

| Observation | Measurement |
|---|---|
| `go test ./...` (all ~60 packages at once, macOS) | 3 of 60 packages failed: `cmd/sift`, `internal/engine`, `internal/evidence` |
| Failure mode | dial-time `connect: can't assign requested address` (EADDRNOTAVAIL) against `127.0.0.1` listeners that were already up |
| Same packages in isolation | all pass (`go test ./internal/engine -run 'TestWS\|TestGrpc'` = ok) |
| `go test -p 1 ./...` before the dial fix | mostly green, but `internal/dist/coordinator` still flaked at the end of a saturated run (2 tests, the same EADDRNOTAVAIL while dialling its own workers) |
| `go test -p 1 ./...` after the dial fix | two consecutive clean runs: exit 0, 61 packages ok, 0 failures (≈4 min each) |
| Host limits | `net.inet.ip.portrange = 49152-65535` (16 384 ports), `net.inet.tcp.msl = 15000` (15 s TIME_WAIT) |

The load generators and protocol tests in this repository open thousands of
loopback connections; at `-p 4` and above they collectively exhaust the
ephemeral port range, so unrelated packages fail while dialling. Nothing in the
product or the tests is skipped to make this go away — `make test` runs the same
tests, just with bounded package parallelism (`TEST_P`, default `1`). Use
`make test TEST_P=8` on a host with a wider range, or `make test-short` to drop
`-race` for a faster local loop.

`make verify` runs the same bounded parallelism (it used to call a bare
`go test ./...`, which reintroduced the very flake the target exists to catch)
and ends with the gosec ratchet instead of "zero findings". The old check could
never pass: the five remaining findings are MEDIUM `G304` file-inclusion hits,
which the documented ratchet policy allowlists by design, so a clean tree was
reported as a failure.

The coordinator was the last package that still failed at `-p 1`. Its
master→worker dial is now a context dialer that retries only `EADDRNOTAVAIL`
(and `EADDRINUSE` on stacks that report the same source-port pressure) inside
the existing 5 s Ping deadline; every other dial error still fails fast
(`dialWorker` in `internal/dist/coordinator/master.go`). The retry loop is
bounded by wall-clock time, not an attempt count: gRPC hands the dialer its own
connect context (≈20 s), so a count-based bound could stall one connect attempt
for minutes and suppress gRPC's own backoff. One liveness test also waited for
its gRPC listener before probing it — gRPC is fail-fast by default, so a Ping
that raced a not-yet-serving listener marked a healthy worker dead under
repeated runs. No test is skipped or shortened.

Stress beyond the CI setting exposed a second, real defect in the tests
themselves, and it is fixed rather than documented away. `go test
./internal/dist/coordinator -count=5` used to fail 3 of 5 iterations with
`connect: can't assign requested address` inside a readiness Ping.
Instrumenting the run showed why: for about 8 seconds the whole host could not
open a loopback connection at all (a probe issuing 100 dials failed 100/100),
because the unpaced load tests in that package opened far more connections than
the 16 384-port range can hold in TIME_WAIT. `tinyScenario` now paces its runs
at 100 req/s — these tests assert coordinator semantics, not throughput — and
the same package then passed six consecutive `-count=1` runs and a `-count=5`
stress run with zero EADDRNOTAVAIL. The same probe run alongside the paced
suite reports no dial failures at any point.

Two real cross-platform defects were found through the same CI runs and are
fixed in code rather than in the harness:

- Directory `fsync` is now a no-op on Windows (`internal/fsutil.SyncDir`).
  Windows cannot flush a directory handle, so every writer that synced its
  output directory failed there with `sync <dir>: Access is denied` — five
  packages were red on `windows-latest` because of it.
- Paths are compared case-sensitively in tests (`cmd/sift`, not `cmd/Sift`;
  `packaging/homebrew/sift.rb`, not `Sift.rb`). macOS hides this; Linux and
  Windows do not.

## Notes

- `-coverpkg=./...` measures coverage across packages, not just the package under test.
- `-covermode=atomic` is used for race-safe coverage accounting; compare results consistently using the same mode/settings.
