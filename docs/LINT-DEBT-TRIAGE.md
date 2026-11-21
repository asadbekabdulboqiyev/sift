# LINT DEBT TRIAGE — sift

**Measurement:** 2026-11-20, HEAD `773fa56` (main), golangci-lint v2.14.0 (go1.26.11).
**Total:** 738 issues, 138 `.go` files. The tool ran, and the numbers are taken from the actual report output.
**Update (2026-11-21):** After Phase 1, **510** issues remain — see §7.

## 1. Measurement method and configuration

```sh
golangci-lint run ./... \
  --output.json.path=<tmp>/sift-lint.json \
  --issues-exit-code 0
```

- Configuration: `.golangci.yml` (standard + `errcheck`, `gocritic`, `gosec`, `govet`,
  `ineffassign`, `misspell`, `revive`, `staticcheck`, `unconvert`, `unused`;
  formatters `gofmt`, `goimports`). `govet`, `misspell`, `gofmt` — **0** issues.
- `--issues-exit-code 0` only changes the exit code; it does not affect the number of issues.
- `max-issues-per-linter: 0`, `max-same-issues: 0` — nothing was truncated;
  `uniq-by-line` is at its default. The JSON report contains exactly 738 objects.
- Clarification: the comment at `.golangci.yml:73-78` records **755** for HEAD `605dc57`;
  the current HEAD has **738** (-17). The `only-new-issues: true` ratchet is actually
  in `.github/workflows/ci.yml:71` (`golangci-lint-action@v7`); in `.golangci.yml`
  only a comment exists.

## 2. By linter

| Linter | Count | Share | Nature | Example (`file:line`) |
|---|---:|---:|---|---|
| errcheck | 365 | 49.5% | mostly noise, a small part is worth checking | `internal/report/report.go:212` |
| revive | 172 | 23.3% | pure style / API naming | `internal/audit360/manager.go:36` |
| staticcheck | 118 | 16.0% | mixed: quickfix + genuine SA findings | `cmd/sift/cmd_pentest_generate.go:67` |
| gocritic | 32 | 4.3% | style | `cmd/sift/cmd_pentest_generate.go:205` |
| unused | 28 | 3.8% | dead code (17 of them in tests) | `cmd/sift-master/main.go:48` |
| goimports | 8 | 1.1% | auto-format | `cmd/sift/cmd_pentest_generate.go:10` |
| ineffassign | 6 | 0.8% | genuine, minor | `cmd/sift-worker/main.go:300` |
| gosec | 5 | 0.7% | 4 are false positives/low risk, 1 hardening | `internal/attest/trust.go:339` |
| unconvert | 4 | 0.5% | style | `cmd/sift-dashboard/main.go:383` |

## 3. By rule (738 issues)

| Rule | Count | Share |
|---|---:|---:|
| errcheck (all) | 365 | 49.5% |
| revive / exported-comment | 152 | 20.6% |
| staticcheck QF1012 (`WriteString(fmt.Sprintf(...))`) | 72 | 9.8% |
| unused | 28 | 3.8% |
| gocritic ifElseChain | 25 | 3.4% |
| revive / stutter | 16 | 2.2% |
| goimports | 8 | 1.1% |
| staticcheck QF1001 (De Morgan) | 7 | 0.9% |
| staticcheck S1009 (redundant nil check) | 7 | 0.9% |
| ineffassign | 6 | 0.8% |
| gosec (G602×2, G304×2, G301×1) | 5 | 0.7% |
| staticcheck SA9003 (empty branch) | 5 | 0.7% |
| staticcheck SA1019 (deprecated API) | 5 | 0.7% |
| gocritic singleCaseSwitch | 4 | 0.5% |
| revive / comment-format | 4 | 0.5% |
| unconvert | 4 | 0.5% |
| remaining 18 rules (SA6002×3, S1031×3, SA4009×2, S1039×2, S1024×2 and 1 each) | 25 | 3.4% |

## 4. Genuine issue or style/noise

| Category | Count | Assessment and rationale | Example |
|---|---:|---|---|
| errcheck / `fmt.Fprint*` | 323 | 88.5% of errcheck: 288 `w`, 18 `out`, 11 `pt.out`, 4 `tw`, 1 `w.out`, 1 `os.Stdout`. Writing to an output stream; signatures like `Render(w io.Writer)` do not return an error → **mostly noise**, but `io.Writer` errors (closed pipe, disk full) are hidden | `internal/report/report.go:212` |
| errcheck / `Close` + `RemoveAll` | 42 | 41 `defer x.Close()` + 1 `defer os.RemoveAll(tmpDir)` → a resource-cleanup error may be hidden, **needs review** | `internal/dashboard/insights_bounty.go:332`, `cmd/sift-worker/main.go:296` |
| revive / exported-comment | 152 | **Pure style**: only missing doc comments. 33 files, 21 of them in `internal/metrics/metrics.go` | `internal/audit360/manager.go:36` |
| QF1012 | 72 | **Style/auto-fix**: 6 files, 40 of them in `cmd_pentest_generate.go`; behavior does not change (`strings.Builder` does not return an error on write) | `cmd/sift/cmd_pentest_generate.go:67` |
| unused | 28 | 17 in tests; 11 in production: dead code/flag → **genuine**, but safe to remove | `cmd/sift-master/main.go:48` (`timeline` flag is not read) |
| ifElseChain / singleCaseSwitch | 29 | **Style**, low refactor risk | `cmd/sift/cmd_pentest_print.go:437` |
| revive / stutter | 16 | Requires changing exported names → **risk of API breakage**, better to leave it for now | `internal/certificate/certificate.go:659` |
| gosec | 5 | G602×2 — **false positive** (`if i == 0 { continue }` in `certificate.go:723` and `if i <= 0` in `hostxray/report.go:408`); G304×2 — **dev-only** (`SIFT_DASHBOARD_DEV_ASSETS=1`, names hardcoded: `index.html`, `style.css`); G301 — 0o755 → **minor hardening** | `internal/attest/trust.go:339` |
| SA1019 | 5 | **Genuine**: deprecated `crypto/ecdsa.PublicKey.X/Y` (Go 1.26), `elliptic.Curve.IsOnCurve`, `http2.Transport` | `internal/oidc/oidc.go:545` |
| SA9003 / SA6002 / SA4009 | 10 | **Genuine signal**: empty branches, `sync.Pool.Put([]byte)` allocation, `ctx` overwritten before use | `internal/store/memstore/memstore.go:55`, `internal/engine/buffer_pool.go:97` |

## 5. Phase 1 proposal: the 3 rules producing the most issues

| Rule | Eliminated | Total share | Workload (estimate) | Risk |
|---|---:|---:|---|---|
| errcheck (365) | 365 | 49.5% | 48 files: express 323 `Fprint*` calls as `_ = fmt.Fprint*(...)` or with a single helper; audit the 42 `Close`/`RemoveAll` cases separately — **1-2 person-days + review** | low, but the explicit hiding of write errors must be documented |
| revive / exported-comment (152) | 152 | 20.6% | add doc comments to 33 files — **~0.5-1 person-days** | negligible (comments only) |
| QF1012 (72) | 72 | 9.8% | in 6 files, `WriteString(fmt.Sprintf(...))` → `fmt.Fprintf(&b, ...)`; can try with `--fix` (on a scratch branch) — **~0.5 person-days** | low |

**Total: 589 / 738 = 79.8%** of issues will be eliminated; 149 remain (20.2%).
Recommended execution order: QF1012 → revive comment → errcheck (the largest, but touches the most files).

## 6. Why the `only-new-issues` ratchet was kept during cleanup (resolved in §9)

1. The 738 existing findings are spread across 138 files; without the ratchet, **every** PR would be red in the lint job,
   and the CI signal is lost because of debt unrelated to the change.
2. The ratchet surfaces **all** new issues (CI used `only-new-issues: true`), so regressions are not hidden —
   only old debt does not block.
3. The 755 → 738 dynamic recorded in the `.golangci.yml` comment shows that the debt is decreasing, but still far from 0;
   even if Phase 1 alone covers 79.8%, 149 remain.
4. Removal criteria: `golangci-lint run ./...` yields **0 issues** (or explicit, documented suppressions for all debt
   rules) and several consecutive CI runs pass green.

**Resolution:** the criteria in item 4 were met at the end of Phase 3 (§9). The ratchet and its
`pull-requests: read` permission were removed from `.github/workflows/ci.yml`; CI now lints the whole
repository on every run.

## 7. Phase 1 completed (2026-11-21)

4 parallel agents worked across 44 files. Result: **735 → 510** issues (-225, -30.6%).

| Linter | Before | After | Notes |
|---|---:|---:|---|
| staticcheck | 116 | 44 | **QF1012 72 → 0** (all converted to `_, _ = fmt.Fprintf(&b, ...)`; the errcheck count did not increase) |
| revive | 172 | 19 | **exported-comment 152 → 0** (doc comments added); the remaining 19 are mainly `stutter` (risk of API breakage, deliberately left untouched) |
| errcheck | 365 | 365 | deferred to Phase 2 (§5) |
| gocritic / unused / goimports / ineffassign / gosec / unconvert | 82 | 82 | deferred to Phase 2 |

Verification: `gofmt`, `go vet ./...`, `go build ./...`, `go test`, `go test -race`, integration,
`gitleaks`, `actionlint`, `helm lint`, `goreleaser check` — all PASS.

**Ratchet not removed yet:** 510 debt issues remain (the §6 criteria are not met).

## 8. Phase 2 completed (2026-11-21): errcheck

4 parallel agents worked across all 48 files with errcheck findings. Result: **510 → 145** issues (-365),
with **errcheck 365 → 0**. No other linter count changed, so no new issues were introduced.

| Agent scope | Files | Findings fixed |
|---|---:|---:|
| `internal/report` + `internal/cliux` | 3 | 87 |
| `cmd/sift` pentest/network printers | 6 | 124 |
| `cmd/sift` misc + worker + examples | 13 | 101 |
| `internal/*` (engine, dashboard, scanner, ...) | 26 | 53 |
| **Total** | **48** | **365** |

Handling breakdown across the whole phase:
- **323** `fmt.Fprint*` calls made explicit as `_, _ = fmt.Fprint*(...)`. All target `io.Writer`,
  `tabwriter.Writer`, `strings.Builder`, or `os.Stderr`; the enclosing functions do not return an error,
  so behavior and output text are unchanged.
- **42** cleanup calls made explicit: 39 deferred `Close()` calls rewritten as
  `defer func() { _ = x.Close() }()`, 1 `os.RemoveAll(tmpDir)` and 2 direct `Close()` discarded with `_ =`.
  One deferred TCP connection in `cmd/sift-worker/main.go` uses a value-capturing closure
  (`func(c *grpc.ClientConn) { _ = c.Close() }(conn)`) because `conn` is reassigned later; this preserves
  the original defer-time receiver. No cleanup error could be propagated without changing behavior.
- **0** errors newly caught or handled; **0** logic, message, or test changes.

Verification: `gofmt`, `go vet ./...`, `go build ./...`, `go test`, `go test -race`, integration tests,
`gitleaks` (no leaks), `actionlint`, `git diff --check`, and English-only / absent-term scans — all PASS.

Remaining: **145** issues (gocritic 31, staticcheck 44, unused 28, revive 19, goimports 8,
ineffassign 6, gosec 5, unconvert 4). **Ratchet not removed yet:** the §6 criteria are not met.

## 9. Phase 3 completed (2026-11-21): lint debt to zero

4 parallel agents worked across 91 files. Result: **145 → 0** issues. Every remaining finding from §8 was
resolved; `golangci-lint run ./...` now reports **0 issues**.

| Agent scope | Files | Findings fixed |
|---|---:|---:|
| `cmd/*` + `examples/*` | 19 | 25 |
| `internal/scanner/*` + `hostxray` + `fingerprint` + `honesty` | 25 | 45 |
| `dashboard` + `report` + `replay` + `evidence` + `cliux` + `shared` + `store` | 22 | 34 |
| `engine` + `twin` + `oidc` + `certificate` + `attest` + `audit360` + `bounty` + `config` + `dist` | 25 | 41 |
| **Total** | **91** | **145** |

Breakdown of the cleared backlog: staticcheck 44, gocritic 31, unused 28, revive 19, goimports 8,
ineffassign 6, gosec 5, unconvert 4.

Real fixes (not suppressions):
- **Real bug — `exitAfterDefer`** in `cmd/sift-scan/main.go`: `enforceScanAuthz` called `os.Exit` while a
  deferred `context.WithTimeout` cancel was pending, so the cancel never ran. The function now returns
  `(class, allowed, error)`; `main` owns all exits, so the deferred cancel runs on success, denial and error
  paths. Exit codes and user-facing messages are unchanged.
- **SA4000** in `owasp/owasp_test.go`: a mock login check tested `"admin"` twice; it now checks distinct
  `"username":"admin"` and `"password":"admin"` JSON fields.
- **SA1019 (crypto/elliptic)** in `oidc/oidc.go`: raw `IsOnCurve` / `PublicKey.X,Y` JWK validation was migrated to
  `ecdsa.ParseUncompressedPublicKey(elliptic.P256, point)` with explicit 256-bit coordinate guards. The test
  JWK helper now derives points from `pub.Bytes()` instead of deprecated raw coordinates. Security checks and
  error text are unchanged; no suppression was used.
- **SA6002 (sync.Pool)** in `engine/buffer_pool.go`: tiers now store `*[]byte` so `Put` needs no boxing
  allocation; `ReusableBuffer` gained a `slot` header and `Get` delegates to `GetMinSize`. Both sides of each
  pool were changed together; confirmed by the full race suite.
- **G301** in `attest/trust.go`: trust-store directory mode hardened from `0o755` to `0o750`.
- **SA9003 / ineffassign / unconvert / goimports / mechanical gocritic and staticcheck fixes** were applied
  where behavior was provably unchanged (no-op branches removed, redundant conversions and assignments dropped,
  `if`-`else` chains rewritten as `switch`, imports regrouped).

Justified suppressions (all inline, with reasons; no exported name was renamed):
- **revive stutter (19)**: exported identifiers kept to avoid breaking the public API.
- **gosec G602 (2)**: index accesses in `hostxray/report.go` and `certificate/certificate.go` are guarded by
  preceding bounds checks — false positives.
- **gosec G304 (2)**: `dashboard/static.go` dev-only asset reads behind `SIFT_DASHBOARD_DEV_ASSETS=1` with
  hardcoded filenames — false positives.
- **staticcheck SA1019 (1)**: `engine/enhanced_clients_test.go` keeps a deliberate no-op referencing
  `x/net/http2` to link the package; replacing it would drop that link.
- **unused (several)**: helpers used only by `//go:build integration` tests are invisible to the default lint
  build; deleting them would break the integration suite. `dirSyncNone` is the iota zero value used by `options{}`;
  deleting it would renumber durability modes and change the default.

Verification (all PASS): `gofmt -l`, `go vet ./...`, `go build ./...`, `go test -count=1 ./...`,
`go test -race -count=1 ./...`, integration compile plus `go test -race -tags=integration ./...`,
`golangci-lint run ./...` (0 issues), `gitleaks` (no leaks), `actionlint`, `git diff --check`, and the English-only /
absent-term scans (both clean).

**Ratchet removed:** with the backlog at 0, `only-new-issues: true` and its `pull-requests: read` permission were
deleted from `.github/workflows/ci.yml`; CI now fails on any lint finding in any file. Related comments in
`.golangci.yml` were updated to describe the full-repo lint policy.

## Limitations

- This report was created on 2026-11-20; §7 adds Phase 1, §8 adds Phase 2 and §9 adds Phase 3 results dated
  2026-11-21. The `only-new-issues: true` ratchet was removed from CI in Phase 3 (§9); `.golangci.yml` comments
  were updated accordingly.
- The count was taken with `.golangci.yml` exclusions in place: errcheck/gosec/gocritic in tests are excluded
  (the comment records that removing the exclusions was measured at **+295** additional findings — this number
  is not included in the present measurement); `.pb.go` and two scanner files are also excluded. Full gosec runs only
  in a separate `security` CI job with a baseline.
