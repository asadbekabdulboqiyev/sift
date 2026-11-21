# Changelog

All notable changes to Sift are documented here. This file follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) style and semantic
versioning. Entries are taken from git tags and commit history; nothing here is
a promise of future work.

## [Unreleased]

Repository-quality follow-up to v0.18.1. No release tag is assigned to these
changes yet.

### Changed

- Cleared the lint backlog: `golangci-lint run ./...` reports **0 issues**. The
  count went 738 -> 510 -> 145 -> 0 across three phases;
  `docs/LINT-DEBT-TRIAGE.md` records the phases, fixes and justified suppressions.
- CI now lints the whole repository on every run. The `only-new-issues` ratchet
  and its `pull-requests: read` permission were removed from
  `.github/workflows/ci.yml`; the workflow has 15 jobs, gated by a single
  `ci-ok` aggregate that fails if any required job does not succeed.
  `security.yml` and `codeql.yml` gained matching `security-ok` and
  `codeql-ok` aggregates, so branch protection can require one named check
  per workflow.
- Every GitHub Action across all workflows is pinned to a 40-character commit
  SHA with an exact semver comment (verified against the upstream tags);
  Node is pinned to 26.13.1. The `bench` job now runs
  eight samples and fails when any package sec/op median regresses more than
  10% against the previous successful baseline. Fuzz targets run for 180s
  with a stable cache key, and bench/fuzz/docker no longer wait serially on
  `test`. Dockerfiles set `GOTOOLCHAIN=local`, use exact `1.26.11` builder
  images and pin all base images by digest.
- Aggregate test coverage is **76.2%** overall and **78.0%** excluding generated
  `.pb.go` files. The CI coverage gate floor is now 75% (was 70%), and
  `go mod tidy` reports no changes.
- `govulncheck` reports **0 vulnerabilities** in reachable code; the one
  remaining advisory is in a module that is not called by the build.

### Security

- The `load-run` endpoint now goes through the full authorization policy
  (`OpLoadTest`) instead of a partial check, with a named authorization ticket
  and an audit entry.
- Loopback, private, CGNAT, multicast and reserved destinations are rejected.
  Reserved-IP classification was corrected for documentation, benchmarking and
  future-use blocks that Go reports as global-unicast.
- OIDC claim values are no longer used directly as role names. A signed token
  carrying `{"role":"admin"}` cannot grant admin; claim values must be mapped
  to local roles with an operator-managed `oidc_role_map` (or the
  `-auth-oidc-role-map` / `--dashboard-auth-oidc-role-map` flags). The map is
  fail closed: unmapped claims are ignored and mapping to the built-in `admin`
  role is refused. Deployments that relied on raw claim role names must add the
  map or their OIDC users lose those roles.
- VeriGate pass cookies are now `Secure` by default. Plain-HTTP deployments
  must opt out explicitly with `SecureCookies: &false`; the standalone demo
  does so. The previous behavior silently omitted `Secure` behind a
  TLS-terminating proxy.

### Performance

- CVE signatures are compiled once and cached (including invalid patterns),
  cutting a full-signature scan from ~214 us to ~72 us and allocations from
  339 KB / 2,776 allocs to 14 KB / 217 allocs per call.
- Port and directory scans now take the concurrency semaphore before spawning
  a goroutine, removing tens of thousands of blocked goroutines on large ranges
  (cancelled 65k-port scan: 2.58 ms -> 1.8 us).
- Directory title extraction scans bytes in one case-insensitive pass instead
  of lowercasing the whole document twice (5.5 ms -> 59 us on a 4 MB body).
- Live telemetry totals (`TotalRequests`, `TotalErrors`, `RPS`) are O(1) atomic
  reads instead of locking and summing all steps (11.4 us -> 0.3 us).
- JSON path extraction uses direct scalar formatting (1.17 us -> 1.12 us).
- Known limit: scanning a ~1 MB response body through all 94 CVE signatures
  still takes ~1 s of regex work; this is bounded linear matching, not
  catastrophic backtracking, but large bodies remain the dominant CVE cost.

## [v0.18.1] - 2026-11-20

Repository-quality, release-hardening and security patch. Authentication and
certificate-verification defaults changed in this release; those changes are
user-visible and are called out under Security and Changed below.

### Security

- RBAC now evaluates every authenticated request (including GET), path-first
  and fail-closed; admin/audit endpoints require the matching permission.
- Socket-level `authz.DialControl` is installed on CLI and dashboard run paths,
  with proxy destinations rechecked via `authz.CheckDialTarget` to close the
  DNS-rebinding SSRF path.
- Default CSRF same-origin enforcement and a 20 RPS / burst 40 rate limit;
  redirects are pinned to the initial host **and** scheme (no https→http
  downgrade). HTTP read/write/header timeouts added.
- Certificate/attestation trust: reject unsigned v1 envelope fields, derive
  `CertificateID` from signed fields only, expose `issuerTrust` in the attest
  result, and add `VerifyChain` for multi-certificate paths (CWE-347/345).
- HTTP/3 probes verify TLS certificates by default (opt-in bypass only,
  CWE-295); raw IdP token error bodies are redacted (CWE-532).
- Invalid `--target` ports now fail at parse time with exit 2; unknown
  fingerprint profiles no longer panic in `NewDialer`.
- Dashboard authentication (F-01): `sift run --mode dashboard` now accepts
  `--dashboard-auth-oidc`, `--dashboard-auth-rbac` and
  `--dashboard-auth-rbac-enabled`, matching the standalone `sift-dashboard`
  flags. OIDC `issuer:client_id` pairs split on the last colon, so an issuer URL
  with a port works. OIDC and RBAC remain off by default.
- Trust anchor policy (F-02): `sift verify` and `sift certificate` now require a
  trust anchor by default; an unpinned signer is INVALID (exit 1) unless
  `--allow-unpinned` is passed. Conflicting `--require-anchor` /
  `--allow-unpinned` combinations are rejected as usage errors instead of being
  silently weakened.

### Fixed

- Unify the report grade ladder behind `report.GradeForScore` across CLI,
  dashboard, OWASP and vuln scanner; split the inverse CVE scale into
  `SeverityGrade` and rename its JSON key to `cve_risk_score` so the two
  opposing `risk_score` meanings no longer collide.
- Repair CLI subcommand dispatch (lowercase `sift-<name>` paths, idempotent
  prefix handling) and fix broken commands and examples in the docs.
- Preserve error chains with `%w` across scenario parsing, Guard scope checks
  and assertion errors; honour context cancellation in `Guard.Check`.
- `LoadSignals` now distinguishes an absent `signals` key from a present but
  empty one, so the documented single-object JSON shape loads correctly.

### Changed

- Breaking (F-02): `sift verify` / `sift certificate` without an enrolled trust
  store now exit 1 instead of reporting a successful `IssuerUnpinned` verdict.
  The old behavior is available only through the explicit `--allow-unpinned`
  opt-out; self-signed fixtures in `scripts/demo-verified.sh` and
  `scripts/verify-html-parity.sh` pass it deliberately.
- Dashboard OIDC/RBAC can now be configured from `sift run --mode dashboard`
  with `--dashboard-auth-oidc`, `--dashboard-auth-rbac` and
  `--dashboard-auth-rbac-enabled` (previously only `sift-dashboard` exposed
  them).
- Centralize atomic file publication in `internal/shared/atomicfile.Write`
  across 14 writers, preserving each site's durability level, and delegate
  duplicated finding/risk, OWASP, severity and loopback rules to `internal/shared`.
- Decompose high-complexity CLI commands and dashboard routing, and split the
  1518-line `insights.go` into domain files — behaviour-preserving extractions.
- Split protobuf generation into a pinned, byte-reproducible toolchain with a
  CI drift check; drop 13 dead helpers and no-op/import-pin code.
- CI: add `-count=1` (and `-race`) to test jobs so cached results cannot mask
  stale tests; raise the in-workflow coverage gate floor from 45% to 70%; single
  Go version source; repair GoReleaser 422 asset handling and sign/verify
  checksums in the same run. No Codecov upload step is configured.
- Document lint-gating decisions, real DCO 1.1, and honest security/commercial
  claims. At release time 739 pre-existing issues were retained under the
  `only-new-issues` ratchet; that ratchet has since been removed (see
  [Unreleased]). Bus factor of 1 is stated explicitly - still an open risk.

### Added / Coverage

- 68 deterministic tests for hostxray, evidence and dist/coordinator paths.
  Measured coverage: `internal/hostxray` 37.4%→84.1%, `internal/evidence`
  43.2%→90.7%, `internal/dist/coordinator` 57.0%→80.0%.
- Version consistency gate keeps tag, `VERSION` file and source literal aligned;
  README badge, install commands and winget manifests follow the release tag.

Source: derived from `git log v0.18.0..HEAD` (16 DCO-signed commits) and local
verification on 2026-11-20. Remote-only outcomes (CI status, in-workflow
coverage gate, cosign same-run verification) are confirmed on the tagged run.

## [v0.18.0] - 2026-11-19

### Added

- Canonical `internal/finding` model with certificate and audit360 adapters and
  a `verified` / `heuristic` / `unchecked` confidence enum. Legacy finding JSON
  is unchanged.
- Separate fast and heavy test tiers; slow integration tests no longer run in
  the default fast tier.

### Changed

- `vuln_scanner.go` split from 1468 to 305 lines and `dashboard/server.go` from
  1441 to 429 lines, along existing package boundaries with no behavior change.
- Contributor documentation: good-first issues, an ownership map in
  `MAINTAINERS.md`, and a 90-day roadmap. This is documentation only; no second
  maintainer has been appointed and the bus factor is still 1.

### Fixed

- Pentest-to-finding conversion is now idempotent.
- Per-scan TLS opt-out is recorded on the top-level scan result.
- Reliability fixes from this cycle: audit360 stops sending traffic after run
  cancellation, the raw UDP socket is closed after exchange, passive subdomain
  sources are bounded by a timeout context, and the fuzz producer stops on
  context cancellation.
- No legacy load-burst references remain; the gitleaks allowlist matches the
  literal test token only.

### Verified

- `gofmt`, build, `go vet`, fast (64 packages) and integration (64 packages)
  tiers, race tests, and gitleaks (0 leaks).

## [v0.17.0] - 2026-11-18

- Verifiable certificates: pinned trust anchors (`Sift trust ...`), sealed PDFs
  carrying the signed certificate and a SHA-256 digest of the text drawn on
  their pages (`sift-cert-pdf/v1`), and A4 print output.
- Fixed blank certificate PDFs (wrong PDF object names), verdict colors derived
  from a spaced class name, and a nil dereference when printing from an
  assessment alone.
- Added `verify/standalone/sift_verify.py` (standard library only) with golden
  canonical vectors so the Go and Python digests cannot drift silently.

## [v0.16.6] - 2026-11-17

- Patch release. See the tag and the commit history for the exact change set.

## [v0.16.0] - 2026-11-15

- Sift 360-degree 1-click security and capacity audit (tag subject).

## [v0.15.2] - 2026-11-14

- Patch release. See the tag and the commit history for the exact change set.

## [v0.15.0] - 2026-11-13

- Feature release. See the tag and the commit history for the exact change set.

## [v0.14.14] - 2026-11-13

- Completed the rename from the previous project name.

## [v0.14.0] - 2026-09-23

- Feature release. See the tag and the commit history for the exact change set.

## Earlier releases

Tags back to `v0.9.0` are present in the repository. For exact per-commit
detail, use `git log <older-tag>..<newer-tag>` and the tag annotations; this
file does not reconstruct entries that are not recorded there.

Source: `git tag` and `git log` read on 2026-11-19. The v0.18.0 and v0.17.0
entries follow their tag annotations; earlier sections quote only tag subjects
or state that the detail lives in git history.
