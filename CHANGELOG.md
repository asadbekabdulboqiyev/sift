# Changelog

All notable changes to Sift are documented here. This file follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) style and semantic
versioning. Entries are taken from git tags and commit history; nothing here is
a promise of future work.

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
  stale tests; raise the Codecov coverage floor from 45% to 70% with fail-closed
  upload; single Go version source; repair GoReleaser 422 asset handling and
  sign/verify checksums in the same run.
- Document lint-gating decisions (739 pre-existing issues retained under the
  `only-new-issues` ratchet), real DCO 1.1, and honest security/commercial
  claims. Bus factor of 1 is stated explicitly — still an open risk.

### Added / Coverage

- 68 deterministic tests for hostxray, evidence and dist/coordinator paths.
  Measured coverage: `internal/hostxray` 37.4%→84.1%, `internal/evidence`
  43.2%→90.7%, `internal/dist/coordinator` 57.0%→80.0%.
- Version consistency gate keeps tag, `VERSION` file and source literal aligned;
  README badge, install commands and winget manifests follow the release tag.

Source: derived from `git log v0.18.0..HEAD` (16 DCO-signed commits) and local
verification on 2026-11-20. Remote-only outcomes (CI status, Codecov gate,
cosign same-run verification) are confirmed on the tagged run.

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
