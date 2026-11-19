# Changelog

All notable changes to Sift are documented here. This file follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) style and semantic
versioning. Entries are taken from git tags and commit history; nothing here is
a promise of future work.

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
- No legacy stress-strike references remain; the gitleaks allowlist matches the
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
