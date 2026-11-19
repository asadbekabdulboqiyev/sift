# Maintainers

Current maintainers of the Sift project.

## Lead Maintainer

- **Asadbek Abdulboqiyev** — `asadbeksoon0421@icloud.com`
  - GitHub: `@asadbekabdulboqiyev`
  - Responsibilities: architecture, release management, security, and code review.

## Co-Maintainers

- (none yet) — the bus factor is **1**, not 2+. Reaching 2+ is a goal, but no
  second maintainer has been appointed.
  - The `Lower bus factor` item in the v0.18.0 release notes refers to
    documentation only: good-first issues, the ownership map below, and the
    90-day roadmap. It does not mean a second person can review or merge today.
  - If you are interested, follow the contribution process in `CONTRIBUTING.md` and open a discussion/PR.

## Ownership map

Three areas are **lead-only**: a change there needs review from the lead
maintainer before merge. This matches the restricted list in `CONTRIBUTING.md`
section 7 and the explicit path entries in `.github/CODEOWNERS`.

| Area | Path | Change policy |
| --- | --- | --- |
| Load engine | `internal/engine/` | Lead-only |
| Attestation and verification | `internal/attest/` | Lead-only |
| Authorization and dial control | `internal/authz/` | Lead-only |

**Every other path is open to contributors.** That includes
`internal/scanner/`, `internal/dashboard/`, `internal/dist/`,
`internal/honesty/`, `web/verifier/`, `verify/standalone/`, `examples/`,
`docs/`, `scripts/`, `deploy/`, and `.github/`. Contributors may open PRs in
these areas directly; the standard CI and review process in `CONTRIBUTING.md`
applies.

`.github/CODEOWNERS` requests a review from the lead on all paths through its
default `*` rule, and adds explicit review entries for several of the open
paths above. That is a review request, not a lead-only gate outside the three
areas in the table; CODEOWNERS does not by itself enforce merge policy. Every
entry in that file names the same single person, so it does not increase the bus
factor.

## Becoming a maintainer

1. Submit **3+ high-quality merged PRs** (features or fixes).
2. Participate actively in code reviews and project discussions.
3. Be nominated by the lead maintainer and added to `MAINTAINERS.md`.

## Contact

- **Issues:** GitHub Issues
- **Security:** `asadbeksoon0421@icloud.com` (responsible disclosure)
- **General:** `asadbeksoon0421@icloud.com`
