# Contributing to Sift

Thanks for your interest in contributing to Sift. Please follow these guidelines to keep contributions consistent, reviewable, and safe.

## 1. Before you start

- **Open an issue first.** For new features, bug reports, or proposals, open a GitHub issue before starting significant work.
- **Wait for alignment on large changes.** Significant features or architectural changes should be discussed with maintainers before implementation.

## 2. Code style and commits

- **Go formatting/linting:** run `gofmt`, `go vet`, and `golangci-lint` (if available in your environment).
- **Tests are required for new functionality.** Add or update `*_test.go` coverage for behavior you introduce or change.
- **Keep commits focused and meaningful.** Prefer small, scoped commits with clear messages, for example:
  - `feat(scope): short description`
  - `fix(scope): short description`
- **Be explicit in commit messages.** Describe what changed and why (file/line references are optional).
- **Sign off every commit** with `git commit -s`; see section 9 for the DCO requirement.

## 3. Validation (CI expectations)

Pull requests should pass the following checks:

```bash
go build ./...
go vet ./...
go test -count=1 ./...
```

Coverage target: maintain **>=75%** aggregate coverage. The most recent
measurement is **76.2%** overall (78.0% excluding generated `.pb.go` files;
see `docs/COVERAGE.md`). CI enforces the same **75%** floor in
`.github/workflows/ci.yml`; that floor is a minimum, not the project target.
New changes should not reduce coverage for the areas they touch.

## 4. Security

- **Never commit secrets.** Do not commit API keys, tokens, credentials, `.env` files, or private key material.
- **Report vulnerabilities responsibly.** Do not push exploit details or sensitive vulnerability reports to public branches/issues. Follow the repository's security disclosure process (see `SECURITY.md`).
- **Respect authorization and safety controls.** State-changing and sensitive operations must follow existing auth/RBAC/authorization and audit controls.

## 5. Documentation

- **Update docs with behavior changes.** If you add or change functionality, update relevant documentation in `docs/` and/or `README.md`.
- **Keep API/CLI docs accurate.** If flags, commands, APIs, or outputs change, update the corresponding documentation.
- **Document standards and formats clearly.** Protocol/spec-related changes (e.g. VPMP-related behavior) should be documented in the appropriate spec/document files.

## 6. Release process

- **Versioning:** semantic versioning (for example, `v0.14.5` → `v0.15.2`).
- **Changelog:** update `CHANGELOG.md` for user-visible changes.
- **Tagging:** releases are tagged with `git tag`.
- **Builds:** release builds are produced via `./scripts/build-all.sh` (and project release workflows where applicable).

## 7. Ownership and good first issues

Risk-sensitive subsystems - the load `engine`, `attest` (sealing/verification),
and `authz` (authorization and dial control) - are maintained by the project
lead. Changes there need review from the lead before merge. The full path map is
in `MAINTAINERS.md` under "Ownership map"; every path not listed as restricted
there is open to contributors.

Everything else is open to contributors. The lists below are concrete starting
points with the files to touch and a rough review size: **S** = one file, tens of
lines; **M** = two or three files, a few hundred lines. Sizes describe review
load only; they are not a schedule or a commitment. Pick one item, reference it
in an issue, and keep one item per PR.

### Documentation

- **S** - `docs/VPMP-RFC.md` section 6 (implementation status): re-check each
  listed path under `internal/dist/` and update the table when a component or
  its E2E test moves. Keep the component and its test in the same row.
- **S** - `docs/OWASP-SCANNER.md` section 5 (confidence model): keep the
  four-level model and the note about the three-level verifier in
  `internal/scanner/verify.go` in sync when either side changes.
- **S** - `README.md` "Documentation" list: add a newly shipped doc from `docs/`
  with one line of scope. No marketing prose in that list.

### Examples

- **S** - `examples/sla_gate.yaml`: keep the existing four thresholds and the
  `/health` step; add comments that map a threshold to the actual CLI flags
  (`--expect-p99-ms`, `--expect-error-rate`, `--expect-min-rps` in
  `cmd/sift/main.go`). Do not invent flags that are not wired.
- **S** - `examples/basic-get.yaml` or `examples/branching-flow.yaml`: add one
  scenario that exercises an existing check, with a short purpose comment at
  the top of the same file.
- **M** - `examples/demo_store/README.md` and `examples/demo_store/`: document
  one existing local flow end to end (start command, Sift command, expected
  exit code). Do not change the demo server code in the same PR.

### Scanner checks

- **S** - `internal/scanner/passive_checks_exposure.go` plus
  `internal/scanner/checks_passive_test.go`: add one passive check that uses
  `passiveEvidence(...)` and an existing level from
  `internal/scanner/passive_scanner.go`. Include a false-positive rationale and
  one negative regression case.
- **S** - `internal/scanner/intrusive.go` plus
  `internal/scanner/intrusive_test.go`: extend one benign re-check with a
  control or canary case. Keep the `confidence=<level>` evidence prefix; add no
  destructive payloads.
- **M** - `internal/scanner/core/probe.go` and `internal/scanner/core/types.go`
  with `internal/scanner/core/probe_test.go`: adjust one probe helper or type
  while preserving the behavior the scanner packages already rely on.
- **M** - `internal/scanner/verify.go` with `internal/scanner/verify_test.go`:
  improve one re-verification path while keeping the `confirmed`, `probable`,
  `possible` grades and the `[VERIFIED]`, `[PROBABLE]`, `[UNVERIFIED]` badges
  stable. Respect the report-badge caveat in `docs/OWASP-SCANNER.md` section 5.

### Dashboard UI polish

- **S** - one part under `internal/dashboard/assets/` (for example
  `app-02-form.js` or `app-11-shell.js`) with the matching check in
  `internal/dashboard/assets_bundle_test.go` or
  `internal/dashboard/assets_test.go`. Assets are embedded by
  `internal/dashboard/server.go`; keep the served `/app.js` byte-identical to
  the embedded bundle.
- **M** - `internal/dashboard/index.html` and `internal/dashboard/style.css`
  with one asset part: fix one layout or labeling issue in the local-first
  console. Do not change the `/api/...` contract in the same PR.

A useful contribution does not have to add a feature. A pull request that makes
one package smaller, removes duplication, or simplifies a hot path is welcome.
Keep a self-imposed ceiling of roughly 400-600 lines per new file so reviews stay
tractable; split larger changes along existing package boundaries instead of
rewriting them wholesale.

See `docs/ROADMAP.md` for known limitations and planned engineering work, and
`docs/ROADMAP-90D.md` for the current 90-day focus areas and their acceptance
checks.

## 8. Maintainers

See `MAINTAINERS.md` for the current maintainer list.

## 9. Developer Certificate of Origin (DCO)

Every commit must be signed off under the [Developer Certificate of Origin,
version 1.1](https://developercertificate.org/). Add the sign-off with:

```bash
git commit -s -m "fix(scope): short description"
```

This appends a line to the commit message:

```
Signed-off-by: Your Name <you@example.com>
```

Use your real name and an email address you control; the sign-off must match the
commit author identity. By signing off you certify the DCO 1.1 conditions: the
contribution is your own work or you have the right to submit it, you have the
right to submit it under the repository license (Apache-2.0), and you understand
it is public and may be redistributed with a record of the sign-off.

Pull requests containing commits without a `Signed-off-by` line are not merged.
See `LICENSING.md` section 4 for how the sign-off is used.

## Required CI checks

CI defines three named aggregate gates: `ci-ok` (`.github/workflows/ci.yml`),
`security-ok` (`security.yml`) and `codeql-ok` (`codeql.yml`). Each fails when
any required job in its workflow fails. Configure branch protection in the
GitHub repository settings to require all three checks before merge. A single
workflow's aggregate cannot cover jobs from another workflow, so requiring all
three names is intentional. Do not lower the coverage floor (currently 75%)
to hide a regression.

Two jobs are deliberately skipped in some configurations. `analyze` in
`codeql.yml` is skipped on private repositories because SARIF upload needs a
paid add-on, and `dependency-review` in `security.yml` runs only on public pull
requests. The aggregates treat those specific skips as no-runs rather than
failures. A green `codeql-ok` on a private repository therefore means no CodeQL
analysis ran, not that the analysis passed. `govulncheck`, `gosec`, `gitleaks`
and both Trivy jobs run on every push regardless of repository visibility.

## Dashboard scope

The web dashboard is a **local-first operator console**: it is designed to run
on the operator's own machine against targets they are authorized to test. The
API under `/api/...` is the contract; the bundled JavaScript is only a client of
that contract. Treat the dashboard as a control surface for one operator, not
as a multi-tenant service exposed to the public internet. See
`docs/DEPLOYMENT-HARDENING.md` before exposing any dashboard endpoint beyond
localhost.

## Audit trail locking

Every decision, including a denied load-test start, is appended to one
hash-chained JSON-lines trail. `authz.Log.Append` holds a path-keyed process
mutex across `tail()` and `Write`, then takes an exclusive advisory file lock,
so fresh `Log` handles in dashboard goroutines and a concurrently running CLI
cannot duplicate `Seq` or break `PrevHash`. The mutex is keyed by path (not a
cached file handle) so tests that swap `SIFT_AUDIT_LOG` stay isolated.

On Windows the advisory file lock is a no-op: writers inside one process are
still serialized, but concurrent CLI processes on Windows retain a residual
chain-corruption risk. The dashboard is a local-first console; run one writer
at a time there. Every decision records the authenticated subject as `actor`;
an unauthenticated (loopback) dashboard falls back to the process user.

## Questions

If you have questions, open a GitHub issue or contact the maintainers. Thank you for contributing.
