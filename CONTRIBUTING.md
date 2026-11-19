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

## 3. Validation (CI expectations)

Pull requests should pass the following checks:

```bash
go build ./...
go vet ./...
go test -count=1 ./...
```

Coverage target: **80%+** for the project over time. New changes should not reduce coverage for the areas they touch.

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

Risk-sensitive subsystems — the load `engine`, `attest` (sealing/verification),
and `authz` (authorization and dial control) — are maintained by the project
lead. Changes there need review from the lead before merge.

Everything else is open to contributors. Good first contributions:

- Documentation fixes and examples (`README.md`, `docs/`).
- New scanner checks and their regression tests, following the existing
  `internal/scanner/core` patterns.
- Dashboard polish and small UI fixes under `internal/dashboard/`.
- Test isolation and coverage improvements.

A useful contribution does not have to add a feature. A pull request that makes
one package smaller, removes duplication, or simplifies a hot path is welcome.
Keep a self-imposed ceiling of roughly 400-600 lines per new file so reviews stay
tractable; split larger changes along existing package boundaries instead of
rewriting them wholesale.

See `docs/ROADMAP.md` for known limitations and planned engineering work.

## 8. Maintainers

See `MAINTAINERS.md` for the current maintainer list.

## Dashboard scope

The web dashboard is a **local-first operator console**: it is designed to run
on the operator's own machine against targets they are authorized to test. The
API under `/api/...` is the contract; the bundled JavaScript is only a client of
that contract. Treat the dashboard as a control surface for one operator, not
as a multi-tenant service exposed to the public internet. See
`docs/DEPLOYMENT-HARDENING.md` before exposing any dashboard endpoint beyond
localhost.

## Questions

If you have questions, open a GitHub issue or contact the maintainers. Thank you for contributing.
