# 90-Day Roadmap - VPMP, Run/SLA/CI Examples, Scanner False Positives

This plan is derived from code and documents already in this repository. It is a
focus list with acceptance checks, not a commitment or a calendar of dates. Every
"Current state" item below can be found at the path named next to it. "Target"
describes what should be true after the 90-day window; "Acceptance" lists the
commands or conditions used to check it. Ownership and review paths are in
`MAINTAINERS.md` and `CONTRIBUTING.md`.

## Priority 1 - VPMP and the verify process

**Current state (verified in this repo).**

- `docs/VPMP-RFC.md` specifies the `vpmp/v1` evidence format. Section 6 lists
  the proto definition, attestation core, worker signing, master verification,
  aggregator storage, and E2E tests as Implemented; all six listed paths under
  `internal/dist/` exist.
- Three verifier implementations exist. The Go verifier is wired to
  `sift verify` (`cmd/sift/cmd_verify.go`). The JavaScript verifier
  (`web/verifier/vpmp.mjs`, CLI front end `web/verifier/verify-cli.mjs`) is a
  deliberate independent re-implementation, and `docs/VERIFIER.html` is the
  generated offline page. The Python verifier (`verify/standalone/sift_verify.py`)
  is stdlib-only and imports no Sift code.
- Two CI jobs already gate this path: `verifiable-evidence` runs a real paced
  run, then asserts that pristine evidence verifies (exit 0) and tampered
  evidence is rejected (exit 1); `verifier` runs the JS unit tests, the page
  drift check `web/verifier/build-html.mjs --check`, and the Go-to-JS parity
  script `scripts/verify-html-parity.sh`.
- Local entry points exist: `make verifier`, `make verifier-page`, and
  `make demo-verified` (seal, verify, one-byte tamper, restore).

**Target (90 days).** Any change to the verification path keeps all three
implementations in agreement on genuine and altered bundles, and both CI gates
stay green including the negative (tamper) direction.

**Acceptance.**

- `make verifier` exits 0: JS unit tests pass, the shipped page matches the
  tested module, and Go and JS reach the same verdict case by case.
- `node web/verifier/verify-cli.mjs --bundle <bundle> --samples <sidecar> --json`
  reports `valid: true` on a freshly sealed bundle and `valid: false` after a
  one-byte tamper; process exit codes are 0 and 1 respectively.
- `python3 verify/standalone/sift_verify.py --self-test` exits 0, and
  `internal/attest/python_verify_test.go` passes with bundles produced by the
  Go implementation.
- `sift verify --bundle <bundle> --samples <sidecar>` exits 0 for genuine
  evidence and 1 for altered evidence, matching the CI `verifiable-evidence`
  assertions.
- A protocol or verifier change updates `docs/VPMP-RFC.md` and regenerates
  `docs/VERIFIER.html` (`make verifier-page`) in the same PR.

## Priority 2 - Run + SLA + CI examples

**Current state (verified in this repo).**

- `examples/sla_gate.yaml` is a steady 300-user / 15-second profile against
  `http://localhost:8080` with a `/health` step and four thresholds:
  `max_p99_ms: 250`, `max_avg_ms: 100`, `max_error_rate_pct: 1`, `min_rps: 800`.
  Its header documents exit code 2 on a threshold violation.
- The wired CLI gates are `--expect-p99-ms`, `--expect-error-rate`, and
  `--expect-min-rps` (`cmd/sift/main.go`, also summarized in `README.md`);
  exceeding one exits 2. `README.md` additionally lists `--compare` and
  `--regress-pct` under Gates.
- `docs/VERIGATE.md`, section "The SLA verify gate", documents the two-phase
  demo: with protection ON the error rate exceeds 5 percent and Sift exits 2;
  with protection OFF the run passes and Sift exits 0. The same flow is running
  through `scripts/demo-store-sla.sh` and `make demo-sla`.
- The CI `verifiable-evidence` job demonstrates a complete run, then verifies
  the sealed evidence:

  ```
  --target-rps 100 --duration 3 --users 4 --coordinated-omission
  --allow-private --quiet --emit-bundle /tmp/ev/bundle.json
  --bundle-key /tmp/coord.key
  ```

**Target (90 days).** Each documented run/SLA example has one executable
command, one stated expected exit code, and at least one CI job that exercises
the same path. No example or doc names a flag that is absent from
`cmd/sift/main.go`.

**Acceptance.**

- `make demo-sla` prints both phases and the documented verdict (ON -> SLA FAIL
  with Sift exit 2, OFF -> SLA PASS with Sift exit 0).
- `./bin/Sift --config examples/sla_gate.yaml` against the local demo server
  exits 2 when a documented threshold is violated, as its header claims.
- The CI `verifiable-evidence` job passes both directions: pristine bundle exit
  0, tampered sidecar exit 1.
- Each example under `examples/` added during the window is referenced from
  `README.md` or a doc under `docs/` in the same PR; no orphan example files.

## Priority 3 - Scanner false-positive reduction

**Current state (verified in this repo).**

- `internal/scanner/passive_scanner.go` defines four evidence confidence
  levels (`confirmed`, `high`, `heuristic`, `informational`), a dedup key of
  (check ID, URL, name), and `passiveEvidence(...)`, which always writes a
  `False-positive check:` rationale. `internal/scanner/checks_passive_test.go`
  asserts that passive findings carry a confidence prefix and that note.
- `internal/scanner/intrusive.go` carries the same `confidence=<level>` prefix.
  `internal/scanner/intrusive_test.go` covers suppression with a control and a
  canary, including a noisy target and a target that echoes signatures.
- `internal/scanner/verify.go` re-tests findings with three grades
  (`confirmed`, `probable`, `possible`) and badges `[VERIFIED]`, `[PROBABLE]`,
  `[UNVERIFIED]`. `docs/OWASP-SCANNER.md` section 5 records the mapping to the
  four-level report model and the caveat that `cmd/sift/cmd_pentest.go` writes
  `ConfPossible` for every emitted finding, so a report badge may not reflect
  the verifier verdict.
- `cmd/sift/pentest_confidence_regression_test.go` is the existing regression
  guard around the pentest confidence behavior.

**Target (90 days).** Fewer unqualified findings: every emitted passive or
intrusive finding carries a confidence level and a reproducible false-positive
rationale, and a report badge agrees with the verifier verdict whenever the
report claims a verdict.

**Acceptance.**

- `go test ./internal/scanner/... -count=1` passes, including the existing
  confidence/dedup assertions in `checks_passive_test.go`, the control/canary
  cases in `intrusive_test.go`, and the re-verification cases in
  `internal/scanner/verify_test.go`.
- Every new or modified check ships at least one negative regression case (a
  benign response that must not be reported) in the same PR.
- `[VERIFIED]` is used only for findings with an independent second observation
  or a deterministic response, per `docs/OWASP-SCANNER.md` section 5.
- The `cmd/sift/cmd_pentest.go` badge caveat in `docs/OWASP-SCANNER.md` section 5
  is removed only when code and document agree; until then the caveat stays.

## Scope note

This document does not add new roadmap estimates: the numbers and limits quoted
above are the ones already present in the named files. Items outside these three
priorities remain in `docs/ROADMAP.md` and are not re-prioritized here.
