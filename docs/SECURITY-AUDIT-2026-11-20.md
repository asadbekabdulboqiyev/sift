# Security Audit — Sift v0.18.1 (2026-11-20)

> **THIS IS A LOCAL AUDIT. NOT a third-party pentest. NOT a compliance certificate.**

## 1. Scope and Methodology

| Element | Value |
|---|---|
| Repo | `/Users/asadbek/sift` |
| Branch / HEAD | `main` / `773fa564f5ef64546dcffd0bd7160bf43c2b18fb` |
| Date | 2026-11-20 |
| Method | Static source review and call-chain searching (`rg`/`grep`) |
| Work Not Performed | The application was not run; no DAST/network scanner and no exploitation attempts. The dependency scanner was not run by this audit, but it runs continuously in CI (§5.7) |

Areas reviewed: authz/RBAC and `DialControl`, CSRF/rate limiting/CSP, certificate verification (CWE-347/345), HTTP/3 TLS, OIDC token logging and JWT validation, fingerprint dialer, port validation, dashboard JS XSS, insights file paths, coordinator TLS, CLI auth connection.

While working on the report, the working tree had the following **unrelated** changes (some appeared during the review): `.github/workflows/release.yml`, `internal/engine/raw_client_leak_test.go`, `internal/evidence/evidence_unit_test.go`, `internal/hostxray/report_test.go`, `internal/shared/atomicfile_test.go` (modified); `docs/LINT-DEBT-TRIAGE.md`, `internal/finding/confidence_json_test.go`, `internal/secrets/resolver_table_test.go`, `internal/store/postgres/pure_unit_test.go`, `internal/tenant/context_behavior_test.go` (new). They were not created or modified by this audit and are outside the report's scope. The only file created was `docs/SECURITY-AUDIT-2026-11-20.md`. No production code was touched; `git add` / `git commit` / `git push` were not performed.

## 2. Explicit Limitation

**THIS IS A LOCAL AUDIT, NOT a third-party pentest, NOT a compliance certificate.**

- No independent third-party expert, pentest firm, external scanner, or certification body was involved.
- No exploitation, network scanning, DAST, or live testing was performed; all conclusions are based on code reading.
- This document does not certify compliance with SOC 2, ISO 27001, GDPR, or any other compliance requirements.
- A "Not found" entry means only **no confirmed vulnerability within the reviewed code scope**; it does not prove the absence of vulnerabilities in the system.

## 3. Findings Table

| ID | Severity | File:line | Evidence (code excerpt) | Exploitability | Recommendation | Status |
|---|---|---|---|---|---|---|
| F-01 | Medium | `cmd/sift/cmd_run_execute.go:19-29`, `cmd/sift/dash_mode.go:165-175`, `cmd/sift-dashboard/main.go:158-170` | `dashboardAuthOptions` returns only `Tokens`, `APIKeyHashes`, `AllowedOrigins`, `RateLimit*`, `TrustProxy`, `AllowAnonymous`; `OIDCIssuer`/`RBACEnabled`/`RBACRole` are absent. `dash_mode.go:167-169`: `case dashAuth.HasCredentials(): auth = srv.ApplyAuth(dashAuth)`. In `sift-dashboard/main.go:166-170`, by contrast, `OIDCIssuer: oidcIssuer`, `RBACEnabled: *authRBACEnabled`, `RBACRole: authRBAC` are present. With `rg`, no `auth-oidc`/`auth-rbac`/`OIDCIssuer` was found inside `cmd/sift`. | Low-Medium: only on the `sift run --dashboard` path and when the operator expects RBAC; auth is mandatory for non-loopback (`dash_mode.go:158-163`). | Add OIDC/RBAC flags to `sift run` and pass them into `AuthOptions`, or clearly document that RBAC is available only in `sift-dashboard` and warn when it is incorrectly expected. | **FIXED** — §6 |
| F-02 | Medium | `cmd/sift/cmd_certificate.go:69`, `internal/certificate/certificate.go:797-820`, `cmd/sift/cmd_verify.go:362-366` | `fs.BoolVar(&require, "require-anchor", false, "fail unless the signer is in the trust store")`; `case store == nil: check.Status = attest.IssuerUnpinned`; then, if `Verify(c)` succeeds, an error occurs only in `case check.Status == attest.IssuerUnpinned && requireAnchor:`. `loadVerifyTrustStore` returns `return nil, nil` when there is no default store and the flag is disabled. | Medium: in environments where no trust store file is installed, a self-signed but internally valid certificate is accepted (status `IssuerUnpinned`, exit code 0). | Make `require-anchor` default to `true` for verification, or make `--allow-unpinned` an explicit opt-in; state the current default openly in the documentation. | **FIXED** — §6 |

### F-01 Evidence (full excerpt)

```go
// cmd/sift/cmd_run_execute.go:19-29
func dashboardAuthOptions(o *runOptions) dashboard.AuthOptions {
	return dashboard.AuthOptions{
		Tokens:         o.dashAuthTokens,
		APIKeyHashes:   o.dashAuthAPIKeys,
		AllowedOrigins: o.dashAuthOrigins,
		RateLimitRPS:   o.dashAuthRateLimit,
		RateLimitBurst: o.dashAuthBurst,
		TrustProxy:     o.dashAuthProxy,
		AllowAnonymous: o.dashAuthInsecure,
	}
}
```

```go
// cmd/sift/dash_mode.go:167-169 — no RBAC configuration
case dashAuth.HasCredentials():
	auth = srv.ApplyAuth(dashAuth)
	defer auth.Close()
```

```go
// cmd/sift-dashboard/main.go:166-170 — full wiring in another entry point
OIDCIssuer:     oidcIssuer,
OIDCClientID:   oidcClientID,
OIDCRoleClaim:  "role",
RBACEnabled:    *authRBACEnabled,
RBACRole:       authRBAC,
```

### F-02 Evidence (full excerpt)

```go
// cmd/sift/cmd_certificate.go:69
fs.BoolVar(&require, "require-anchor", false, "fail unless the signer is in the trust store")

// internal/certificate/certificate.go:797-820
case store == nil:
	check.Status = attest.IssuerUnpinned
...
case check.Status == attest.IssuerUnpinned && requireAnchor:
	return check, fmt.Errorf("certificate: signer %s is unpinned and a trust anchor is required",
		check.Fingerprint())

// cmd/sift/cmd_verify.go:362-366
if requireAnchor {
	return nil, fmt.Errorf("--require-anchor needs a trust store, but %s does not exist...", def)
}
return nil, nil
```

### Not Found / Not Evaluated

**Not Found (within the reviewed code scope):**

- **XSS:** In `internal/dashboard/assets/app-05-render.js:277`, `row()` outputs the value with `esc(val)`; `body.innerHTML = html` at `:358` receives pre-escaped data. The `esc()` and `setOut()` calls in `app-14-insights.js:16-29` behave the same way. No confirmed XSS was found. The `new Function(...)` at `app-07-init.js:188-193` comes only from a hardcoded `map`; it is not XSS, but it may conflict with the CSP `script-src 'self'` (`security.go:74-83`) (a functionality issue).
- **Path traversal:** `internal/dashboard/insights_helpers.go:15-43,98-126` has path containment and sanitization; not found.
- **Sensitive data written to logs (CWE-532):** In `internal/oidc/oidc.go:314-351`, only the sanitized `error` code is used instead of the provider error body; not found.
- **DNS rebinding:** `internal/authz/dial.go:30-40,54-89` and `internal/engine/client.go:55-98,110-134` perform socket-level re-checking; no confirmed bypass was found.

**Not Evaluated (within this audit's scope):** SQL/NoSQL/command injection, XXE, runtime and network tests. CI's automatic dependency scans (govulncheck/Trivy) are not part of this audit. No "not found" conclusion is given for these categories.

## 4. Status of Previous Fixes

| Fix | Status | Evidence (file:line + excerpt) |
|---|---|---|
| Authz RBAC: path-first, fail-closed | **Confirmed** | `internal/dashboard/auth.go:216-227`: `if a.rbacEnabled { perm := permForPath(r.URL.Path, r.Method); if !a.rbacAllowed(...) { http.Error(w, "rbac: permission denied", 403) } }`; `:398-416`: `case strings.HasPrefix(path, "/api/admin"): return rbac.PermAdmin`, then `/api/audit`, `/api/run`, fallback `tests:run`/`tests:view`. The coverage concern is in F-01. |
| `authz.DialControl` + `CheckDialTarget` | **Confirmed** | `internal/authz/dial.go:36-38`: `if got := ClassifyIP(ip); got.severity() > approved.severity() { return fmt.Errorf(...) }`; `:54-89`: errors for an empty host/port, a resolution error, or a rejected IP. `internal/engine/client.go:58-62` `Control: control`, `:87-97` `net.Dialer{Control: control}` on the uTLS path, `:110-131` `authz.CheckDialTarget(...)` on the proxy path. |
| CSRF same-origin + 20 RPS / burst 40 | **Confirmed (browser scope)** | `internal/dashboard/security.go:25-38`: if Origin is present, scheme and host are compared; `internal/dashboard/auth.go:48-49`: `defaultAuthRPS = 20.0`, `defaultAuthBurst = 40`; `:173-183`: `a.rateEnabled = true` and zero values are filled with the defaults; `:229-232`: `if !isSafeMethod(r.Method) && !a.originAllowed(r) { ... 403 }`. Limitation: `security.go:27-29` accepts clients without Origin — this is not a vulnerability, it is a deliberate design for non-local clients. |
| Certificate CWE-347 / CWE-345 | **Confirmed** | `internal/certificate/certificate.go:477-479`: `if err := validateV1Envelope(c); err != nil { return err }`; `:488-497`: unsigned `validity_period`, `previous_certificate_hash`, `experiment_reference` are rejected; `:673-688`: `signedCertificateID` only from signed fields; `:712-738`: `VerifyChain` checks genesis and the hash chain. |
| HTTP/3 TLS verification default | **Confirmed (code level)** | `internal/http3/h3.go:101-106`: `InsecureSkipVerify: opts.InsecureSkipVerify`, `ServerName: host`; `:120-126`: `InsecureSkipVerify: insecure` only on opt-in. No production call was found (only tests inside `internal/http3`). |
| CWE-532: IdP token redaction | **Confirmed** | `internal/oidc/oidc.go:314-320`: `tokenEndpointError` outputs only the result of `oauthErrorCode(body)`; `:337-351`: `sanitizeErrorCode` allows only 64-character ASCII codes. |
| Fingerprint: no panic + port validation | **Partially confirmed / questionable** | No panic: `internal/fingerprint/fingerprint.go:133-139` returns `ErrUnknownProfile`, `:147-152` `NewDialer` also returns a dial with an error. Port: `internal/scanner/guard.go:493-497` `if err != nil || n < 1 || n > 65535`; `internal/dashboard/portscan.go:81-85` `if p < 1 || p > 65535`. Questionable: `fingerprint.go:29` `Default Profile = ""` is absent from the `:48-62` map, and `:109-123` `resolved()` does not add it — `NewDialerChecked(Options{})` returns an error. This is a functionality/availability issue, not a security vulnerability; due to the `if tlsFP != ""` condition at `internal/engine/client.go:78`, it is not called in production. |

## 5. Areas with Residual Risk

1. **F-01 — RBAC coverage.** ~~RBAC cannot be enabled in `sift run --dashboard`~~ — fixed in §6: OIDC/RBAC flags were added.
2. **F-02 — trust anchor optional.** ~~If there is no trust store and `--require-anchor` is not given, the `IssuerUnpinned` status is not an error~~ — fixed in §6: the anchor is mandatory by default.
3. **OIDC JWKS filter.** ~~At `:499-506`, keys are loaded only by `kid`~~ — **FIXED (2026-11-21)**: `jwkKey.usableForSigning()` was added — `use` is accepted only as `""`/`"sig"`, and if `alg` is present, only `RS256`→RSA or `ES256`→EC/P-256 matching is accepted. This is an additional filter (JWT algorithm pinning is unchanged). Tests: `TestJWKUsableForSigning` (12 cases), `TestLoadKeysFiltersJWKSMetadata`. The requirement that JWKS control must reside at the IdP remains in force.
4. **Coordinator TLS.** ~~If neither a CA nor `-tls-skip-verify` is given, `return nil, nil` — a plaintext connection~~ — **FIXED (2026-11-21)**: the `TLSOptions.RequireTLS` field and the `--tls-require` flag were added (`cmd/sift-master`, `cmd/sift-worker`). Opt-in: with `RequireTLS=true`, if both CA and skip-verify are absent, `ClientCreds()` returns an error. The default (`false`) is unchanged — existing plaintext fleets keep working. Test: `TestTLSOptionsRequireTLS` (5 subtests).
5. **DNS error at the gate level.** `internal/dashboard/handlers_run.go:122-128`: on a classify error, `authz.ClassPublic, "", false` is returned; however, via `:141-149` this class is passed to `authz.DialControl` and re-checked at the socket. The risk is low, but it is fail-open at the gate level.
6. **HTTP/3 probe.** ~~`req := "GET / HTTP/1.1\r\nHost: " + host + ...` based on a raw Host line~~ — **FIXED (2026-11-21)**: the `hostHeader()` helper rejects an empty host and CR/LF before dialing (preventing header injection) and wraps an IPv6 literal in `[::1]` form to produce a correct HTTP/1.1 Host. Tests: `TestHostHeader`, `TestCheckAltSvcRejectsUnsafeHost`, `TestCheckAltSvcIPv6HostHeader`. There is still no production call; if it is wired up in the future, it must be checked together with `authz.DialControl`.
7. **Audit coverage.** Static review only: DAST, runtime configuration, network, and multi-tenant integration tests were not covered. The dependency scan was not run by this audit, but it runs in CI: `govulncheck` (Go reachability, `.github/workflows/security.yml:24-45`), Trivy image scan + enforcing gate (HIGH/CRITICAL, `security.yml:189-262`), `dependency-review` (PR, high), Dependabot (gomod/actions/docker). Local `trivy fs --scanners vuln --severity HIGH,CRITICAL .` (2026-11-21): **0 vulnerabilities** (gomod). It cannot replace a third-party pentest.

---

## 6. Remediation of Findings (post-audit, 2026-11-20)

Both findings were fixed with the user's permission. The code changes were re-verified (`go build ./...`, `go test ./cmd/sift/... ./cmd/sift-dashboard/... ./internal/certificate/... ./internal/dashboard/... -count=1` — green).

### F-01 — OIDC/RBAC flags in `sift run --dashboard`

| File | Change |
|---|---|
| `cmd/sift/cmd_run_options.go` | Added `dashAuthOIDC`, `dashAuthRBAC`, `dashAuthRBACEnabled` to `runOptions`; new flags: `--dashboard-auth-oidc`, `--dashboard-auth-rbac`, `--dashboard-auth-rbac-enabled` (default `false`). |
| `cmd/sift/cmd_run_execute.go` | `dashboardAuthOptions()` now passes `OIDCIssuer`, `OIDCClientID`, `OIDCRoleClaim`, `RBACEnabled`, `RBACRole`. The OIDC `issuer:client_id` is split at the **last** `:` — a URL issuer (with a port) works. |
| `cmd/sift/dash_mode.go` | The entire `AuthOptions` is passed to `ApplyAuth`; `oidc=%t rbac=%t` was added to the auth message. |
| `cmd/sift-dashboard/main.go` | Additional finding during the audit: `-auth-oidc` used `SplitN(":", 2)`, so a URL issuer was parsed incorrectly. Switched to `LastIndex` via `parseOIDCPairs()` — the two entry points are now consistent. |
| Tests | `cmd/sift/cmd_run_dashboard_auth_test.go` (5 tests), `cmd/sift-dashboard/main_oidc_test.go` (URL issuer + last-colon + malformed). |

Defaults did not change: RBAC still starts disabled; only the capability was added.

### F-02 — trust anchor mandatory by default

| File | Change |
|---|---|
| `cmd/sift/cmd_verify.go`, `cmd/sift/cmd_certificate.go` | `--require-anchor` defaults to `true`; new `--allow-unpinned` is an explicit opt-out. `resolveAnchorPolicy()` rejects conflicting flags **with an error** (no silent weakening): `--require-anchor=false` + `--allow-unpinned` is consistent, explicit `--require-anchor` + `--allow-unpinned` is a usage error. The library API (`VerifyBytesWithTrust`, `VerifyPDF`) did not change — this is only a CLI policy. |
| `cmd/sift/cmd_trust.go`, `README.md`, `internal/certificate/html.go` | Help/guide/documentation texts reflect the new default. |
| `scripts/demo-verified.sh`, `scripts/verify-html-parity.sh` | Because self-sealed fixtures worked without a trust store, `--allow-unpinned` was added to them — so that the breaking change would not break their self-consistency check. |
| Tests | `cmd/sift/cmd_require_anchor_f02_test.go` (7 tests: default→exit 1, opt-out→VALID, pinned→VALID, conflict, help). Old CLI tests were updated with `--allow-unpinned` to preserve their self-consistency intent. |

**Breaking change (intentional):** `sift verify` / `sift certificate` without a trust store and without flags now returns exit 1. This is the security policy approved by the user; the previous behavior is restored only with `--allow-unpinned`.

### Residual Risks (not fixed)

If there is no trust store and `--allow-unpinned` is given, the status becomes `IssuerUnpinned` again with exit code 0 — this is now an **explicit opt-in**, not an accidental default. A third-party pentest, DAST, and a compliance certificate are still absent; the dependency scan is available in CI and returned 0 HIGH/CRITICAL in the local check (§5.7).

---

## 7. Additional Post-Audit Work (2026-11-21)

### 7.1 Dependency Scan Coverage Corrected

While the audit was being written, §1/§3/§5.7/§6 incorrectly stated that "there is no dependency scan". In fact, these jobs were already present at the audit HEAD (`773fa564`): `govulncheck` (symbol-level reachability, every push/PR + weekly cron), Trivy image scan + enforcing gate (`exit-code: 1`, HIGH/CRITICAL), `dependency-review` (PR, high), Dependabot (gomod/actions/docker). Local `trivy fs --scanners vuln --severity HIGH,CRITICAL .` (2026-11-21): **0 vulnerabilities** (gomod). The corresponding lines in the report were corrected.

### 7.2 Coordinator TLS — opt-in fail-closed (§5.4)

The `TLSOptions.RequireTLS` field and the `--tls-require` flags were added (`cmd/sift-master`, `cmd/sift-worker`, `internal/dist/coordinator/tls.go`). With `RequireTLS=true` and no CA or skip-verify, `ClientCreds()` returns an error — an accidental plaintext dial is now visible. The default is unchanged. `TestTLSOptionsRequireTLS` (5 subtests) was added; `go test ./internal/dist/coordinator/... ./cmd/sift-master/... ./cmd/sift-worker/...` is green.

### 7.3 OIDC JWKS Metadata Filter (§5.3)

In `internal/oidc/oidc.go`, `jwkKey.usableForSigning()` was added and called in `loadKeys()` before `publicKey()`: `use=enc` is rejected, when `alg` is declared only matching `kty`/`crv` is accepted (`RS256`→RSA, `ES256`→EC/P-256), and an unknown `alg` is rejected. The error message and JWT algorithm pinning are unchanged. `TestJWKUsableForSigning` (12 cases) + `TestLoadKeysFiltersJWKSMetadata` were added; `go test ./internal/oidc/...` is green.

### 7.4 HTTP/3 Probe Host Hardening (§5.6)

In `internal/http3/h3.go`, `hostHeader()` was added — an empty host, CR, or LF is rejected before dialing, and IPv6 literals are wrapped in `[::1]` form. `TestHostHeader`, `TestCheckAltSvcRejectsUnsafeHost`, `TestCheckAltSvcIPv6HostHeader` were added; `go test ./internal/http3/...` is green.

### 7.5 Residual Risks

- §5.5 (DNS fail-open at the gate level): `authz.DialControl` re-checks at the socket level — documented, not changed.
- A third-party pentest, DAST, runtime/multi-tenant tests, and a compliance certificate are still absent — they are outside the scope of this local audit.

---

## 8. Browser Crawl DialControl Closure (2026-11-22)

### 8.1 Confirmed gap

`--browser` crawl mode launched headless Chromium through chromedp. Chromium is a separate process with its own DNS resolver and socket stack, so it never touched `crawler.Client` and the gate's `authz.DialControl` hook was inert. A rendered page could fetch `169.254.169.254` or RFC1918 space directly and return the body through the DOM — an SSRF path every other pentest probe closes. `browser.New()` had no dial-control parameter, and `crawlBrowser()` never passed one.

### 8.2 Fix

- `internal/authz/dial.go`: added `CheckedDialIPs`, which resolves a host, applies `control` to every answer, and returns the approved IPs. `CheckDialTarget` now delegates to it; its semantics are unchanged.
- `internal/scanner/browser/guardproxy.go` (new): a loopback-only HTTP/CONNECT forward proxy. For every CONNECT and absolute-form request it calls `CheckedDialIPs`, then dials the **checked IP literal** with `net.Dialer{Control: control}` still installed (closing the resolve/connect rebinding race). It enforces a method allow-list, http-only absolute-form targets, bounded concurrent connections (64), and timeouts; malformed or empty authorities are refused before any socket is opened. Go's `http.ReadRequest` derives the authority from the request-target for both CONNECT and absolute-form, so the address that is class-checked is the address that is dialed. The listener is `127.0.0.1:0` only and is not an open relay.
- `internal/scanner/browser/browser.go`: `New(...Option)` with `WithDialControl`; when a control is present, Chromium is launched with `--proxy-server=http://127.0.0.1:PORT`, `--proxy-bypass-list=<-loopback>` (removes Chromium's implicit direct bypass for localhost **and `169.254/16`**), `--disable-quic`, and `--force-webrtc-ip-handling-policy=disable_non_proxied_udp`. Added `Browser.Close()` to tear down the listener and in-flight tunnels. No control ⇒ no proxy ⇒ historical direct behavior (dev/availability checks).
- `internal/scanner/crawl/crawler.go`: `Crawler.DialControl` and a `newCrawlBrowser` seam; browser mode forwards the control to `browser.New()` and always closes the browser.
- `cmd/sift/cmd_pentest.go`: passes `e.cfg.gate.DialControl()` into the crawler; pinned by a source-level regression test at the CLI boundary.

Verification: pure-Go proxy suite (listen/close, class allow/refuse, CONNECT, absolute-form, control-on-destination-and-socket, malformed authorities, open-proxy refusals, method/scheme allow-list, tunnel teardown under `-race -count=3`); Chromium-gated integration tests proving an approved loopback page renders and an unapproved one is refused with zero upstream hits; crawler wiring test with a fake factory. `go vet`, `go build ./...` and the affected package tests are green.

### 8.3 Residual browser paths — closed in the follow-up phase (2026-11-22)

A follow-up phase closed the paths listed here as residual in the first browser phase:

- `internal/scanner/auth/auth.go`: `AuthConfig.DialControl` (runtime-only, `json:"-"`) carries the gate decision into `loginBrowserLocked()`, which builds the browser through the `newAuthBrowser` seam with `browser.WithDialControl` and always calls `Close()` (including on login failure). The CLI passes `e.cfg.gate.DialControl()` through `pentestBuildAuthSessionWithControl`. Tests with a fake browser prove exact control propagation, teardown on error, and nil-control preservation.
- `internal/scanner/auth/auth.go`: the form-login `authClient` now installs the same control on its transport. `ClientWithDialControl` only covered the public client, so the login POST was a second uncontrolled egress path; both now share one `controlledTransport` helper.
- `internal/scanner/verify.go`: `NewVerifierWithControl` installs the dial check on the verifier client. Verification re-tests URLs taken from crawled (attacker-controlled) findings, so `pentestDeepScan` now passes the gate control instead of constructing `NewVerifier` directly.
- `internal/scanner/browser/guardproxy.go`: `GuardProxyOptions` exposes the guard flags + closer as a shared helper, extracted from `browser.New`. `internal/browserload` gains `NewRunnerWithControl` + `Runner.Close()` on top of it, so the independent Chromium load-test stack can no longer bypass the gate when it is wired into scanning.
- `internal/browserload/browser.go`: `NewRunner()` stays direct and is used only by tests/dev; there are no production callers. Any future production wiring must use `NewRunnerWithControl`.
- `internal/authz/proxy.go`: `ProxyWithControl` wraps a transport's proxy selector so the destination is re-checked with `CheckDialTarget` whenever an HTTP proxy carries the request. A `net.Dialer.Control` hook sees only the proxy address, so without this the Go HTTP clients that pair `ProxyFromEnvironment` with a dial control (form/login client, verifier, vulnerability scanner, plain-HTTP crawler) could be pointed at metadata/private space through an egress proxy while the socket check approved the proxy (CWE-290). This mirrors the existing `Guard.checkProxyTarget` behavior; it is a no-op with no proxy or no control. Unit tests prove the destination is refused before the proxy socket opens and that an approved destination still passes.
- `internal/engine/ws_client.go`: the load-test WebSocket dialer had the same CWE-290 gap — `ProxyFromEnvironment` plus a socket `Control` hook sees only the proxy. The dialer's proxy selector now goes through the same `authz.ProxyWithControl`, with an injectable proxy base for deterministic tests. `internal/engine/client.go`'s duplicate `proxyWithControl` now delegates to the shared helper so the two cannot drift.

Accepted residual: when an HTTP proxy carries a request, the destination is re-resolved and checked in the client process, but the proxy resolves and connects independently. A hostile proxy or a split-horizon/rebind between the two lookups can still reach a blocked address; this is the same accepted limit that already applied to `Guard.checkProxyTarget` and the engine clients. The only airtight path is the guard proxy, which dials the checked literal IP directly. This residual is not reachable on the pentest path without an operator-configured egress proxy.

Verification for this phase: seam-based auth tests, socket-level form-login and verifier control tests, proxy-environment CWE-290 tests (HTTP plus WebSocket), shared-helper and browserload option tests, CLI source-level wiring tests, plus the existing full Go and Chromium-gated suites.

### 8.4 Still out of scope (by design, not scan traffic)

Service integrations (notify/webhook/SIEM/Telegram, OIDC IdP, NVD, crt.sh, GitHub) use fixed or operator-configured endpoints and have no `scanner.Guard` in scope. The dist coordinator's gRPC worker dials, the local demo-store, and `replay`'s explicit destination allowlist are separate trust models. `EnsureAvailable()` navigates only `about:blank`. `internal/http3.checkAltSvc` has no production caller. None of these are on a pentest request path.

---

## 9. Egress-Gate Closure Audit (2026-11-23)

### 9.1 Method

A full-tree audit of every non-test `net.Dialer` / `Dial` / `Transport` / proxy / WebSocket / gRPC / QUIC site (95 call sites in 28 files) was run at `557f235` by three independent read-only security agents: scanner-path, engine-path, infra-path. Every claim was cross-verified centrally against source before any change. Agents were read-only; all edits, staging and git operations were performed by the CEO.

### 9.2 Confirmed scan-path gaps fixed in this phase

Three helpers on a normal `sift pentest` ran after the gate approved the target but bypassed the gate's socket decision. A DNS answer that flips to loopback/RFC1918/metadata between the initial reachability probe (`cmd_pentest.go:306`) and these phases was fetched with no `Control`, using `http.DefaultTransport` (whose proxy selector sees no destination re-check) or legacy nil-control `ScanHTTP`:

| Helper | Phase | Impact | Fix |
|---|---|---|---|
| `pentestMiniLoadTest` | wrap-up, **default enabled** (`--skip-load-test=false`) | 50 unguarded GETs to the full target URL; stable SSRF/DoS primitive | `pentestMiniLoadTestWithControl` via `core.NewHTTPClientWithControl` |
| `pentestScanTech` | discovery, step 1 | Ungated `Server`/`X-Powered-By` and `ScanHTTP` probes leak internal headers into the report | `pentestScanTechWithControl` threading control to both `pentestHTTPGetWithControl` and the new `scanner.ScanHTTPWithControl` re-export |
| `pentestScanVulns` | assessment | Ungated CORS probe makes the connection even though only one header is read | `pentestScanVulnsWithControl` using the controlled HTTP helper |

`pentestHTTPGet` now delegates to `pentestHTTPGetWithControl(..., nil)`; all three new `*WithControl` helpers keep the legacy wrappers nil-preserving, so dev/tests retain the historical direct behavior. The CLI passes `e.cfg.gate.DialControl()` at all three production call sites. `core.NewHTTPClientWithControl` keeps `ErrUseLastResponse`, installs `Control` on both the plain and uTLS sockets, and sets no proxy — so behavior is unchanged except for the added gate decision.

Tests: socket-level allow/refuse for each controlled helper (public approval refuses loopback with `authz: refusing to connect`, loopback approval permits, nil preserves old behavior), plus a source-level CLI wiring test that all three call sites pass the gate control and no ungated call remains. Full gate: `gofmt`, `git diff --check`, `go vet ./...`, `go build ./...`, `go test ./... -count=1`, `go test -race ./cmd/sift ./internal/scanner`, `golangci-lint run ./...` (0 issues), `gitleaks`, `actionlint`, and `GOOS=windows GOARCH=amd64 go build ./...` — all green.

### 9.3 Deferred findings (separate trust models, not fixed here)

The same audit found issues outside the scan gate; they are deliberately excluded from this commit and tracked for separate phases:

- ~~**`internal/replay/engine.go` (HIGH, separate CLI trust model).** `sift-replay` uses a bare `http.Transport` with no `Control`; `CheckRedirect` follows cross-host/scheme redirects without pinning to the initial target, and captured custom headers survive the redirect. `--base-url` is a pre-resolution string rewrite, not a post-resolution allowlist. A HAR from an attacker plus a redirect can reach metadata/private space and write the response into the JSON report.~~ **FIXED in §9.4.**
- ~~**`internal/dist/coordinator/master.go` (MEDIUM, control-plane).** `RegisterRequest.Address` is only checked for non-emptiness; with the default empty master token and attestation disabled, an unauthenticated gRPC caller can register an arbitrary address that `ResolveWorkers` later dials via an ungated `dialWorker`, giving a reachability oracle and scenario/token leak. Needs fail-closed auth, address validation/allowlist and rate limiting.~~ **FIXED in §9.6.**
- ~~**`internal/http3/h3.go` (LOW, latent).** QUIC and Alt-Svc TLS dials have no control path, but no production caller exists.~~ **FIXED in §9.5.**
- ~~**`internal/engine/raw_client.go` (LOW, adjacent).** The TCP session pool is keyed by `userIndex` only, not target; with `Session=true` and a variable target, a socket authorized for one destination can be reused for another — cross-target misdelivery, not a new ungated egress.~~ **FIXED in §9.5.**
- **Infra audit verdict:** every dial in `cmd/sift-worker`, `audit360/orchestrator.go`, `authz/notify.go` and `dist/coordinator/auth.go` is operator-configured or already gated; no scan-derived URL reaches a "fixed endpoint" client. The §8.4 out-of-scope classification is confirmed for scan traffic.
- **Accepted residual (unchanged):** `authz.ProxyWithControl` re-resolves and checks the destination in the client process, while an HTTP proxy resolves independently; a hostile/split-horizon proxy can still reach a blocked address. Documented in `internal/authz/proxy.go` and §8.3.

### 9.4 Replay engine egress closure (2026-11-23, Phase 2)

The HIGH replay finding from §9.3 is fixed in a separate commit because `sift-replay` is an independent CLI trust model, not scan traffic.

- **Socket-level gate:** `ReplayConfig` gained a runtime-only `DialControl` (`json:"-"`). `NewReplayWorker` installs it as `net.Dialer.Control` on the transport *only when non-nil*, and layers `authz.ProxyWithControl(http.ProxyFromEnvironment, control)` so a proxy hop re-checks the destination. Nil keeps the historical bare transport (`DialContext == nil && Proxy == nil`), asserted by test. The engine transport pattern was chosen over `core.NewHTTPClientWithControl` because the latter forces `ErrUseLastResponse` (breaking `--follow-redirects`) and drops replay's `TLSKeys`/`SkipTLSVerify` TLS settings.
- **Redirect pin:** `internal/replay/redirect.go` `replayRedirectCheck` pins every hop's `URL.Host` **and** `URL.Scheme` to `via[0]` (host includes the port), keeps the 10-hop cap, and re-checks each hop with `authz.CheckDialTarget` when a control is present. This stops captured custom headers (e.g. `X-Api-Key`, which Go forwards cross-host) from leaking and stops a foreign response body entering the JSON report — the refused hop returns `ErrUseLastResponse`, so only the 302 is recorded. Pinning is unconditional, including with a nil control: cross-host/scheme redirects are now refused by design. Same-host redirects are unaffected.
- **CLI gate:** `cmd/sift-replay/authz.go` `replayDialControl(--base-url)` classifies the operator-named target with `authz.Classify`, hard-refuses `ClassMetadata`, and returns `authz.DialControl(target.Class())`. `cmd/sift` is a separate `main` package so its gate builder is not importable; the base URL is treated as the explicit approval. An empty base URL leaves the control nil (historical direct replay to capture hosts) — documented residual below.

Tests (`internal/replay/engine_control_test.go`, `cmd/sift-replay/authz_test.go`): cross-host redirect refused (302 kept, foreign target sees 0 requests and no dial), same-host redirect allowed, both scheme-change directions refused, captured `X-Api-Key` not forwarded cross-host, loopback refused under a public approval at the socket, metadata base URL/hostname refused, and nil control preserves the historical transport + redirect behavior. Full gate: `gofmt`, `go build ./...`, `go test ./internal/replay/... ./cmd/sift-replay/... -count=1`, `go test -race ./internal/replay/...`, `go vet ./internal/replay/... ./cmd/sift-replay/...` — all green.

**Residuals (unchanged / documented):** (1) with neither `--base-url` nor any gate, the socket control stays nil — redirect pinning still applies, but there is no socket-level approval for replaying straight to capture URLs; closing this requires deriving a gate from every captured URL (out of scope). (2) `sift-replay` still lacks the full `cmd/sift` policy/ticket/audit gate (class-based approval only; no `--authorized`/`--policy`). (3) the `authz.ProxyWithControl` split-horizon residual from §8.3 holds.

### 9.5 HTTP/3 dial-control and raw TCP pool target-keying (2026-11-23, Phase 4)

Two LOW findings from §9.3 are fixed here. No production H3 caller exists yet; this makes the scan path ready rather than adding integration.

- **HTTP/3 control path** (`internal/http3/h3.go`): `ProbeOptions` gained a runtime-only `DialControl`. The Alt-Svc TCP leg installs it as `net.Dialer.Control`. For QUIC, quic-go v0.59.1's `DialAddr` opens its own UDP socket with no hook, so the controlled path uses `net.ListenConfig{Control: ...}.ListenPacket` → `&quic.Transport{Conn: udpConn}` → `tr.Dial`; both transport and socket are closed by the caller. `ListenConfig.Control` sees the local address, so the wrapper passes the already-resolved destination to the gate while handing it the real `RawConn`. Nil control keeps the exact original paths (`quic.DialAddr` / bare `net.Dialer`); `Probe` and `checkAltSvc` are nil-preserving wrappers.
- **Raw TCP pool target-keying** (`internal/engine/raw_client.go`): `tcpConns` (type fixed at `map[int]net.Conn`) now stores a `tcpSession{Conn, target}` wrapper. `takeTCPConnForTarget` reuses a socket only when the target matches; a mismatch closes the old socket and deletes the entry so the next dial runs through the existing gated `net.Dialer{Control: e.dialControl}` path. Legacy `takeTCPConn`/`putTCPConn` signatures and behavior are unchanged; the non-session path is unaffected.

Tests (`internal/http3/h3_control_test.go`, `internal/engine/raw_client_pool_test.go`) use in-process TLS + QUIC listeners: TCP/UDP control callback receives the resolved peer and a real `RawConn`, gate refusal aborts the dial, nil control matches legacy results, same-target session reuses one socket while a changed target re-dials and closes the old socket (asserted by server-side accept/close counters), and non-session path dials every call. Full gate: `gofmt`, `go build ./...`, `go test ./internal/http3/... ./internal/engine/... -count=1`, `go test -race ./internal/http3/... ./internal/engine/...`, `go vet ./internal/http3/... ./internal/engine/...` — all green.

**Residuals:** (1) no production caller wires `ProbeOptions.DialControl` yet (no H3 caller exists); (2) for a DNS QUIC target only the single `ResolveUDPAddr` answer reaches the UDP hook, unlike `authz.CheckDialTarget`'s check-every-answer semantics — no new ungated egress, and out of scope for this minimal fix.

### 9.6 Dist master registration control-plane closure (2026-11-23, Phase 5)

The MEDIUM master finding from §9.3 is fixed. Not scan traffic; §8.4's classification holds.

- **Fail-closed Register** (`internal/dist/coordinator/master.go`): registration is refused when the master has no token, no pinned worker keys and no attestation requirement. The check runs before any hostname resolution, so a no-token master cannot serve as a DNS probe. A shared token is enforced by the existing gRPC `ServerOptions(token)` unary/stream interceptors in `cmd/sift-master`; a pin or attestation requirement is enforced in `Register` itself (attestation without any pinned key is also refused — there is no trust anchor to verify a proof against). Static `--workers` fleets never call `Register` and are unaffected.
- **Address policy** (`internal/dist/coordinator/register_address.go`): strict `host:port` (non-empty host, numeric port 1–65535). IP literals are classified with `authz.ClassifyIP`; hostnames go through `authz.CheckDialTarget`, so **every** DNS answer must pass. Default allows only `ClassPublic`; the new `--allow-private-workers` opt-in additionally allows loopback and RFC1918. CGNAT, link-local, multicast, reserved and metadata are always denied, even with the opt-in. Registration is rejected before the address is stored or dialed.
- **Connect-time re-check** (`gatedDialWorker`): `Master.Connect` re-runs the policy for discovered addresses before `dialWorker`, closing a re-registration/resolution race. Addresses in `cfg.Workers` are operator-chosen and keep the original dialer.
- **Rate limit** (`internal/dist/coordinator/register_rate.go`): dependency-free fixed window of 30 attempts / 10 s keyed by gRPC peer IP (worker id for in-process callers, 4096-bucket sweep). This is a flood brake, not an authentication gate.

Tests (`master_register_validation_test.go` plus updated fleet/attestation/integration tests): default refusal of loopback/RFC1918/link-local/metadata/CGNAT/multicast/reserved and malformed addresses with explanatory messages, public accepted by default, private only with the opt-in, no-auth-anchor refused (token, pins and attestation all absent), pinned+attested worker still registers through challenge-response, static `--workers` dial path unaffected, re-registration replaces the entry, per-source rate limit, and connect-time re-check refusing a blocked address before the socket dialer is reached. Full gate: `gofmt`, `go build ./...`, `go test ./... -count=1`, `go test -race ./internal/dist/coordinator/...`, `go vet ./...` — all green (the worktree-only `TestInprocFindProjectRoot` failure was a directory-name artifact, absent in the real checkout).

**Operator impact:** auto-discovery fleets with no token, no pins and no attestation must now configure one of them; private/loopback self-registration additionally needs `--allow-private-workers`. The flag help text documents both changes.

**Residual:** for hostname registrations a DNS rebinding race remains between the final policy check and the `net.Dialer` inside `dialWorker`. IP-literal registrations (the normal case) are exact. Closing it cleanly requires a `Control` hook on gated dials and a refactor of the shared `dialTCP` test stub; left out of this minimal fix.

---

Security Engineer, 2026-11-20. As a result of the audit, `docs/SECURITY-AUDIT-2026-11-20.md` was created; the F-01/F-02 fixes are documented in §6, the additional work on 2026-11-21 is documented in §7, the browser-crawl DialControl closure on 2026-11-22 is documented in §8, and the egress-gate closure audit, Phase 1 pentest scan-path fixes, Phase 2 replay engine egress closure, Phase 4 HTTP/3 + raw pool hardening and Phase 5 dist master registration closure on 2026-11-23 are documented in §9. All integration and git operations were performed by the CEO.
