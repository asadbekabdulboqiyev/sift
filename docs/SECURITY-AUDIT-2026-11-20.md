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

### 8.3 Residual (tracked separately)

`internal/scanner/auth/auth.go:loginBrowserLocked()` (`--auth-browser-login-url`) still calls `browser.New()` with no control. Its navigation target is the operator-configured login URL, not attacker-controlled crawled content, so it does not expose the DOM-SSRF primitive from §8.1 in the same way; it is nonetheless the same unwired second process. Recommended follow-up: thread the gate's `DialControl` through `AuthConfig` into `loginBrowserLocked()`. Not changed in this phase to keep the commit scoped to the confirmed crawl finding.

`internal/browserload/browser.go` (`NewRunner()`/`Run()`) is a second, independent chromedp stack with no dial control. It has no production callers at this HEAD (tests only), so it is not on any pentest request path; it would need the same guard-proxy treatment before being wired into scanning.

---

Security Engineer, 2026-11-20. As a result of the audit, `docs/SECURITY-AUDIT-2026-11-20.md` was created; the F-01/F-02 fixes are documented in §6, the additional work on 2026-11-21 is documented in §7, and the browser-crawl DialControl closure on 2026-11-22 is documented in §8. All integration and git operations were performed by the CEO.
