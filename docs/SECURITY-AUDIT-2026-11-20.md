# Xavfsizlik auditi — Sift v0.18.1 (2026-11-20)

> **BU LOKAL AUDIT. Uchinchi tomon pentest EMAS. Compliance sertifikati EMAS.**

## 1. Scope va metodologiya

| Element | Qiymat |
|---|---|
| Repo | `/Users/asadbek/sift` |
| Branch / HEAD | `main` / `773fa564f5ef64546dcffd0bd7160bf43c2b18fb` |
| Sana | 2026-11-20 |
| Usul | Statik manba ko'rib chiqish va chaqiruv zanjirlarini qidirish (`rg`/`grep`) |
| Bajarilmagan ishlar | Ilova ishga tushirilmadi; DAST/tarmoq skaneri, dependency scanner, ekspluatatsiya urinishlari yo'q |

Ko'rib chiqilgan yo'nalishlar: authz/RBAC va `DialControl`, CSRF/rate limiting/CSP, sertifikat verifikatsiyasi (CWE-347/345), HTTP/3 TLS, OIDC token loglash va JWT tekshiruvi, fingerprint dialeri, port validatsiyasi, dashboard JS XSS, insights fayl yo'llari, coordinator TLS, CLI auth ulanishi.

Hisobot ustida ishlayotganda ishchi daraxt quyidagi **bog'liqsiz** o'zgarishlarga ega edi (ba'zilari tekshiruv davomida paydo bo'lgan): `.github/workflows/release.yml`, `internal/engine/raw_client_leak_test.go`, `internal/evidence/evidence_unit_test.go`, `internal/hostxray/report_test.go`, `internal/shared/atomicfile_test.go` (o'zgartirilgan); `docs/LINT-DEBT-TRIAGE.md`, `internal/finding/confidence_json_test.go`, `internal/secrets/resolver_table_test.go`, `internal/store/postgres/pure_unit_test.go`, `internal/tenant/context_behavior_test.go` (yangi). Ular ushbu audit tomonidan yaratilmagan yoki o'zgartirilmagan va hisobot doirasiga kirmaydi. Yagona yaratilgan fayl — `docs/SECURITY-AUDIT-2026-11-20.md`. Production kodiga tegilmadi; `git add` / `git commit` / `git push` bajarilmadi.

## 2. Aniq cheklov

**BU LOKAL AUDIT, uchinchi tomon pentest EMAS, compliance sertifikati EMAS.**

- Mustaqil uchinchi tomon eksperti, pentest firmasi, tashqi skaner yoki sertifikatlovchi organ ishtirok etmadi.
- Hech qanday ekspluatatsiya, tarmoq skanlash, DAST yoki live test o'tkazilmadi; barcha xulosalar kod o'qishga asoslangan.
- Ushbu hujjat SOC 2, ISO 27001, GDPR yoki boshqa compliance talablariga muvofiqlikni tasdiqlamaydi.
- "Topilmadi" degan yozuv faqat **ko'rib chiqilgan kod doirasida tasdiqlangan zaiflik yo'q** degan ma'noni anglatadi; tizimda zaiflik yo'qligini isbotlamaydi.

## 3. Topilmalar jadvali

| ID | Daraja | Fayl:qator | Dalil (kod iqtibosi) | Ekspluatatsiya ehtimoli | Tavsiya | Holat |
|---|---|---|---|---|---|---|
| F-01 | O'rta | `cmd/sift/cmd_run_execute.go:19-29`, `cmd/sift/dash_mode.go:165-175`, `cmd/sift-dashboard/main.go:158-170` | `dashboardAuthOptions` faqat `Tokens`, `APIKeyHashes`, `AllowedOrigins`, `RateLimit*`, `TrustProxy`, `AllowAnonymous` qaytaradi; `OIDCIssuer`/`RBACEnabled`/`RBACRole` yo'q. `dash_mode.go:167-169`: `case dashAuth.HasCredentials(): auth = srv.ApplyAuth(dashAuth)`. `sift-dashboard/main.go:166-170` da esa `OIDCIssuer: oidcIssuer`, `RBACEnabled: *authRBACEnabled`, `RBACRole: authRBAC` bor. `rg` bilan `cmd/sift` ichida `auth-oidc`/`auth-rbac`/`OIDCIssuer` topilmadi. | Past-O'rta: faqat `sift run --dashboard` yo'li va operator RBAC kutgan hollarda; non-loopback uchun auth majburiy (`dash_mode.go:158-163`). | `sift run` ga OIDC/RBAC flaglarini qo'shib `AuthOptions` ga uzatish, yoki hujjatda RBAC faqat `sift-dashboard` da mavjudligini aniq yozish va noto'g'ri kutilganda ogohlantirish. | **TUZATILDI** — §6 |
| F-02 | O'rta | `cmd/sift/cmd_certificate.go:69`, `internal/certificate/certificate.go:797-820`, `cmd/sift/cmd_verify.go:362-366` | `fs.BoolVar(&require, "require-anchor", false, "fail unless the signer is in the trust store")`; `case store == nil: check.Status = attest.IssuerUnpinned`; keyin `Verify(c)` muvaffaqiyatli bo'lsa, faqat `case check.Status == attest.IssuerUnpinned && requireAnchor:` da xato. `loadVerifyTrustStore` default store yo'q va flag o'chirilganda `return nil, nil` qaytaradi. | O'rta: trust store fayli o'rnatilmagan muhitlarda o'z-o'zidan imzolangan, lekin ichki jihatdan to'g'ri sertifikat tasdiqlanadi (status `IssuerUnpinned`, chiqish kodi 0). | Verification uchun `require-anchor` default `true` qilish yoki `--allow-unpinned` ni aniq opt-in qilish; hujjatda hozirgi default ni ochiq yozish. | **TUZATILDI** — §6 |

### F-01 dalili (to'liq iqtibos)

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
// cmd/sift/dash_mode.go:167-169 — RBAC sozlanishi yo'q
case dashAuth.HasCredentials():
	auth = srv.ApplyAuth(dashAuth)
	defer auth.Close()
```

```go
// cmd/sift-dashboard/main.go:166-170 — boshqa entry point da to'liq ulanish bor
OIDCIssuer:     oidcIssuer,
OIDCClientID:   oidcClientID,
OIDCRoleClaim:  "role",
RBACEnabled:    *authRBACEnabled,
RBACRole:       authRBAC,
```

### F-02 dalili (to'liq iqtibos)

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

### Topilmadi / baholanmadi

**Topilmadi (ko'rib chiqilgan kod doirasida):**

- **XSS:** `internal/dashboard/assets/app-05-render.js:277` dagi `row()` qiymatni `esc(val)` bilan chiqaradi; `:358` dagi `body.innerHTML = html` oldindan escape qilingan ma'lumotni oladi. `app-14-insights.js:16-29` dagi `esc()` va `setOut()` chaqiruvlari ham shunday. Tasdiqlangan XSS topilmadi. `app-07-init.js:188-193` dagi `new Function(...)` faqat hardcoded `map` dan keladi; u XSS emas, lekin CSP `script-src 'self'` (`security.go:74-83`) bilan ziddiyat bo'lishi mumkin (funksionallik masalasi).
- **Path traversal:** `internal/dashboard/insights_helpers.go:15-43,98-126` da yo'l containment va sanitize mavjud; topilmadi.
- **Maxfiy ma'lumotlarning log'ga chiqishi (CWE-532):** `internal/oidc/oidc.go:314-351` da provider xato tanasi o'rniga faqat sanitized `error` kodi ishlatiladi; topilmadi.
- **DNS rebinding:** `internal/authz/dial.go:30-40,54-89` va `internal/engine/client.go:55-98,110-134` da soket darajasida qayta tekshirish bor; tasdiqlangan bypass topilmadi.

**Baholanmadi (shu audit doirasida):** SQL/NoSQL/command injection, XXE, dependency vulnerability scan, runtime va tarmoq testlari. Bu kategoriyalar bo'yicha "topilmadi" degan xulosa berilmaydi.

## 4. Oldingi tuzatishlar holati

| Tuzatish | Holat | Dalil (fayl:qator + iqtibos) |
|---|---|---|
| Authz RBAC: path-first, fail-closed | **Tasdiqlandi** | `internal/dashboard/auth.go:216-227`: `if a.rbacEnabled { perm := permForPath(r.URL.Path, r.Method); if !a.rbacAllowed(...) { http.Error(w, "rbac: permission denied", 403) } }`; `:398-416`: `case strings.HasPrefix(path, "/api/admin"): return rbac.PermAdmin`, keyin `/api/audit`, `/api/run`, fallback `tests:run`/`tests:view`. Qamrov bo'yicha shubhali joy F-01 da. |
| `authz.DialControl` + `CheckDialTarget` | **Tasdiqlandi** | `internal/authz/dial.go:36-38`: `if got := ClassifyIP(ip); got.severity() > approved.severity() { return fmt.Errorf(...) }`; `:54-89`: bo'sh host/port, resolve xatosi yoki rad etilgan IP uchun xato. `internal/engine/client.go:58-62` `Control: control`, `:87-97` uTLS yo'lida `net.Dialer{Control: control}`, `:110-131` proxy yo'lida `authz.CheckDialTarget(...)`. |
| CSRF same-origin + 20 RPS / burst 40 | **Tasdiqlandi (browser doirasi)** | `internal/dashboard/security.go:25-38`: Origin bo'lsa scheme va host solishtiriladi; `internal/dashboard/auth.go:48-49`: `defaultAuthRPS = 20.0`, `defaultAuthBurst = 40`; `:173-183`: `a.rateEnabled = true` va nol qiymatlar default bilan to'ldiriladi; `:229-232`: `if !isSafeMethod(r.Method) && !a.originAllowed(r) { ... 403 }`. Cheklov: `security.go:27-29` da Origin yo'q klientlar qabul qilinadi — bu zaiflik emas, nomahalliy klientlar uchun atayin qilingan dizayn. |
| Sertifikat CWE-347 / CWE-345 | **Tasdiqlandi** | `internal/certificate/certificate.go:477-479`: `if err := validateV1Envelope(c); err != nil { return err }`; `:488-497`: imzolanmagan `validity_period`, `previous_certificate_hash`, `experiment_reference` rad etiladi; `:673-688`: `signedCertificateID` faqat signed maydonlardan; `:712-738`: `VerifyChain` genesis va hash zanjirini tekshiradi. |
| HTTP/3 TLS verification default | **Tasdiqlandi (kod darajasida)** | `internal/http3/h3.go:101-106`: `InsecureSkipVerify: opts.InsecureSkipVerify`, `ServerName: host`; `:120-126`: `InsecureSkipVerify: insecure` faqat opt-in. Production chaqiruvi topilmadi (faqat `internal/http3` ichidagi testlar). |
| CWE-532: IdP token redaction | **Tasdiqlandi** | `internal/oidc/oidc.go:314-320`: `tokenEndpointError` faqat `oauthErrorCode(body)` natijasini chiqaradi; `:337-351`: `sanitizeErrorCode` faqat 64 belgili ASCII kodlarga ruxsat beradi. |
| Fingerprint: panic yo'q + port validatsiyasi | **Qisman tasdiqlandi / shubhali** | Panic yo'q: `internal/fingerprint/fingerprint.go:133-139` `ErrUnknownProfile` qaytaradi, `:147-152` `NewDialer` ham xato bilan dial qaytaradi. Port: `internal/scanner/guard.go:493-497` `if err != nil || n < 1 || n > 65535`; `internal/dashboard/portscan.go:81-85` `if p < 1 || p > 65535`. Shubhali: `fingerprint.go:29` `Default Profile = ""` `:48-62` xaritada yo'q, `:109-123` `resolved()` uni qo'shmaydi — `NewDialerChecked(Options{})` xato beradi. Bu funksionallik/availability masalasi, xavfsizlik zaifligi emas; `internal/engine/client.go:78` dagi `if tlsFP != ""` sharti tufayli productionda chaqirilmaydi. |

## 5. Xavf qolgan jo'nalishlar

1. **F-01 — RBAC qamrovi.** ~~`sift run --dashboard` da RBAC yoqib bo'lmaydi~~ — §6 da tuzatildi: OIDC/RBAC flaglari qo'shildi.
2. **F-02 — trust anchor ixtiyoriy.** ~~Trust store bo'lmasa va `--require-anchor` berilmasa, `IssuerUnpinned` statusi xato emas~~ — §6 da tuzatildi: anchor default majburiy.
3. **OIDC JWKS filteri.** `internal/oidc/oidc.go:111-121` da `use` va `alg` maydonlari mavjud, lekin `:499-506` da faqat `kid` bo'yicha yuklanadi: `keys[k.Kid] = pub`. JWT tomonida algoritm qat'iy pinlangan (`:363-399`: faqat `RS256`/`ES256` + kalit turi tekshiruvi), shuning uchun xavf past; JWKS nazorati IdP da bo'lishi shart.
4. **Coordinator TLS.** `internal/dist/coordinator/tls.go:53-70`: CA ham, `-tls-skip-verify` ham berilmasa `return nil, nil` — plaintext ulanish; self-signed uchun `InsecureSkipVerify` opt-in. Productionda CA majburiy qilinishi kerak.
5. **Gate darajasidagi DNS xatosi.** `internal/dashboard/handlers_run.go:122-128`: classify xatosida `authz.ClassPublic, "", false` qaytariladi; lekin `:141-149` orqali bu class `authz.DialControl` ga uzatilib, soketda qayta tekshiriladi. Xavf past, lekin gate darajasida fail-open.
6. **HTTP/3 probe.** `internal/http3/h3.go:136`: `req := "GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n"` — xom Host qatoriga asoslangan; production chaqiruvi topilmadi, dinamik sinov qilinmadi. Kelajakda ulansa, `authz.DialControl` bilan birga tekshirish va host validatsiyasi talab qilinadi.
7. **Audit qamrovi.** Faqat statik ko'rib chiqish: dependency audit, DAST, runtime konfiguratsiya, tarmoq va ko'p ijarachi (multi-tenant) integratsiya testlari qamrab olinmadi. Uchinchi tomon pentesti bilan almashtirib bo'lmaydi.

---

## 6. Topilmalarning tuzatilishi (auditdan keyin, 2026-11-20)

Ikkala topilma ham foydalanuvchi ruxsati bilan tuzatildi. Kod o'zgarishlari
sifatida qayta tekshirildi (`go build ./...`, `go test ./cmd/sift/... ./cmd/sift-dashboard/... ./internal/certificate/... ./internal/dashboard/... -count=1` — yashil).

### F-01 — OIDC/RBAC flaglari `sift run --dashboard` da

| Fayl | O'zgarish |
|---|---|
| `cmd/sift/cmd_run_options.go` | `runOptions` ga `dashAuthOIDC`, `dashAuthRBAC`, `dashAuthRBACEnabled`; yangi flaglar: `--dashboard-auth-oidc`, `--dashboard-auth-rbac`, `--dashboard-auth-rbac-enabled` (default `false`). |
| `cmd/sift/cmd_run_execute.go` | `dashboardAuthOptions()` endi `OIDCIssuer`, `OIDCClientID`, `OIDCRoleClaim`, `RBACEnabled`, `RBACRole` ni uzatadi. OIDC `issuer:client_id` **oxirgi** `:` bo'yicha ajratiladi — URL issuer (port bilan) ishlaydi. |
| `cmd/sift/dash_mode.go` | Butun `AuthOptions` `ApplyAuth` ga uzatiladi; auth xabariga `oidc=%t rbac=%t` qo'shildi. |
| `cmd/sift-dashboard/main.go` | Audit paytida qo'shimcha topilma: `-auth-oidc` `SplitN(":", 2)` ishlatgani uchun URL issuer noto'g'ri parslanardi. `parseOIDCPairs()` orqali `LastIndex` ga o'tkazildi — ikki entry point izchil. |
| Testlar | `cmd/sift/cmd_run_dashboard_auth_test.go` (5 test), `cmd/sift-dashboard/main_oidc_test.go` (URL issuer + last-colon + malformed). |

Defaults o'zgarmadi: RBAC hali ham o'chirilgan holda boshlanadi; faqat imkoniyat qo'shildi.

### F-02 — trust anchor default majburiy

| Fayl | O'zgarish |
|---|---|
| `cmd/sift/cmd_verify.go`, `cmd/sift/cmd_certificate.go` | `--require-anchor` default `true`; yangi `--allow-unpinned` aniq opt-out. `resolveAnchorPolicy()` ziddiyatli flaglarni **xato bilan** rad etadi (jim zaiflashtirish yo'q): `--require-anchor=false` + `--allow-unpinned` izchil, ochiq `--require-anchor` + `--allow-unpinned` — ishlatish xatosi. Kutubhona API'si (`VerifyBytesWithTrust`, `VerifyPDF`) o'zgarmadi — bu faqat CLI siyosati. |
| `cmd/sift/cmd_trust.go`, `README.md`, `internal/certificate/html.go` | Yordam/guide/hujjat matnlari yangi default ni aks ettiradi. |
| `scripts/demo-verified.sh`, `scripts/verify-html-parity.sh` | O'z-o'zidan muhrlangan fixture'lar trust store'siz ishlaganligi sababli ularga `--allow-unpinned` qo'shildi —breaking change ularning self-consistency tekshiruvini buzmasligi uchun. |
| Testlar | `cmd/sift/cmd_require_anchor_f02_test.go` (7 test: default→exit 1, opt-out→VALID, pinned→VALID, ziddiyat, help). Eski CLI testlari o'z self-consistency niyatini saqlash uchun `--allow-unpinned` bilan yangilandi. |

**Breaking change (qasddan):** trust store'siz flagsiz `sift verify` / `sift certificate` endi exit 1 qaytaradi. Bu foydalanuvchi tasdiqlagan xavfsizlik siyosati; oldingi xatti-harakat faqat `--allow-unpinned` bilan qaytariladi.

### Qolgan xavflar (tuzatilmadi)

Trust store bo'lmasa va `--allow-unpinned` berilsa, status yana `IssuerUnpinned` va chiqish kodi 0 bo'ladi — bu endi **oniqli opt-in**, tasodifiy default emas. Uchinchi tomon pentest, DAST, dependency scan va compliance sertifikati hali ham yo'q (§2, §5.7).

---

Xavfsizlik Muhandisi, 2026-11-20. Audit natijasida `docs/SECURITY-AUDIT-2026-11-20.md` yaratildi; F-01/F-02 tuzatishlari §6 da hujjatlashtirildi. Barcha integratsiya va git operatsiyalarini Bosh Direktor bajardi.
