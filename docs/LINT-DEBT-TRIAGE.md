# LINT DEBT TRIAGE — sift

**O'lchov:** 2026-11-20, HEAD `773fa56` (main), golangci-lint v2.14.0 (go1.26.11).
**Jami:** 738 issue, 138 ta `.go` fayli. Tool ishladi, raqamlar haqiqiy hisobot chiqishidan olingan.
**Yangilash (2026-11-21):** 1-bosqichdan keyin **510** issue qoldi — §7 ga qarang.

## 1. O'lchov usuli va konfiguratsiya

```sh
golangci-lint run ./... \
  --output.json.path=<tmp>/sift-lint.json \
  --issues-exit-code 0
```

- Konfiguratsiya: `.golangci.yml` (standard + `errcheck`, `gocritic`, `gosec`, `govet`,
  `ineffassign`, `misspell`, `revive`, `staticcheck`, `unconvert`, `unused`;
  formatters `gofmt`, `goimports`). `govet`, `misspell`, `gofmt` — **0** issue.
- `--issues-exit-code 0` faqat chiqish kodini o'zgartiradi; issue soniga ta'sir qilmaydi.
- `max-issues-per-linter: 0`, `max-same-issues: 0` — hech narsa qisqartirilmagan;
  `uniq-by-line` default holatda. JSON hisobotda aynan 738 ob'ekt bor.
- Aniqlik: `.golangci.yml:73-78` izohida HEAD `605dc57` uchun **755** ta qayd etilgan;
  hozirgi HEAD da **738** (-17). Ratchet `only-new-issues: true` aslida
  `.github/workflows/ci.yml:71` da (`golangci-lint-action@v7`), `.golangci.yml` da
  faqat izoh mavjud.

## 2. Linter bo'yicha

| Linter | Son | Ulush | Xarakter | Misol (`fayl:qator`) |
|---|---:|---:|---|---|
| errcheck | 365 | 49.5% | asosan shovqin, oz qismi tekshirishga arziydi | `internal/report/report.go:212` |
| revive | 172 | 23.3% | sof stil / API nomi | `internal/audit360/manager.go:36` |
| staticcheck | 118 | 16.0% | aralash: quickfix + haqiqiy SA topilmalari | `cmd/sift/cmd_pentest_generate.go:67` |
| gocritic | 32 | 4.3% | stil | `cmd/sift/cmd_pentest_generate.go:205` |
| unused | 28 | 3.8% | o'lik kod (17 tasi testda) | `cmd/sift-master/main.go:48` |
| goimports | 8 | 1.1% | avtoformat | `cmd/sift/cmd_pentest_generate.go:10` |
| ineffassign | 6 | 0.8% | haqiqiy, kichik | `cmd/sift-worker/main.go:300` |
| gosec | 5 | 0.7% | 4 tasi noto'g'ri musbat/pas xavf, 1 hardening | `internal/attest/trust.go:339` |
| unconvert | 4 | 0.5% | stil | `cmd/sift-dashboard/main.go:383` |

## 3. Qoida bo'yicha (738 ta)

| Qoida | Son | Ulush |
|---|---:|---:|
| errcheck (barcha) | 365 | 49.5% |
| revive / exported-comment | 152 | 20.6% |
| staticcheck QF1012 (`WriteString(fmt.Sprintf(...))`) | 72 | 9.8% |
| unused | 28 | 3.8% |
| gocritic ifElseChain | 25 | 3.4% |
| revive / stutter | 16 | 2.2% |
| goimports | 8 | 1.1% |
| staticcheck QF1001 (De Morgan) | 7 | 0.9% |
| staticcheck S1009 (ortiqcha nil-tekshiruv) | 7 | 0.9% |
| ineffassign | 6 | 0.8% |
| gosec (G602×2, G304×2, G301×1) | 5 | 0.7% |
| staticcheck SA9003 (bo'sh branch) | 5 | 0.7% |
| staticcheck SA1019 (deprecated API) | 5 | 0.7% |
| gocritic singleCaseSwitch | 4 | 0.5% |
| revive / comment-format | 4 | 0.5% |
| unconvert | 4 | 0.5% |
| qolgan 18 qoida (SA6002×3, S1031×3, SA4009×2, S1039×2, S1024×2 va 1 tadan) | 25 | 3.4% |

## 4. Haqiqiy muammo yoki stil/shovqin

| Kategoriya | Son | Baho va asos | Misol |
|---|---:|---|---|
| errcheck / `fmt.Fprint*` | 323 | 88.5% errcheck: 288 `w`, 18 `out`, 11 `pt.out`, 4 `tw`, 1 `w.out`, 1 `os.Stdout`. Chiqish oqimiga yozish; `Render(w io.Writer)` kabi imzolarda xatoni qaytarish yo'q → **asosan shovqin**, lekin `io.Writer` xatolari (yopiq pipe, disk to'lish) yashirinadi | `internal/report/report.go:212` |
| errcheck / `Close` + `RemoveAll` | 42 | 41 `defer x.Close()` + 1 `defer os.RemoveAll(tmpDir)` → resurs tozalash xatosi yashirinishi mumkin, **ko'rib chiqish kerak** | `internal/dashboard/insights_bounty.go:332`, `cmd/sift-worker/main.go:296` |
| revive / exported-comment | 152 | **Sof stil**: faqat doc comment yo'q. 33 fayl, 21 tasi `internal/metrics/metrics.go` da | `internal/audit360/manager.go:36` |
| QF1012 | 72 | **Stil/avto-tuzatish**: 6 fayl, 40 tasi `cmd_pentest_generate.go` da; xatti-harakat o'zgarmaydi (`strings.Builder` yozuvda xato qaytarmaydi) | `cmd/sift/cmd_pentest_generate.go:67` |
| unused | 28 | 17 tasi testda; 11 tasi production: o'lik kod/flag → **haqiqiy**, lekin xavfsiz o'chirish | `cmd/sift-master/main.go:48` (`timeline` flag o'qilmaydi) |
| ifElseChain / singleCaseSwitch | 29 | **Stil**, refactor xavfi past | `cmd/sift/cmd_pentest_print.go:437` |
| revive / stutter | 16 | Eksport qilingan nomlarni o'zgartirish talab qilinadi → **API buzilishi xavfi**, hozircha tark etish ma'qul | `internal/certificate/certificate.go:659` |
| gosec | 5 | G602×2 — **noto'g'ri musbat** (`certificate.go:723` da `if i == 0 { continue }`, `hostxray/report.go:408` da `if i <= 0` bor); G304×2 — **dev-only** (`SIFT_DASHBOARD_DEV_ASSETS=1`, nomlar hardcode: `index.html`, `style.css`); G301 — 0o755 → **kichik hardening** | `internal/attest/trust.go:339` |
| SA1019 | 5 | **Haqiqiy**: deprecated `crypto/ecdsa.PublicKey.X/Y` (Go 1.26), `elliptic.Curve.IsOnCurve`, `http2.Transport` | `internal/oidc/oidc.go:545` |
| SA9003 / SA6002 / SA4009 | 10 | **Haqiqiy signal**: bo'sh branchlar, `sync.Pool.Put([]byte)` allocation, `ctx` ishlatilishdan oldin ustiga yozilishi | `internal/store/memstore/memstore.go:55`, `internal/engine/buffer_pool.go:97` |

## 5. 1-bosqich taklifi: eng ko'p muammo beradigan 3 qoida

| Qoida | Yo'q qilinadi | Jami ulush | Ish hajmi (taxmin) | Risk |
|---|---:|---:|---|---|
| errcheck (365) | 365 | 49.5% | 48 fayl: 323 `Fprint*` ni `_ = fmt.Fprint*(...)` yoki bitta helper bilan ifodalash; 42 `Close`/`RemoveAll` ni alohida audit qilish — **1-2 kishi-kuni + review** | past, lekin yozish xatolarining aniq yashirilishi yozib qo'yilishi shart |
| revive / exported-comment (152) | 152 | 20.6% | 33 faylga doc comment qo'shish — **~0.5-1 kishi-kuni** | deyarli yo'q (faqat comment) |
| QF1012 (72) | 72 | 9.8% | 6 faylda `WriteString(fmt.Sprintf(...))` → `fmt.Fprintf(&b, ...)`; `--fix` bilan sinash mumkin (scratch branchda) — **~0.5 kishi-kuni** | past |

**Jami: 589 / 738 = 79.8%** muammo yo'qoladi, qoladi 149 ta (20.2%).
Tavsiya etilgan bajarish tartibi: QF1012 → revive comment → errcheck (eng katta, lekin eng ko'p faylga tegadi).

## 6. Nega `only-new-issues` ratchet hozircha olinmasligi kerak

1. 738 ta mavjud topilma 138 faylga tarqalgan; ratchetsiz **har bir** PR lint job'ida qizil bo'ladi,
   o'zgartirish bilan bog'liq bo'lmagan qarz tufayli CI signali yo'qoladi.
2. Ratchet yangi muammolarning **hammasini** o'chiradi (CI da `only-new-issues: true`), shuning uchun
   regression yashirilmaydi — faqat eski qarz blok qilmaydi.
3. `.golangci.yml` izohida qayd etilgan 755 → 738 dinamikasi qarz kamayayotganini, lekin 0 dan
   uzoqligini ko'rsatadi; 1-bosqichning o'zi 79.8% ni qoplasa ham 149 ta qoladi.
4. Olib tashlash mezoni: `golangci-lint run ./...` **0 issue** berishi (yoki barcha qarzdor
   qoidalar uchun aniq, hujjatlashtirilgan suppressiya) va bir necha ketma-ket CI run yashil o'tishi.

## 7. 1-bosqich bajarildi (2026-11-21)

4 ta parallel agent 44 ta faylda ishladi. Natija: **735 → 510** issue (-225, -30.6%).

| Linter | Oldin | Keyin | Izoh |
|---|---:|---:|---|
| staticcheck | 116 | 44 | **QF1012 72 → 0** (barchasi `_, _ = fmt.Fprintf(&b, ...)` ga o'tkazildi, errcheck soni oshmadi) |
| revive | 172 | 19 | **exported-comment 152 → 0** (doc comment qo'shildi); qolgan 19 — asosan `stutter` (API buzilishi xavfi, ataylab tegilmadi) |
| errcheck | 365 | 365 | 2-bosqichga qoldirildi (§5) |
| gocritic / unused / goimports / ineffassign / gosec / unconvert | 82 | 82 | 2-bosqichga qoldirildi |

Verification: `gofmt`, `go vet ./...`, `go build ./...`, `go test`, `go test -race`, integration,
`gitleaks`, `actionlint`, `helm lint`, `goreleaser check` — barchasi PASS.

**Ratchet hali olinmaydi:** 510 ta qarz qolmoqda (§6 mezoni bajarilmadi).

## Cheklovlar

- Ushbu hisobot 2026-11-20 da yaratilgan; §7 2026-11-21 dagi 1-bosqich natijalarini qo'shadi.
  `.golangci.yml` va CI fayllari o'zgartirilmadi; ular `only-new-issues: true` ratchet'ni saqlaydi.
- Hisob `.golangci.yml` exclusionlari bilan olingan: testlardagi errcheck/gosec/gocritic chiqarilgan
  (izohda exclusion olib tashlanganda **+295** qo'shimcha topilma o'lchangani qayd etilgan — bu raqam
  mazkur o'lchovga kirmaydi); `.pb.go` va ikki scanner fayli ham chiqarilgan. To'liq gosec faqat
  alohida `security` CI job'ida baseline bilan ishlaydi.
