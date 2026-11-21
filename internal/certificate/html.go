package certificate

import (
	"fmt"
	"html"
	"strings"
)

// html.go — the printable certificate.
//
// # Two pages, because a certificate is not a report
//
// Page 1 is the certificate: who issued it, what was assessed, the verdict, the
// severity summary and the seal. It is a fixed A4 sheet, laid out in
// millimetres, so the print dialog cannot reflow it.
//
// Page 2 (the annex) carries the findings and the compliance mapping, and it
// flows: a run with forty findings gets more annex pages, and the certificate
// page still looks like a certificate. A single 400 mm page that a printer cuts
// in half is not a document, it is a bug.
//
// # Self-contained by requirement
//
// No external CSS, no web fonts, no JavaScript, no images. A school prints this
// on a cheap laser printer from a browser with no network, and it has to look
// the same there as it does on the machine that issued it.
//
// # The seal is outside the cryptographic boundary
//
// Everything from <div class="seal"> to its matching close is excluded from
// Assessment.DocumentSHA (see stripSeal in certificate.go). That is deliberate:
// the seal carries the signature, the certificate id and the validity period,
// and all three only exist after signing. Printing or saving the page must not
// change what was signed, so the marker must not move and the block must stay
// balanced.
//
// # The rule that keeps the hash stable
//
// Anything rendered OUTSIDE the seal must be known before signing, which means
// it may only come from the Assessment (plus the format version). Post-signing
// values — certificate id, validity, previous hash, signature — live inside the
// seal, never above it. Getting this wrong produces a certificate that fails its
// own verification, which is exactly what the tests check for.
//
// # Honesty rules that shape the wording
//
//   - It never claims the target is secure. It claims a specific assessment ran
//     and that this document is the one that was signed.
//   - It never imitates a state emblem or an official state blank. The stamp is
//     this project's own mark, and the page says what it means.
//   - Untested categories stay "NOT TESTED". No PASS is invented.

// DocumentMeta is the post-signing half of the certificate: values that only
// exist after Sign has produced a signature, and that live inside the
// hash-excluded seal. The zero value renders an empty seal, which is what the
// signing pass needs.
type DocumentMeta struct {
	Signature               string
	PublicKey               string
	SignedAt                string
	Version                 string
	CertificateID           string
	PreviousCertificateHash string
	ValidityPeriod          string
}

// RenderHTML renders the certificate as a self-contained, printable A4
// document. It is the historical signature, kept so callers that only have the
// five original values keep working; it renders the seal without a certificate
// id.
func RenderHTML(a Assessment, signature, publicKey, signedAt, version string) string {
	return RenderHTMLMeta(a, DocumentMeta{
		Signature: signature,
		PublicKey: publicKey,
		SignedAt:  signedAt,
		Version:   version,
	})
}

// RenderHTMLMeta renders the certificate with the full post-signing metadata.
// The seal block it produces is excluded from the document hash, so calling it
// a second time with a certificate id cannot invalidate a signature.
func RenderHTMLMeta(a Assessment, m DocumentMeta) string {
	version := strings.TrimSpace(m.Version)
	if version == "" {
		version = Version
	}
	signedAt := m.SignedAt
	if strings.TrimSpace(signedAt) == "" {
		signedAt = a.SignedAt
	}

	var rows strings.Builder
	for _, f := range a.Findings {
		_, _ = fmt.Fprintf(&rows,
			"      <tr><td class=\"sev\"><span class=\"badge b-%s\">%s</span></td><td>%s</td><td class=\"mono dim\">%s</td><td class=\"mono dim id\">%s</td></tr>\n",
			severityClass(f.Severity), html.EscapeString(strings.ToUpper(strings.TrimSpace(f.Severity))),
			html.EscapeString(f.Title), html.EscapeString(f.Evidence), html.EscapeString(f.ID),
		)
	}
	if rows.Len() == 0 {
		rows.WriteString("      <tr><td colspan=\"4\" class=\"dim\">No defects were recorded in the tested categories.</td></tr>\n")
	}

	var comps strings.Builder
	for _, ctl := range a.Compliance {
		_, _ = fmt.Fprintf(&comps,
			"      <tr><td>%s</td><td class=\"mono dim\">%s</td><td>%s</td><td class=\"status s-%s\">%s</td></tr>\n",
			html.EscapeString(ctl.Framework), html.EscapeString(ctl.ID), html.EscapeString(ctl.Title),
			statusClass(ctl.Status), html.EscapeString(strings.ToUpper(strings.TrimSpace(ctl.Status))),
		)
	}
	if comps.Len() == 0 {
		comps.WriteString("      <tr><td colspan=\"4\" class=\"dim\">No compliance controls were mapped.</td></tr>\n")
	}

	covered := make([]string, 0, len(a.Covered))
	for _, x := range a.Covered {
		covered = append(covered, html.EscapeString(x))
	}
	coveredText := strings.Join(covered, " &middot; ")
	if coveredText == "" {
		coveredText = "&mdash;"
	}

	total := a.Counts.Critical + a.Counts.High + a.Counts.Medium + a.Counts.Low + a.Counts.Info

	grade := strings.TrimSpace(a.Grade)
	if grade == "" {
		grade = "—"
	}
	verdict := strings.TrimSpace(a.Verdict)
	if verdict == "" {
		verdict = "—"
	}
	verdictHead, verdictDetail, verdictTone := splitVerdict(verdict)

	certID := strings.TrimSpace(m.CertificateID)
	if certID == "" {
		certID = "assigned on signing"
	}

	hasAnnex := len(a.Findings) > 0 || len(a.Compliance) > 0
	pageCount := "1"
	if hasAnnex {
		pageCount = "1 / 2"
	}

	var annex strings.Builder
	if hasAnnex {
		annex.WriteString(`
<div class="sheet annex">
  <div class="annexhead">
    <div class="wordmark small">Sift<small>Annex to the certificate</small></div>
    <div class="meta">
      ` + html.EscapeString(displayOrDash(a.Target)) + `<br>
      ` + html.EscapeString(displayTime(a.SignedAt)) + `
    </div>
  </div>
  <div class="rule"></div>

  <h2 style="margin-top:6mm">Findings</h2>
  <table class="findings">
    <thead><tr><th>Severity</th><th>Title</th><th>Evidence</th><th style="text-align:right">ID</th></tr></thead>
    <tbody>
` + rows.String() + `    </tbody>
  </table>

  <h2>Compliance mapping</h2>
  <table class="findings">
    <thead><tr><th>Framework</th><th>Control</th><th>Title</th><th>Status</th></tr></thead>
    <tbody>
` + comps.String() + `    </tbody>
  </table>

  <div class="annexfoot">
    This annex is part of the same signed document as the certificate page.
    Categories not listed here were not tested and are not claimed to pass.
  </div>
</div>
`)
	}

	return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sift — Security Assessment Certificate</title>
<style>
  /* A4, no margins: each sheet draws its own border so a print dialog cannot
     shift the frame or add a second white edge. */
  @page { size: A4 portrait; margin: 0; }
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; background: #eceff2; }
  body {
    font-family: "Iowan Old Style", "Palatino Linotype", Palatino, Georgia, "Times New Roman", serif;
    color: #1c2a33; line-height: 1.42;
    -webkit-print-color-adjust: exact; print-color-adjust: exact;
  }
  .sheet {
    position: relative;
    width: 210mm; margin: 8mm auto; background: #fdfcf8;
    box-shadow: 0 6px 24px rgba(13,43,69,.18);
    padding: 14mm 16mm 11mm;
  }
  /* The certificate page is exactly one sheet: it must not spill. Overflow is
     clipped at the border box, but the 11 mm bottom padding stays inside the
     clip, so a browser with slightly different font metrics loses nothing —
     text is only ever cut after 11 mm of grace. Without this, a 0.48 px
     rounding difference between the box (297 mm) and the paper pushes the
     footer onto a second page. */
  .sheet.page1 { height: 297mm; display: flex; flex-direction: column; overflow: hidden; }
  /* The annex flows: a long findings list legitimately runs onto more pages, so
     it carries no absolute frame — a frame would be cut in half at a page
     boundary. It gets a rule under its own masthead instead. It is a plain
     block on purpose: Chrome ignores a forced page break on a flex container,
     which would glue the annex onto the certificate's page. */
  .sheet.annex { min-height: 297mm; display: block; }

  /* Double frame: heavy navy outside, hairline gold inside. Certificate page
     only, for the reason above. */
  .sheet.page1::before {
    content: ""; position: absolute; inset: 6mm;
    border: 0.7mm solid #0d2b45; pointer-events: none;
  }
  .sheet.page1::after {
    content: ""; position: absolute; inset: 8mm;
    border: 0.25mm solid #b3893b; pointer-events: none;
  }

  .masthead { display: flex; align-items: flex-end; justify-content: space-between; gap: 8mm; }
  .wordmark { font-size: 19pt; font-weight: 700; letter-spacing: .34em; color: #0d2b45; text-transform: uppercase; }
  .wordmark small { display: block; font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; font-size: 6.4pt; letter-spacing: .18em; color: #6b7785; text-transform: uppercase; margin-top: 1mm; }
  .wordmark.small { font-size: 13pt; }
  .meta { text-align: right; font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; font-size: 6.8pt; letter-spacing: .06em; color: #6b7785; text-transform: uppercase; line-height: 1.7; }
  .meta b { color: #0d2b45; font-weight: 600; }

  .rule { height: 0.6mm; background: #0d2b45; margin: 4mm 0 0; }
  .rule.thin { height: 0.2mm; background: #b3893b; margin: 1.2mm 0 0; }

  .titleblock { text-align: center; margin: 8mm 0 6mm; }
  .titleblock h1 {
    font-size: 20pt; line-height: 1.15; margin: 0; letter-spacing: .06em;
    text-transform: uppercase; color: #0d2b45; font-weight: 600;
  }
  .titleblock .sub { margin-top: 2.2mm; font-size: 8.6pt; color: #6b7785; font-style: italic; }
  .titleblock .cid {
    margin-top: 3mm; font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Helvetica, Arial, sans-serif;
    font-size: 7.4pt; letter-spacing: .1em; color: #0d2b45; text-transform: uppercase;
  }

  .verdictrow { display: flex; align-items: center; gap: 6mm; margin: 0 0 5mm; }
  .medallion {
    flex: 0 0 auto; width: 24mm; height: 24mm; border-radius: 50%;
    border: 0.7mm solid #b3893b; display: flex; flex-direction: column;
    align-items: center; justify-content: center; background: #fffdf6;
  }
  .medallion .g { font-size: 20pt; line-height: 1; font-weight: 700; color: #0d2b45; }
  .medallion .l { font-family: ui-sans-serif, system-ui, sans-serif; font-size: 5.4pt; letter-spacing: .16em; text-transform: uppercase; color: #6b7785; margin-top: 0.8mm; }
  .verdictcopy { flex: 1 1 auto; }
  .verdictcopy .v { font-size: 12pt; letter-spacing: .14em; text-transform: uppercase; font-weight: 700; }
  .verdictcopy .vd { font-size: 8.6pt; color: #45525c; margin-top: 1mm; }
  .verdictcopy .t { font-size: 9pt; color: #45525c; margin-top: 1.2mm; }
  .v-pass { color: #1d6b4f; } .v-fail { color: #8c2b2b; } .v-warn { color: #8a5a12; }
  .stats { display: flex; gap: 6mm; flex-wrap: wrap; margin-top: 2.4mm; }
  .stat { font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; font-size: 6.6pt; letter-spacing: .1em; text-transform: uppercase; color: #6b7785; }
  .stat b { display: block; font-size: 12pt; letter-spacing: 0; color: #0d2b45; font-weight: 700; }

  h2 {
    font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Helvetica, Arial, sans-serif;
    font-size: 7.2pt; letter-spacing: .2em; text-transform: uppercase; color: #0d2b45;
    margin: 5mm 0 1.6mm; padding-bottom: 1mm; border-bottom: 0.2mm solid #d8cfae;
  }
  table { width: 100%; border-collapse: collapse; }
  .kv td { padding: 1.3mm 0; font-size: 8.8pt; vertical-align: top; border-bottom: 0.15mm solid #e6e1d3; }
  .kv td.k { width: 26%; color: #6b7785; font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; font-size: 7pt; letter-spacing: .08em; text-transform: uppercase; padding-top: 1.8mm; }
  .grid2 { display: flex; gap: 9mm; }
  .grid2 > div { flex: 1 1 0; }

  .findings th, .findings td { text-align: left; padding: 1.3mm 1.5mm; font-size: 8pt; vertical-align: top; border-bottom: 0.15mm solid #e6e1d3; }
  .findings th { font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; font-size: 6.4pt; letter-spacing: .14em; text-transform: uppercase; color: #6b7785; font-weight: 600; }
  .findings td.sev { width: 17mm; white-space: nowrap; }
  .findings td.id { width: 22mm; text-align: right; }
  .badge { display: inline-block; padding: 0.3mm 1.5mm; border-radius: 1mm; font-family: ui-sans-serif, system-ui, sans-serif; font-size: 6pt; font-weight: 700; letter-spacing: .08em; }
  .b-critical { background: #f7dede; color: #8c2b2b; }
  .b-high { background: #f9e4d8; color: #8c3f2b; }
  .b-medium { background: #fbf0d2; color: #8a5a12; }
  .b-low { background: #dfeee2; color: #1d6b4f; }
  .b-info { background: #e0e9f2; color: #0d2b45; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
  .dim { color: #6b7785; }
  .status { font-family: ui-sans-serif, system-ui, sans-serif; font-size: 6.6pt; font-weight: 700; letter-spacing: .08em; white-space: nowrap; }
  .s-pass { color: #1d6b4f; } .s-fail { color: #8c2b2b; } .s-not-tested, .s-skip { color: #6b7785; }

  .counts { display: flex; gap: 0; border-top: 0.2mm solid #d8cfae; border-bottom: 0.2mm solid #d8cfae; }
  .counts div { flex: 1 1 0; padding: 1.8mm 0; text-align: center; border-right: 0.15mm solid #e6e1d3; }
  .counts div:last-child { border-right: 0; }
  .counts .n { font-size: 12pt; font-weight: 700; color: #0d2b45; }
  .counts .n.zero { color: #b6bcc2; font-weight: 400; }
  .counts .c { font-family: ui-sans-serif, system-ui, sans-serif; font-size: 5.8pt; letter-spacing: .14em; text-transform: uppercase; color: #6b7785; }

  .spacer { flex: 1 1 auto; }

  /* ---- Seal: excluded from the signed document hash ---- */
  .seal { margin-top: 4mm; border-top: 0.4mm solid #0d2b45; padding-top: 3.4mm; }
  .seal .cols { display: flex; gap: 7mm; align-items: flex-start; }
  .seal .notes { flex: 1 1 auto; font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; font-size: 7pt; line-height: 1.45; color: #45525c; }
  .seal .notes .h { font-size: 6.2pt; letter-spacing: .16em; text-transform: uppercase; color: #6b7785; margin-bottom: 1mm; }
  .seal .notes code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 6.6pt; color: #0d2b45; background: #f2efe4; padding: 0.2mm 0.9mm; }
  .seal .sign { flex: 0 0 58mm; text-align: center; }
  .seal .stamp {
    width: 26mm; height: 26mm; margin: 0 auto 1.6mm; border-radius: 50%;
    border: 0.7mm double #b3893b; color: #0d2b45; transform: rotate(-7deg);
    display: flex; flex-direction: column; align-items: center; justify-content: center;
    font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Helvetica, Arial, sans-serif;
    font-size: 5pt; letter-spacing: .12em; text-transform: uppercase; line-height: 1.25;
    background: #fffdf6;
  }
  .seal .stamp .big { font-size: 7.4pt; letter-spacing: .22em; font-weight: 700; }
  .seal .sigline { border-top: 0.2mm solid #1c2a33; margin-top: 1mm; padding-top: 1mm; font-size: 7.2pt; }
  .seal .sigline .role { font-family: ui-sans-serif, system-ui, sans-serif; font-size: 5.8pt; letter-spacing: .12em; text-transform: uppercase; color: #6b7785; }
  .seal .finger { margin-top: 2.4mm; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 6.2pt; line-height: 1.55; color: #0d2b45; word-break: break-all; }
  .seal .finger .l, .footnote .l { font-family: ui-sans-serif, system-ui, sans-serif; font-size: 5.8pt; letter-spacing: .13em; text-transform: uppercase; color: #6b7785; }
  .footnote { margin-top: 3mm; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 6pt; line-height: 1.5; color: #45525c; word-break: break-all; }
  .footnote .l { margin-right: 1mm; }
  .pagefoot { margin-top: 2.4mm; display: flex; justify-content: space-between; font-family: ui-sans-serif, system-ui, sans-serif; font-size: 5.8pt; letter-spacing: .12em; text-transform: uppercase; color: #8b949d; }

  .annexhead { display: flex; align-items: flex-end; justify-content: space-between; gap: 8mm; }
  /* The annex footer closes the flowing block. margin-top:auto only resolves in
     a flex container, and the annex is a block on purpose (Chrome ignores a
     forced page break on a flex container), so it gets a fixed gap instead. */
  .annexfoot { margin-top: 6mm; padding-top: 5mm; border-top: 0.2mm solid #e6e1d3; font-family: ui-sans-serif, system-ui, sans-serif; font-size: 6.6pt; line-height: 1.5; color: #7a8590; }

  /* Pagination rules for the annex. Without these a printer splits a finding
     across two sheets and repeats nothing, so page 3 of a long annex arrives
     with no column headings and half a row. */
  .annex thead { display: table-header-group; }
  .annex tr { break-inside: avoid; page-break-inside: avoid; }
  .annex h2 { break-after: avoid; page-break-after: avoid; }

  @media print {
    html, body { background: #fff; }
    .sheet { margin: 0; box-shadow: none; width: 210mm; }
    .sheet.page1 { height: 297mm; }
    .sheet.annex { break-before: page; page-break-before: always; min-height: 0; }
    .sheet.annex .annexhead { break-after: avoid; page-break-after: avoid; }
  }
  @media screen and (max-width: 780px) {
    .sheet { width: auto; min-height: 0; height: auto; margin: 0 0 6mm; padding: 10mm; box-shadow: none; }
    .grid2, .seal .cols { display: block; }
    .seal .sign { margin-top: 5mm; }
    .sheet.page1 { height: auto; }
  }
</style>
</head>
<body>
<div class="sheet page1">

  <div class="masthead">
    <div class="wordmark">Sift<small>Evidence protocol</small></div>
    <div class="meta">
      Format <b>` + html.EscapeString(version) + `</b><br>
      Signature <b>Ed25519</b><br>
      Verifies <b>offline</b>
    </div>
  </div>
  <div class="rule"></div>
  <div class="rule thin"></div>

  <div class="titleblock">
    <h1>Security Assessment Certificate</h1>
    <div class="sub">Recording the scope, the measured result and the evidence hash of one assessment</div>
    <div class="cid">` + html.EscapeString(displayOrDash(a.Issuer)) + ` &middot; ` + html.EscapeString(displayTime(a.SignedAt)) + `</div>
  </div>

  <div class="verdictrow">
    <div class="medallion"><div class="g">` + html.EscapeString(grade) + `</div><div class="l">Grade</div></div>
    <div class="verdictcopy">
      <div class="v ` + verdictTone + `">` + html.EscapeString(verdictHead) + `</div>
      ` + verdictDetailHTML(verdictDetail) + `
      <div class="t">` + html.EscapeString(displayOrDash(a.Target)) + `</div>
      <div class="stats">
        <div class="stat">Risk score<b>` + fmt.Sprintf("%d/100", a.RiskScore) + `</b></div>
        <div class="stat">Findings<b>` + fmt.Sprintf("%d", total) + `</b></div>
        <div class="stat">OWASP Top 10<b>` + fmt.Sprintf("%d/10", a.OWASPPass) + `</b></div>
        <div class="stat">Tested families<b>` + fmt.Sprintf("%d", len(a.Covered)) + `</b></div>
      </div>
    </div>
  </div>

  <div class="grid2">
    <div>
      <h2>Assessment</h2>
      <table class="kv">
        <tr><td class="k">Target</td><td>` + html.EscapeString(displayOrDash(a.Target)) + `</td></tr>
        <tr><td class="k">Scope</td><td>` + html.EscapeString(displayOrDash(a.Scope)) + `</td></tr>
        <tr><td class="k">Started</td><td>` + html.EscapeString(displayTime(a.Started)) + `</td></tr>
        <tr><td class="k">Ended</td><td>` + html.EscapeString(displayTime(a.Ended)) + `</td></tr>
        <tr><td class="k">Duration</td><td>` + html.EscapeString(displayOrDash(a.Duration)) + `</td></tr>
      </table>
    </div>
    <div>
      <h2>Issuance</h2>
      <table class="kv">
        <tr><td class="k">Issuer</td><td>` + html.EscapeString(displayOrDash(a.Issuer)) + `</td></tr>
        <tr><td class="k">Issued</td><td>` + html.EscapeString(displayTime(a.SignedAt)) + `</td></tr>
        <tr><td class="k">Tool</td><td>` + html.EscapeString(displayOrDash(strings.TrimSpace(a.Tool+" "+a.ToolVersion))) + `</td></tr>
        <tr><td class="k">Families</td><td>` + coveredText + `</td></tr>
        <tr><td class="k">Annex</td><td>` + annexNote(hasAnnex) + `</td></tr>
      </table>
    </div>
  </div>

  <h2>Severity counts</h2>
  <div class="counts">
    <div><div class="n` + zeroClass(a.Counts.Critical) + `">` + fmt.Sprintf("%d", a.Counts.Critical) + `</div><div class="c">Critical</div></div>
    <div><div class="n` + zeroClass(a.Counts.High) + `">` + fmt.Sprintf("%d", a.Counts.High) + `</div><div class="c">High</div></div>
    <div><div class="n` + zeroClass(a.Counts.Medium) + `">` + fmt.Sprintf("%d", a.Counts.Medium) + `</div><div class="c">Medium</div></div>
    <div><div class="n` + zeroClass(a.Counts.Low) + `">` + fmt.Sprintf("%d", a.Counts.Low) + `</div><div class="c">Low</div></div>
    <div><div class="n` + zeroClass(a.Counts.Info) + `">` + fmt.Sprintf("%d", a.Counts.Info) + `</div><div class="c">Info</div></div>
    <div><div class="n">` + fmt.Sprintf("%d", total) + `</div><div class="c">Total</div></div>
  </div>

  <div class="spacer"></div>

  <div class="seal">
    <div class="cols">
      <div class="notes">
        <div class="h">What this document proves</div>
        It proves that this assessment was sealed by the signing key below, and
        that the document you are reading is the one that was sealed. Any edit to
        a single byte of the assessment or of this page makes verification fail.
        <br><br>
        It does not prove that the target is secure, that the scan was
        exhaustive, or that the signer is an authority you trust. It is
        tamper-evident evidence, not a warranty.
        <div class="h" style="margin-top:2.6mm">How to verify</div>
        <code>sift certificate cert.json</code> &nbsp;or&nbsp; <code>sift certificate cert.pdf</code>
        <br>
        Pin the issuer once with <code>sift trust add --key &lt;issuer.pub&gt;</code>.
        Verification requires a trust anchor by default, so a certificate from any
        other key is refused. Use <code>--allow-unpinned</code> only for an explicit
        self-consistency-only check.
      </div>
      <div class="sign">
        <div class="stamp">
          <div class="big">SIFT</div>
          <div>tamper-evident</div>
          <div>evidence</div>
        </div>
        <div class="sigline">
          ` + html.EscapeString(displayOrDash(a.Issuer)) + `
          <div class="role">Issuer of record &middot; sealed ` + html.EscapeString(displayTime(signedAt)) + `</div>
        </div>
        <div class="finger">
          <div class="l">Signer key fingerprint (SHA-256)</div>
          ` + html.EscapeString(groupHex(m.PublicKey, 4)) + `
        </div>
      </div>
    </div>
    <div class="footnote">
      <span class="l">Ed25519 signature</span><br>
      ` + html.EscapeString(m.Signature) + `<br>
      <span class="l">Document SHA-256 (this page, seal excluded)</span><br>
      ` + html.EscapeString(groupHex(a.DocumentSHA, 8)) + `<br>
      <span class="l">Certificate id</span> ` + html.EscapeString(certID) + `
      &nbsp;&middot;&nbsp; <span class="l">Validity</span> ` + html.EscapeString(displayOrDash(m.ValidityPeriod)) + `
      &nbsp;&middot;&nbsp; <span class="l">Previous</span> ` + html.EscapeString(shortHex(m.PreviousCertificateHash, 16)) + `
    </div>
    <div class="pagefoot">
      <div>Sift &middot; ` + html.EscapeString(version) + ` &middot; page ` + pageCount + `</div>
      <div>` + html.EscapeString(displayOrDash(a.Target)) + `</div>
    </div>
  </div>

</div>
` + annex.String() + `
</body>
</html>`
}

// HTML renders the full certificate page from a sealed Certificate, including
// its signature seal and certificate id.
func HTML(c *Certificate) string {
	return RenderHTMLMeta(c.Assessment, DocumentMeta{
		Signature:               c.Signature,
		PublicKey:               c.PublicKey,
		SignedAt:                c.SignedAt,
		Version:                 c.Version,
		CertificateID:           c.CertificateID,
		PreviousCertificateHash: c.PreviousCertificateHash,
		ValidityPeriod:          c.ValidityPeriod,
	})
}

// severityClass maps a free-text severity to a badge class. Unknown values fall
// back to the info style rather than inventing a colour with no meaning.
func severityClass(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "high", "medium", "low", "info":
		return strings.ToLower(strings.TrimSpace(s))
	default:
		return "info"
	}
}

// statusClass maps a compliance status to a CSS class. "NOT TESTED" must never
// look like a pass, so it gets its own muted class.
func statusClass(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "PASS":
		return "pass"
	case "FAIL":
		return "fail"
	default:
		return "not-tested"
	}
}

// zeroClass greys out a zero count so the eye goes to the numbers that matter.
func zeroClass(n int) string {
	if n == 0 {
		return " zero"
	}
	return ""
}

// annexNote tells the reader whether page 2 exists, in the page they are
// holding, so a missing annex is noticed immediately.
func annexNote(has bool) string {
	if !has {
		return "none &mdash; no findings were recorded"
	}
	return "included (page 2 of 2)"
}

// groupHex splits a lowercase hex string into space-separated groups so a human
// can read it aloud and compare it by eye. Anything that is not hex is returned
// unchanged: the seal must render even when the certificate is malformed,
// because a reader needs to see what is wrong.
func groupHex(s string, width int) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "—"
	}
	if width <= 0 {
		width = 4
	}
	var b strings.Builder
	for i := 0; i < len(s); i += width {
		if i > 0 {
			b.WriteByte(' ')
		}
		end := i + width
		if end > len(s) {
			end = len(s)
		}
		b.WriteString(s[i:end])
	}
	return b.String()
}

// shortHex abbreviates a hex string for a one-line reference. It keeps both
// ends: a prefix alone would not distinguish two signatures that differ at the
// tail, which is exactly the case a reader is trying to rule out.
func shortHex(s string, n int) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "—"
	}
	if len(s) <= n {
		return s
	}
	half := n / 2
	if half < 4 {
		half = 4
	}
	return s[:half] + "…" + s[len(s)-half:]
}

// splitVerdict separates the report ladder's one-line verdict into a headline,
// a detail and a colour tone.
//
// internal/report returns "MEDIUM RISK -- Remediation recommended". Printing
// that whole string at 12 pt with .14em letter-spacing runs off the sheet, and
// turning it into a CSS class produced "v-medium risk -- remediation
// recommended" — a class name with spaces that matched no rule, so no verdict
// ever got a colour. The headline carries the tone; the detail is set smaller
// underneath it.
func splitVerdict(v string) (head, detail, tone string) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "—", "", ""
	}
	head = v
	for _, sep := range []string{" -- ", " — ", " --", "-- ", "--", "—"} {
		if i := strings.Index(v, sep); i > 0 {
			head = strings.TrimSpace(v[:i])
			detail = strings.TrimSpace(v[i+len(sep):])
			break
		}
	}
	return head, detail, verdictTone(head)
}

// verdictTone maps a verdict headline to the colour class that states it. The
// ladder is CRITICAL > HIGH > MEDIUM > LOW > CLEAN, and the older PASS / FAIL /
// REVIEW wording is accepted so a hand-written report still renders.
func verdictTone(head string) string {
	f := strings.ToUpper(strings.TrimSpace(head))
	switch {
	case strings.HasPrefix(f, "CRITICAL"), strings.HasPrefix(f, "HIGH"), strings.HasPrefix(f, "FAIL"):
		return "v-fail"
	case strings.HasPrefix(f, "MEDIUM"), strings.HasPrefix(f, "LOW"),
		strings.HasPrefix(f, "REVIEW"), strings.HasPrefix(f, "WARN"):
		return "v-warn"
	case strings.HasPrefix(f, "CLEAN"), strings.HasPrefix(f, "PASS"):
		return "v-pass"
	}
	return ""
}

// verdictDetailHTML renders the explanatory half of a verdict, or nothing when
// the verdict was a single word.
func verdictDetailHTML(detail string) string {
	if strings.TrimSpace(detail) == "" {
		return ""
	}
	return `<div class="vd">` + html.EscapeString(detail) + `</div>`
}

func displayTime(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || s == "0001-01-01T00:00:00Z" {
		return "—"
	}
	return s
}

func displayOrDash(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "—"
	}
	return s
}
