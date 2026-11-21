package audit360

import (
	"bytes"
	"fmt"
	"html"
	"sort"
	"strings"
	"time"
)

// RenderHTML returns a self-contained, professional, print-ready HTML document
// for a sealed Sift 360° audit report. It includes integrity/signature fields
// (certificate id, VPMP signature, evidence hash, signer public key when
// present in notes) so the document can be shared as a signed report artifact.
func RenderHTML(r *Audit360Report) string {
	if r == nil {
		return "<!doctype html><html><body><p>No audit360 report.</p></body></html>"
	}

	pubKey := extractSignerPublicKey(r.Notes)
	sig := strings.TrimSpace(r.VPMPSignature)
	certID := strings.TrimSpace(r.CertificateID)
	if certID == "" {
		certID = "unavailable"
	}
	sigState := "Unavailable"
	sigClass := "warn"
	if sig != "" {
		sigState = "Present (VPMP Ed25519 seal)"
		sigClass = "ok"
	}

	target := displayDash(strings.TrimSpace(r.TargetURL))
	ts := displayDash(strings.TrimSpace(r.Timestamp))
	risk := displayDash(strings.TrimSpace(r.RiskLevel))
	sev := strings.ToLower(strings.TrimSpace(r.RiskLevel))
	riskClass := "warn"
	if strings.Contains(sev, "low") {
		riskClass = "ok"
	} else if strings.Contains(sev, "critical") || strings.Contains(sev, "high") {
		riskClass = "bad"
	}

	scoresHTML := renderScores(r.Scores, r.ResilienceScore)
	findingsHTML := renderFindings(r.Findings)
	notesHTML := renderList(r.Notes)
	capHTML := renderCapacity(r)
	configHTML := renderConfig(r.TestConfiguration)

	rawHash := displayDash(strings.TrimSpace(r.RawEvidenceHash))
	rawFmt := displayDash(strings.TrimSpace(r.RawEvidenceFormat))
	scoringVer := displayDash(strings.TrimSpace(r.ScoringVersion))
	dur := fmt.Sprintf("%d ms", r.DurationMS)
	if r.DurationMS <= 0 {
		dur = "—"
	}

	return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sift 360° Signed Audit Report — ` + html.EscapeString(certID) + `</title>
<style>
:root{
  --bg:#f4f7fb; --card:#ffffff; --ink:#0f172a; --muted:#475569; --line:#dbe3ee;
  --brand:#0b3b66; --brand2:#0e7490; --ok:#166534; --okbg:#ecfdf3; --warn:#92400e; --warnbg:#fffbeb; --bad:#991b1b; --badbg:#fef2f2;
}
*{box-sizing:border-box}
body{margin:0;background:linear-gradient(180deg,#eef4fb 0%,var(--bg) 180px);color:var(--ink);font:14px/1.55 "Inter","Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:980px;margin:28px auto;padding:0 18px}
.doc{background:var(--card);border:1px solid var(--line);border-radius:16px;box-shadow:0 12px 40px rgba(15,23,42,.08);overflow:hidden}
.hero{padding:28px 30px;background:linear-gradient(135deg,var(--brand),#12395f 55%,var(--brand2));color:#fff}
.kicker{font-size:12px;letter-spacing:.14em;text-transform:uppercase;opacity:.9}
h1{margin:6px 0 4px;font-size:28px;line-height:1.2}
.sub{margin:0;opacity:.92}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px;padding:18px 30px;background:#f8fbff;border-bottom:1px solid var(--line)}
.pill{background:#fff;border:1px solid var(--line);border-radius:10px;padding:10px 12px}
.pill .l{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}
.pill .v{font-size:14px;font-weight:700;margin-top:2px;word-break:break-word}
.section{padding:22px 30px;border-top:1px solid var(--line)}
.section h2{margin:0 0 10px;font-size:13px;text-transform:uppercase;letter-spacing:.1em;color:#334155}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}
.card{border:1px solid var(--line);border-radius:12px;padding:14px;background:#fff}
.big{font-size:30px;font-weight:800;line-height:1}
.muted{color:var(--muted)}
.badge{display:inline-block;padding:4px 10px;border-radius:999px;font-size:12px;font-weight:700}
.badge.ok{color:var(--ok);background:var(--okbg);border:1px solid #bbf7d0}
.badge.warn{color:var(--warn);background:var(--warnbg);border:1px solid #fde68a}
.badge.bad{color:var(--bad);background:var(--badbg);border:1px solid #fecaca}
table{width:100%;border-collapse:collapse}
th,td{padding:9px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top;font-size:13px}
th{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:#475569;background:#f8fafc}
pre{margin:0;white-space:pre-wrap;word-break:break-all;background:#0b1220;color:#e5edf8;padding:12px;border-radius:10px;font:12px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
ul{margin:8px 0 0 18px;padding:0}
li{margin:4px 0}
.seal{background:#f8fbff}
.kv{display:grid;grid-template-columns:220px 1fr;gap:8px 12px}
.kv .k{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em}
.kv .v{font-weight:600;word-break:break-word}
.footer{padding:14px 30px;border-top:1px solid var(--line);color:var(--muted);font-size:12px;background:#fbfdff}
@media print{
  body{background:#fff}
  .wrap{max-width:none;margin:0;padding:0}
  .doc{border:none;border-radius:0;box-shadow:none}
  .section,.hero,.meta,.footer{break-inside:avoid}
}
</style>
</head>
<body>
<div class="wrap"><div class="doc">
  <div class="hero">
    <div class="kicker">Sift 360° Diagnostics · VPMP Sealed Report</div>
    <h1>Signed Audit & Resilience Assessment</h1>
    <p class="sub">Professional security and capacity diagnostics document with cryptographic seal metadata.</p>
  </div>

  <div class="meta">
    <div class="pill"><div class="l">Target</div><div class="v">` + html.EscapeString(target) + `</div></div>
    <div class="pill"><div class="l">Timestamp (UTC)</div><div class="v">` + html.EscapeString(ts) + `</div></div>
    <div class="pill"><div class="l">Risk level</div><div class="v"><span class="badge ` + riskClass + `">` + html.EscapeString(risk) + `</span></div></div>
    <div class="pill"><div class="l">Certificate ID</div><div class="v">` + html.EscapeString(certID) + `</div></div>
  </div>

  <div class="section">
    <h2>Executive summary</h2>
    <div class="grid">
      <div class="card"><div class="muted">Resilience / overall score</div><div class="big">` + fmt.Sprintf("%d", clampDocScore(r.ResilienceScore)) + `<span style="font-size:16px;color:#64748b"> / 100</span></div><div style="margin-top:8px"><span class="badge ` + riskClass + `">` + html.EscapeString(risk) + `</span></div></div>
      <div class="card"><div class="muted">Seal status</div><div style="margin-top:6px"><span class="badge ` + sigClass + `">` + html.EscapeString(sigState) + `</span></div><div class="muted" style="margin-top:8px">Format: <b>sift.audit360/v2</b><br>Scoring: <b>` + html.EscapeString(scoringVer) + `</b></div></div>
      <div class="card"><div class="muted">Duration</div><div class="big" style="font-size:24px">` + html.EscapeString(dur) + `</div><div class="muted" style="margin-top:8px">Target-scoped diagnostic run (measured/derived evidence as reported).</div></div>
    </div>
  </div>

  <div class="section">
    <h2>Score breakdown</h2>
    ` + scoresHTML + `
  </div>

  <div class="section">
    <h2>Capacity & load evidence</h2>
    ` + capHTML + `
  </div>

  <div class="section">
    <h2>Findings</h2>
    ` + findingsHTML + `
  </div>

  <div class="section">
    <h2>Test configuration & evidence integrity</h2>
    <div class="grid">
      <div class="card">` + configHTML + `</div>
      <div class="card">
        <div class="kv">
          <div class="k">Raw evidence hash</div><div class="v"><code>` + html.EscapeString(rawHash) + `</code></div>
          <div class="k">Raw evidence format</div><div class="v">` + html.EscapeString(rawFmt) + `</div>
          <div class="k">Scoring version</div><div class="v">` + html.EscapeString(scoringVer) + `</div>
        </div>
      </div>
    </div>
  </div>

  <div class="section seal">
    <h2>Cryptographic seal (signature)</h2>
    <div class="kv" style="margin-bottom:12px">
      <div class="k">Certificate ID</div><div class="v"><code>` + html.EscapeString(certID) + `</code></div>
      <div class="k">Signature status</div><div class="v"><span class="badge ` + sigClass + `">` + html.EscapeString(sigState) + `</span></div>
      <div class="k">Signer public key (hex)</div><div class="v"><code>` + html.EscapeString(displayDash(pubKey)) + `</code></div>
    </div>
    <div class="muted" style="margin-bottom:6px">VPMP signature (hex, Ed25519 over canonical sealed payload digest):</div>
    <pre>` + html.EscapeString(displayDash(sig)) + `</pre>
    <p class="muted" style="margin:10px 0 0">This document presents the sealed audit360 report fields. Verification is performed against the canonical sealed payload (certificate ID bound to payload digest) using the signer public key and signature. If signature/public key is unavailable, the report is not cryptographically verifiable as signed.</p>
  </div>

  <div class="section">
    <h2>Notes & transparency</h2>
    ` + notesHTML + `
  </div>

  <div class="footer">Sift 360° Signed Audit Report · generated ` + html.EscapeString(time.Now().UTC().Format(time.RFC3339)) + ` · certificate ` + html.EscapeString(certID) + `</div>
</div></div>
</body>
</html>`
}

// RenderPDF returns a simple, professional text-based PDF document for the
// sealed audit360 report (pure Go, no external dependencies). For the richest
// layout, use the HTML document and "Print to PDF".
func RenderPDF(r *Audit360Report) ([]byte, error) {
	p := newSimplePDF()
	if r == nil {
		p.line("Sift 360° Signed Audit Report")
		p.line("No report data.")
		return p.bytes()
	}
	pubKey := extractSignerPublicKey(r.Notes)
	certID := strings.TrimSpace(r.CertificateID)
	if certID == "" {
		certID = "unavailable"
	}
	p.line("SIFT 360° — SIGNED AUDIT & RESILIENCE REPORT")
	p.line("VPMP Sealed Document (sift.audit360/v2)")
	p.sep()
	p.kv("Target", displayDash(r.TargetURL))
	p.kv("Timestamp (UTC)", displayDash(r.Timestamp))
	p.kv("Certificate ID", certID)
	p.kv("Risk level", displayDash(r.RiskLevel))
	p.kv("Resilience / overall", fmt.Sprintf("%d / 100", clampDocScore(r.ResilienceScore)))
	p.kv("Duration", fmt.Sprintf("%d ms", r.DurationMS))
	p.kv("Scoring version", displayDash(r.ScoringVersion))
	p.kv("Raw evidence hash", displayDash(r.RawEvidenceHash))
	p.sep()
	p.line("SCORES")
	if r.Scores != nil {
		p.kv("Overall", fmt.Sprintf("%d", r.Scores.Overall))
		p.kv("Security", fmt.Sprintf("%d", r.Scores.Security))
		p.kv("Resilience", fmt.Sprintf("%d", r.Scores.Resilience))
		p.kv("Capacity", fmt.Sprintf("%d", r.Scores.Capacity))
		p.kv("Evidence quality", fmt.Sprintf("%d", r.Scores.EvidenceQuality))
	} else {
		p.line("  (breakdown unavailable)")
	}
	p.sep()
	p.line("CAPACITY & LOAD")
	p.kv("Load test available", fmt.Sprintf("%t", r.LoadTestAvailable))
	p.kv("Load test skipped", fmt.Sprintf("%t", r.LoadTestSkipped))
	p.kv("Capacity blocked", fmt.Sprintf("%t", r.CapacityBlocked))
	p.kv("Breaking point reached", fmt.Sprintf("%t", r.BreakingPointReached))
	if r.BreakingPointUsers > 0 {
		p.kv("Breaking point users", fmt.Sprintf("%d", r.BreakingPointUsers))
	}
	if r.MaxSafeRPS > 0 {
		p.kv("Max safe RPS", fmt.Sprintf("%.2f", r.MaxSafeRPS))
	}
	if r.MaxObservedRPS > 0 {
		p.kv("Max observed RPS", fmt.Sprintf("%.2f", r.MaxObservedRPS))
	}
	p.sep()
	p.line("FINDINGS")
	if len(r.Findings) == 0 {
		p.line("  No significant findings reported.")
	} else {
		for i, f := range r.Findings {
			p.line(fmt.Sprintf("  %d. [%s] %s", i+1, strings.ToUpper(displayDash(f.Severity)), displayDash(f.Title)))
			if strings.TrimSpace(f.ImpactSummary) != "" {
				p.line("     Impact: " + f.ImpactSummary)
			}
			if strings.TrimSpace(f.Remediation) != "" {
				p.line("     Fix: " + f.Remediation)
			}
			if strings.TrimSpace(f.Evidence) != "" {
				p.line("     Evidence: " + f.Evidence)
			}
		}
	}
	p.sep()
	p.line("CRYPTOGRAPHIC SEAL")
	p.kv("Signature status", map[bool]string{true: "Present (VPMP Ed25519 seal)", false: "Unavailable"}[strings.TrimSpace(r.VPMPSignature) != ""])
	p.kv("Signer public key", displayDash(pubKey))
	p.line("Signature (hex):")
	for _, chunk := range chunkString(displayDash(r.VPMPSignature), 88) {
		p.line("  " + chunk)
	}
	p.sep()
	p.line("NOTES")
	if len(r.Notes) == 0 {
		p.line("  (none)")
	} else {
		for _, n := range r.Notes {
			p.line("- " + n)
		}
	}
	p.sep()
	p.line("Generated: " + time.Now().UTC().Format(time.RFC3339))
	p.line("Verification: canonical sift.audit360/v2 sealed payload; cert ID bound to payload digest.")
	return p.bytes()
}

func extractSignerPublicKey(notes []string) string {
	const pfx = "VPMP signer public key (hex): "
	for _, n := range notes {
		n = strings.TrimSpace(n)
		if strings.HasPrefix(n, pfx) {
			return strings.TrimSpace(strings.TrimPrefix(n, pfx))
		}
	}
	return ""
}

func displayDash(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "—"
	}
	return s
}

func clampDocScore(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

func renderScores(s *ScoreBreakdown, overall int) string {
	if s == nil {
		return `<div class="card"><div class="muted">Score breakdown unavailable in this report.</div><div style="margin-top:8px">Overall: <b>` + fmt.Sprintf("%d", clampDocScore(overall)) + ` / 100</b></div></div>`
	}
	row := func(name string, v int) string {
		v = clampDocScore(v)
		return fmt.Sprintf(`<tr><td>%s</td><td><b>%d</b> / 100</td><td><div style="background:#e2e8f0;border-radius:999px;height:8px;overflow:hidden"><div style="width:%d%%;height:8px;background:linear-gradient(90deg,#0e7490,#2563eb)"></div></div></td></tr>`, html.EscapeString(name), v, v)
	}
	// Coverage is always shown, including 0: it is the evidence basis for every
	// other score, and a missing row reads as "not assessed".
	coverageRow := row("Assessment coverage (evidence basis)", clampDocScore(s.Coverage))
	return `<table><thead><tr><th>Category</th><th>Score</th><th>Indicator</th></tr></thead><tbody>` +
		row("Overall", s.Overall) + row("Security", s.Security) + row("Resilience", s.Resilience) + row("Capacity", s.Capacity) + row("Evidence quality", s.EvidenceQuality) + coverageRow +
		`</tbody></table>`
}

func renderFindings(findings []Finding) string {
	if len(findings) == 0 {
		return `<div class="card muted">No significant findings reported by the measured checks in this run.</div>`
	}
	var b strings.Builder
	b.WriteString(`<table><thead><tr><th>Severity</th><th>Finding</th><th>Business impact</th><th>Remediation</th><th>Evidence</th></tr></thead><tbody>`)
	for _, f := range findings {
		sev := strings.ToLower(strings.TrimSpace(f.Severity))
		cls := "warn"
		switch sev {
		case "critical", "high":
			cls = "bad"
		case "low", "info":
			cls = "ok"
		case "medium":
			cls = "warn"
		}
		b.WriteString(`<tr><td><span class="badge ` + cls + `">` + html.EscapeString(strings.ToUpper(displayDash(f.Severity))) + `</span></td>`)
		b.WriteString(`<td><b>` + html.EscapeString(displayDash(f.Title)) + `</b></td>`)
		b.WriteString(`<td>` + html.EscapeString(displayDash(f.ImpactSummary)) + `</td>`)
		b.WriteString(`<td>` + html.EscapeString(displayDash(f.Remediation)) + `</td>`)
		b.WriteString(`<td>` + html.EscapeString(displayDash(f.Evidence)) + `</td></tr>`)
	}
	b.WriteString(`</tbody></table>`)
	return b.String()
}

func renderList(items []string) string {
	if len(items) == 0 {
		return `<div class="card muted">No additional notes.</div>`
	}
	var b strings.Builder
	b.WriteString(`<ul>`)
	for _, it := range items {
		it = strings.TrimSpace(it)
		if it == "" {
			continue
		}
		b.WriteString(`<li>` + html.EscapeString(it) + `</li>`)
	}
	b.WriteString(`</ul>`)
	return b.String()
}

func renderCapacity(r *Audit360Report) string {
	var status, detail string
	switch {
	case r.LoadTestSkipped:
		status = `<span class="badge warn">Load test skipped</span>`
		detail = "Active load/breaking-point testing was not run (e.g. Passive mode)."
	case r.CapacityBlocked:
		status = `<span class="badge warn">Capacity not measurable</span>`
		detail = fmt.Sprintf("Target refused audit traffic (HTTP %d, %.1f%% blocked). No breaking point claimed.", r.BlockedStatus, r.BlockedSharePct)
	case r.LoadTestAvailable && r.BreakingPointReached:
		status = `<span class="badge bad">Breaking point reached</span>`
		if r.BreakingPointUsers > 0 {
			detail = fmt.Sprintf("System reached failure threshold at ~%d concurrent users.", r.BreakingPointUsers)
		} else {
			detail = "Failure threshold breached during load test."
		}
	case r.LoadTestAvailable:
		status = `<span class="badge ok">No breaking point in window</span>`
		if r.MaxObservedRPS > 0 {
			detail = fmt.Sprintf("Peak observed throughput: %.2f req/s within audit window.", r.MaxObservedRPS)
		} else {
			detail = "Load test ran without breaching the failure threshold in the allotted time."
		}
	default:
		status = `<span class="badge warn">Unavailable</span>`
		detail = "Load evidence unavailable for this run (not fabricated)."
	}
	var extra []string
	if r.MaxSafeRPS > 0 {
		extra = append(extra, fmt.Sprintf(`<div class="k">Max safe RPS</div><div class="v">%.2f req/s</div>`, r.MaxSafeRPS))
	}
	if r.MaxObservedRPS > 0 {
		extra = append(extra, fmt.Sprintf(`<div class="k">Max observed RPS</div><div class="v">%.2f req/s</div>`, r.MaxObservedRPS))
	}
	if r.MaxObservedUsers > 0 {
		extra = append(extra, fmt.Sprintf(`<div class="k">Max observed users</div><div class="v">%d</div>`, r.MaxObservedUsers))
	}
	extraHTML := ""
	if len(extra) > 0 {
		extraHTML = `<div class="kv" style="margin-top:12px">` + strings.Join(extra, "") + `</div>`
	}
	return `<div class="card"><div style="margin-bottom:8px">` + status + `</div><div>` + html.EscapeString(detail) + `</div>` + extraHTML + `</div>`
}

func renderConfig(c *TestConfiguration) string {
	if c == nil {
		return `<div class="muted">Test configuration not recorded.</div>`
	}
	kv := func(k, v string) string {
		return `<div class="k">` + html.EscapeString(k) + `</div><div class="v">` + html.EscapeString(v) + `</div>`
	}
	rows := []string{
		kv("Mode", displayDash(c.Mode)),
		kv("Requested target", displayDash(c.RequestedTarget)),
		kv("Max duration", fmt.Sprintf("%ds", c.MaxDurationSec)),
		kv("Security scan enabled", fmt.Sprintf("%t", c.SecurityScanEnabled)),
		kv("Active load enabled", fmt.Sprintf("%t", c.ActiveLoadEnabled)),
		kv("Authorization provided", fmt.Sprintf("%t", c.AuthorizationProvided)),
	}
	if c.LoadMaxUsers > 0 {
		rows = append(rows, kv("Load max users", fmt.Sprintf("%d", c.LoadMaxUsers)))
	}
	if c.LoadDurationSec > 0 {
		rows = append(rows, kv("Load duration", fmt.Sprintf("%ds", c.LoadDurationSec)))
	}
	if strings.TrimSpace(c.LoadProfile) != "" {
		rows = append(rows, kv("Load profile", c.LoadProfile))
	}
	return `<div class="kv">` + strings.Join(rows, "") + `</div>`
}

func chunkString(s string, n int) []string {
	if n <= 0 || len(s) <= n {
		return []string{s}
	}
	var out []string
	for len(s) > n {
		out = append(out, s[:n])
		s = s[n:]
	}
	if s != "" {
		out = append(out, s)
	}
	return out
}

// --- minimal PDF writer (text document, pure Go) ---

type simplePDF struct {
	lines []string
}

func newSimplePDF() *simplePDF { return &simplePDF{} }
func (p *simplePDF) line(s string) {
	// normalize tabs and keep printable-ish text
	s = strings.ReplaceAll(s, "\t", "  ")
	p.lines = append(p.lines, s)
}
func (p *simplePDF) kv(k, v string) { p.line(fmt.Sprintf("%-22s %s", k+":", v)) }
func (p *simplePDF) sep()           { p.line(strings.Repeat("-", 78)) }

func (p *simplePDF) bytes() ([]byte, error) {
	const (
		pageW, pageH = 612, 792
		left, topY   = 40, 750
		lineH        = 12
		maxLines     = 58
		fontSize     = 9
	)
	// paginate
	var pages [][]string
	for i := 0; i < len(p.lines); i += maxLines {
		end := i + maxLines
		if end > len(p.lines) {
			end = len(p.lines)
		}
		page := make([]string, end-i)
		copy(page, p.lines[i:end])
		pages = append(pages, page)
	}
	if len(pages) == 0 {
		pages = [][]string{{""}}
	}

	var b bytes.Buffer
	b.WriteString("%PDF-1.4\n%\xFF\xFF\xFF\xFF\n")
	type obj struct {
		id  int
		off int
	}
	var objs []obj
	writeObj := func(id int, body string) {
		objs = append(objs, obj{id: id, off: b.Len()})
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", id, body)
	}

	// 1: catalog, 2: pages
	writeObj(1, "<< /Type /Catalog /Pages 2 0 R >>")
	// reserve pages kids list
	kidIDs := make([]int, len(pages))
	contentIDs := make([]int, len(pages))
	fontIDBase := 3 + len(pages)*2
	for i := range pages {
		kidIDs[i] = 3 + i*2
		contentIDs[i] = 4 + i*2
	}
	var kids []string
	for _, id := range kidIDs {
		kids = append(kids, fmt.Sprintf("%d 0 R", id))
	}
	writeObj(2, fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), len(pages)))

	fontID := fontIDBase
	// ensure deterministic ordering of object ids by writing in sequence
	// page and content objects interleaved per page
	for i, lines := range pages {
		pid := kidIDs[i]
		cid := contentIDs[i]
		writeObj(pid, fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %d %d] /Resources << /Font << /F1 %d 0 R >> >> /Contents %d 0 R >>", pageW, pageH, fontID, cid))
		stream := buildTextStream(lines, left, topY, lineH, fontSize)
		writeObj(cid, fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(stream), stream))
	}
	writeObj(fontID, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")

	// sort objects by id
	sort.Slice(objs, func(i, j int) bool { return objs[i].id < objs[j].id })
	maxID := fontID
	xrefOff := b.Len()
	fmt.Fprintf(&b, "xref\n0 %d\n", maxID+1)
	// build offset map
	offMap := map[int]int{}
	for _, o := range objs {
		offMap[o.id] = o.off
	}
	b.WriteString("0000000000 65535 f \n")
	for id := 1; id <= maxID; id++ {
		if off, ok := offMap[id]; ok {
			fmt.Fprintf(&b, "%010d 00000 n \n", off)
		} else {
			b.WriteString("0000000000 65535 f \n")
		}
	}
	fmt.Fprintf(&b, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", maxID+1, xrefOff)
	return b.Bytes(), nil
}

func buildTextStream(lines []string, left, topY, lineH, fontSize int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "BT\n/F1 %d Tf\n", fontSize)
	y := topY
	for _, ln := range lines {
		ln = sanitizePDFText(ln)
		fmt.Fprintf(&b, "1 0 0 1 %d %d Tm (%s) Tj\n", left, y, pdfEscapeStr(ln))
		y -= lineH
	}
	b.WriteString("ET")
	return b.String()
}

func pdfEscapeStr(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\\', '(', ')':
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			if r >= 32 && r <= 126 {
				b.WriteRune(r)
			} else if r == '\n' || r == '\r' || r == '\t' {
				b.WriteByte(' ')
			} else {
				b.WriteRune('?')
			}
		}
	}
	return b.String()
}

func sanitizePDFText(s string) string {
	// keep it simple for Helvetica/WinAnsi-like output
	return strings.Map(func(r rune) rune {
		if r == '\t' {
			return ' '
		}
		if r < 32 && r != '\n' {
			return -1
		}
		return r
	}, s)
}
