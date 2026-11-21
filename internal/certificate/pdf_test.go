package certificate

// pdf_test.go — the tests that would have caught a blank certificate.
//
// The old PDF writer produced a file that every viewer rendered as an empty
// page, because the page dictionary named the wrong objects for its font and
// its content. The old test only asked whether Bytes() returned something, and
// something is exactly what a blank page is.
//
// So these tests resolve the cross-references instead of trusting the bytes:
// the font must be a font, the content must be a stream, the text must be in
// it, and the xref table must point at the objects it claims to.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/asadbekabdulboqiyev/sift/internal/attest"
)

var (
	reObj      = regexp.MustCompile(`(?m)^(\d+) 0 obj\n`)
	reFontRef  = regexp.MustCompile(`/Font << /F1 (\d+) 0 R >>`)
	reContRef  = regexp.MustCompile(`/Contents (\d+) 0 R`)
	reKidsRef  = regexp.MustCompile(`/Kids \[([^\]]*)\]`)
	reXrefEnt  = regexp.MustCompile(`(?m)^(\d{10}) 00000 n $`)
	reStreamOf = regexp.MustCompile(`(?s)stream\n(.*?)\nendstream`)
)

// pdfParse splits a document into object bodies keyed by object number.
func pdfParse(t *testing.T, doc []byte) map[int]string {
	t.Helper()
	s := string(doc)
	locs := reObj.FindAllStringSubmatchIndex(s, -1)
	if len(locs) == 0 {
		t.Fatalf("no objects in the PDF:\n%s", s)
	}
	objs := make(map[int]string, len(locs))
	for _, loc := range locs {
		num, err := strconv.Atoi(s[loc[2]:loc[3]])
		if err != nil {
			t.Fatalf("object number %q: %v", s[loc[2]:loc[3]], err)
		}
		end := strings.Index(s[loc[1]:], "endobj")
		if end < 0 {
			t.Fatalf("object %d has no endobj", num)
		}
		objs[num] = s[loc[1] : loc[1]+end]
	}
	return objs
}

func mustRef(t *testing.T, re *regexp.Regexp, body, what string) int {
	t.Helper()
	m := re.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("%s: reference not found in %q", what, body)
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("%s: bad object number %q", what, m[1])
	}
	return n
}

// TestPDFReferencesResolve is the regression test for the blank page: the page
// dictionary must point at a font for /F1 and at a stream for /Contents, and
// neither may be the page itself.
func TestPDFReferencesResolve(t *testing.T) {
	doc, err := NewPDF().Text("Sift certificate").Text("Target: https://example.com").Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	objs := pdfParse(t, doc)

	// "/Type /Page" is a prefix of "/Type /Pages", so match the dictionary form
	// that only a real page carries.
	var page int
	for num, body := range objs {
		if strings.Contains(body, "/Type /Page /Parent") {
			page = num
		}
	}
	if page == 0 {
		t.Fatal("no /Type /Page object found")
	}

	body := objs[page]
	fontNum := mustRef(t, reFontRef, body, "page font")
	contNum := mustRef(t, reContRef, body, "page contents")

	if fontNum == page {
		t.Fatalf("page %d uses itself as its font: this is the bug that made every PDF blank", page)
	}
	if contNum == page {
		t.Fatalf("page %d uses itself as its content stream", page)
	}
	font, ok := objs[fontNum]
	if !ok {
		t.Fatalf("font object %d does not exist", fontNum)
	}
	if !strings.Contains(font, "/Type /Font") {
		t.Fatalf("object %d is referenced as the font but is %q", fontNum, font)
	}
	if !strings.Contains(font, "/Encoding /WinAnsiEncoding") {
		t.Fatalf("font object has no WinAnsi encoding: high bytes would render as garbage")
	}
	cont, ok := objs[contNum]
	if !ok {
		t.Fatalf("content object %d does not exist", contNum)
	}
	m := reStreamOf.FindStringSubmatch(cont)
	if m == nil {
		t.Fatalf("object %d is referenced as the content stream but holds no stream: %q", contNum, cont)
	}
	if !strings.Contains(m[1], "(Sift certificate) Tj") {
		t.Fatalf("content stream does not draw the text it was given:\n%s", m[1])
	}
	if !strings.Contains(m[1], "BT") || !strings.Contains(m[1], "ET") {
		t.Fatalf("content stream is not a balanced text object:\n%s", m[1])
	}

	// Every page in the tree must resolve the same way.
	kids := reKidsRef.FindStringSubmatch(objs[2])
	if kids == nil {
		t.Fatalf("page tree has no /Kids: %q", objs[2])
	}
	kidRefs := regexp.MustCompile(`(\d+) 0 R`).FindAllStringSubmatch(kids[1], -1)
	if len(kidRefs) == 0 {
		t.Fatalf("page tree /Kids names no pages: %q", kids[1])
	}
	for _, ref := range kidRefs {
		num, err := strconv.Atoi(ref[1])
		if err != nil {
			t.Fatalf("bad kid reference %q", ref[0])
		}
		kid, ok := objs[num]
		if !ok {
			t.Fatalf("kid %d does not exist", num)
		}
		f := mustRef(t, reFontRef, kid, "kid font")
		if !strings.Contains(objs[f], "/Type /Font") {
			t.Fatalf("kid %d font %d is not a font", num, f)
		}
	}
}

// TestPDFXrefOffsets checks the cross-reference table really points at the
// objects: an offset that is off by one byte makes a strict reader reject the
// whole file.
func TestPDFXrefOffsets(t *testing.T) {
	doc, err := NewPDF().Text("one").Page().Text("two").Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	start := strings.Index(string(doc), "xref\n")
	if start < 0 {
		t.Fatal("no xref table")
	}
	table := string(doc)[start:]
	ents := reXrefEnt.FindAllStringSubmatch(table, -1)
	if len(ents) == 0 {
		t.Fatal("xref table has no in-use entries")
	}
	// Entry i (1-based in the table after the free entry) belongs to object i.
	for i, e := range ents {
		objNum := i + 1
		off, err := strconv.Atoi(e[1])
		if err != nil {
			t.Fatalf("offset %q: %v", e[1], err)
		}
		if off < 0 || off >= len(doc) {
			t.Fatalf("object %d offset %d is outside the file", objNum, off)
		}
		want := strconv.Itoa(objNum) + " 0 obj"
		if !strings.HasPrefix(string(doc[off:]), want) {
			t.Fatalf("object %d offset points at %q, want %q", objNum, string(doc[off:off+20]), want)
		}
	}
}

// TestPDFWrapsLongLines proves a 128-character signature is broken across lines
// instead of running off the right edge of the page, where it is unreadable.
func TestPDFWrapsLongLines(t *testing.T) {
	sig := strings.Repeat("9f074a4e", 16) // 128 chars, like a real Ed25519 signature
	doc, err := NewPDF().Text("Signature:").Text(sig).Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	objs := pdfParse(t, doc)
	var stream string
	for _, body := range objs {
		if m := reStreamOf.FindStringSubmatch(body); m != nil {
			stream = m[1]
			break
		}
	}
	if stream == "" {
		t.Fatal("no content stream")
	}
	if strings.Contains(stream, "("+sig+") Tj") {
		t.Fatal("the 128-character signature was emitted as one unwrapped line")
	}
	// The signature must survive the wrap: concatenating the drawn lines has to
	// give the original string back, or the printed copy would be unverifiable.
	var drawn strings.Builder
	for _, line := range regexp.MustCompile(`\(([^)]*)\) Tj`).FindAllStringSubmatch(stream, -1) {
		drawn.WriteString(line[1])
	}
	if !strings.Contains(drawn.String(), sig) {
		t.Fatalf("wrapping lost characters:\n got %q\nwant to contain %q", drawn.String(), sig)
	}
	// And no drawn line may be wider than the text area.
	for _, line := range regexp.MustCompile(`\(([^)]*)\) Tj`).FindAllStringSubmatch(stream, -1) {
		w := 0.0
		for _, r := range line[1] {
			w += runeWidth(r) * pdfFontSize / 1000
		}
		if w > pdfTextWidth+0.5 {
			t.Fatalf("line %q is %.1f pt wide, page allows %.1f", line[1], w, pdfTextWidth)
		}
	}
}

// TestPDFPaginatesOverflow proves a long document spills onto new pages instead
// of drawing text below the page, where nobody can see it.
func TestPDFPaginatesOverflow(t *testing.T) {
	p := NewPDF()
	for i := 0; i < 120; i++ {
		p.Text("line " + strconv.Itoa(i))
	}
	doc, err := p.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	objs := pdfParse(t, doc)
	count := 0
	for _, body := range objs {
		if strings.Contains(body, "/Type /Page /Parent") {
			count++
		}
	}
	if count < 3 {
		t.Fatalf("120 lines produced %d pages, want at least 3", count)
	}
	// No content stream may draw below the bottom margin.
	for _, body := range objs {
		m := reStreamOf.FindStringSubmatch(body)
		if m == nil {
			continue
		}
		lines := strings.Count(m[1], " Tj\n")
		if lines > pdfMaxLines {
			t.Fatalf("a page holds %d lines; the page fits %d", lines, pdfMaxLines)
		}
	}
}

// TestPDFEncodingKeepsTextReadable checks the WinAnsi mapping: an em dash must
// become the WinAnsi byte, and a rune WinAnsi cannot draw must become "?"
// rather than a malformed octal escape that corrupts the rest of the string.
func TestPDFEncodingKeepsTextReadable(t *testing.T) {
	if got, want := pdfEncode("a—b"), "a\\227b"; got != want {
		t.Fatalf("em dash encoded as %q, want %q", got, want)
	}
	if got, want := pdfEncode("School — 12"), "School \\227 12"; got != want {
		t.Fatalf("mixed text encoded as %q, want %q", got, want)
	}
	if got, want := pdfEncode("қ"), "?"; got != want {
		t.Fatalf("unsupported rune encoded as %q, want %q", got, want)
	}
	if got, want := pdfEncode("(a) \\ b"), "\\(a\\) \\\\ b"; got != want {
		t.Fatalf("delimiters encoded as %q, want %q", got, want)
	}
	// No escape may be longer than the three octal digits a PDF literal allows.
	for _, esc := range regexp.MustCompile(`\\[0-9]+`).FindAllString(pdfEncode("ž—…«»°"), -1) {
		if len(esc) > 4 {
			t.Fatalf("escape %q has more than three octal digits", esc)
		}
	}
}

// TestPDFEmptyDocument keeps the degenerate case valid: a caller that writes no
// text still gets a readable, one-page document rather than a broken file.
func TestPDFEmptyDocument(t *testing.T) {
	doc, err := NewPDF().Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	if !strings.HasPrefix(string(doc), "%PDF-1.4") {
		t.Fatal("missing PDF header")
	}
	if !strings.HasSuffix(string(doc), "%%EOF\n") {
		t.Fatal("missing EOF marker")
	}
	objs := pdfParse(t, doc)
	if !strings.Contains(objs[2], "/Count 1") {
		t.Fatalf("empty document should still have one page: %q", objs[2])
	}
}

// TestPDFPageSizeIsA4 pins the paper. The HTML certificate is A4, and the
// printed copy used to be US Letter: on a European printer that shrinks the
// page by about 5% and leaves a wider white strip at the right edge.
func TestPDFPageSizeIsA4(t *testing.T) {
	doc, err := NewPDF().Text("one line").Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	if !strings.Contains(string(doc), "/MediaBox [0 0 595.28 841.89]") {
		t.Errorf("page tree does not declare an A4 MediaBox")
	}
}

// TestPDFSealRoundTrip proves a sealed PDF verifies on its own: the embedded
// certificate passes signature and document-hash checks, and the text drawn on
// the page hashes to the value in the seal.
func verifiableCert(t *testing.T) *Certificate {
	t.Helper()
	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	a := NewFromPentest("https://example.com", "full scope", "QA Lead", "0.16.6", 12, "B", "PASS",
		Counts{Medium: 1}, 9, "2026-11-07T08:00:00Z", "2026-11-07T08:01:00Z", "1m0s")
	a.Findings = []Finding{{ID: "F-001", Severity: "medium", Title: "Missing CSP", Evidence: "no CSP on /"}}
	c, err := Issue(kp, a, "", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return c
}

func TestPDFSealRoundTrip(t *testing.T) {
	c := verifiableCert(t)
	certJSON, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal certificate: %v", err)
	}

	// Print the certificate the way the CLI prints it. An arbitrary page sealed
	// with a real certificate is no longer a valid PDF — that is the point of
	// the strict check, and TestPDFSealRejectsRebuiltSeal pins it.
	p := NewPDF()
	for _, line := range PDFLines(c.Assessment, c) {
		p.Text(line)
	}
	doc, err := p.Seal(certJSON).Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}

	res, err := VerifyPDF(doc, nil, false)
	if err != nil {
		t.Fatalf("VerifyPDF: %v", err)
	}
	if !res.RenderedMatch {
		t.Fatalf("rendered digest %s does not match seal %s", res.RenderedSHA256, res.SealRenderedSHA256)
	}
	if !res.RenderingMatchesCertificate {
		t.Fatalf("page %s is not what the certificate renders to (%s)", res.RenderedSHA256, res.ExpectedRenderedSHA256)
	}
	if !res.ObjectsMatchCertificate {
		t.Fatal("a certificate this package just printed does not match its own objects")
	}
	if res.Certificate == nil || res.Certificate.Signature != c.Signature {
		t.Fatal("verified PDF did not return the embedded certificate")
	}
	direct, err := PDFRenderedSHA256(doc)
	if err != nil {
		t.Fatalf("PDFRenderedSHA256: %v", err)
	}
	if direct != res.SealRenderedSHA256 {
		t.Fatalf("digest read twice differs: %s vs %s", direct, res.SealRenderedSHA256)
	}
}

// TestRenderPDFIsVerifiable pins the shared printer: whatever RenderPDF emits
// must pass the verifier unchanged. The dashboard download used to build its own
// page, so it looked like a certificate and failed verification with "no
// envelope"; routing every caller through one function is what closes that gap.
func TestRenderPDFIsVerifiable(t *testing.T) {
	c := verifiableCert(t)
	doc, err := RenderPDF(c)
	if err != nil {
		t.Fatalf("RenderPDF: %v", err)
	}
	res, err := VerifyPDF(doc, nil, false)
	if err != nil {
		t.Fatalf("VerifyPDF: %v", err)
	}
	if !res.ObjectsMatchCertificate || !res.RenderingMatchesCertificate {
		t.Fatalf("rendered pdf not bound to certificate: objects=%v rendering=%v",
			res.ObjectsMatchCertificate, res.RenderingMatchesCertificate)
	}
	if res.Certificate == nil || res.Certificate.CertificateID != c.CertificateID {
		t.Fatal("verified pdf did not return the certificate it was rendered from")
	}
}

// TestRenderPDFNilCertificate is the guard for the "no certificate, nothing to
// seal" path: it must return an error rather than a page that pretends to be
// sealed.
func TestRenderPDFNilCertificate(t *testing.T) {
	if _, err := RenderPDF(nil); err == nil {
		t.Fatal("RenderPDF(nil) must fail")
	}
}

// TestPDFSealRejectsRebuiltSeal is the attack the digest alone could not stop.
//
// Take a genuinely signed certificate for grade B. Draw a page that says grade
// A. Seal it with that page's own digest — the writer will happily compute it —
// and leave the embedded certificate untouched. Signature checks pass, the page
// matches the seal, and every check the v0.17.0 verifier made says VALID. The
// page is still a lie, because no issuer signed a page that says A.
//
// The verifier now re-renders the expected pages from the embedded certificate
// and requires the page to equal that, so this file is refused.
func TestPDFSealRejectsRebuiltSeal(t *testing.T) {
	c := verifiableCert(t)
	if c.Assessment.Grade != "B" {
		t.Fatalf("test setup: grade is %q, want B", c.Assessment.Grade)
	}
	certJSON, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal certificate: %v", err)
	}

	// The forged page: an upgraded grade, sealed with its own digest.
	forged, err := NewPDF().
		Text("Sift - Security Assessment Certificate (ss-cert/v1)").
		Text("").
		Text("Target: https://example.com").
		Text("Grade: A   Verdict: PASS   Risk: 0/100").
		Seal(certJSON).
		Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}

	res, err := VerifyPDF(forged, nil, false)
	if err == nil {
		t.Fatal("a PDF whose page was rebuilt around a real certificate verified")
	}
	if res == nil {
		t.Fatal("no result returned for a rejected PDF")
	}
	if !res.RenderedMatch {
		t.Fatal("test setup: the forged page should match its own rewritten seal")
	}
	if res.RenderingMatchesCertificate {
		t.Fatal("the forged page was reported as the certificate's own rendering")
	}
	if !strings.Contains(err.Error(), "rebuilt after signing") {
		t.Errorf("unhelpful error: %v", err)
	}
}

// TestPDFLinesGolden pins the printed text. Every sealed PDF hashes
// these exact lines, so a wording change silently invalidates every copy already
// handed to a reader. The digest of this fixture is also the digest a v0.17.0
// PDF must still re-render to.
func TestPDFLinesGolden(t *testing.T) {
	// A literal, not NewFromPentest: that helper stamps SignedAt with the
	// current time, and a golden that changes every second is not a golden.
	a := Assessment{
		Tool:        "Sift",
		ToolVersion: "0.17.0",
		Target:      "https://example.com",
		Scope:       "full scope",
		Started:     "2026-11-07T08:00:00Z",
		Ended:       "2026-11-07T08:01:00Z",
		Duration:    "1m0s",
		RiskScore:   12,
		Grade:       "B",
		Verdict:     "PASS",
		Counts:      Counts{Medium: 1},
		DocumentSHA: strings.Repeat("ab", 32),
		Issuer:      "QA Lead",
		SignedAt:    "2026-11-07T08:01:00Z",
		Findings:    []Finding{{ID: "F-001", Severity: "medium", Title: "Missing CSP", Evidence: "no CSP on /"}},
		Compliance:  []ComplianceResult{{Framework: "OWASP Top 10 (2021)", ID: "A05", Title: "Security Misconfiguration", Status: "FAIL"}},
	}

	got := strings.Join(PDFLines(a, nil), "\n")
	want := strings.Join([]string{
		"Sift - Security Assessment Certificate (ss-cert/v1)",
		"",
		"Target: https://example.com",
		"Grade: B   Verdict: PASS   Risk: 12/100",
		"Findings: 1 (critical 0, high 0, medium 1, low 0, info 0)",
		"Scope: full scope",
		"Started: 2026-11-07T08:00:00Z   Ended: 2026-11-07T08:01:00Z",
		"Duration: 1m0s",
		"Issuer: QA Lead   Issued: 2026-11-07T08:01:00Z",
		"Tool: Sift 0.17.0",
		"Scanner families: -",
		"Certificate ID: -",
		"Validity: -",
		"",
		"Findings",
		"[MEDIUM] Missing CSP - no CSP on / (F-001)",
		"",
		"Compliance mapping",
		"[FAIL] OWASP Top 10 (2021) A05 - Security Misconfiguration",
		"",
		"Signature (Ed25519, over canonical assessment JSON):",
		"-",
		"Signer public key:",
		"-",
		"Document SHA-256: " + strings.Repeat("ab", 32),
		"",
		"This document is tamper-evident, not a warranty: it proves that the",
		"assessment above was sealed by the key named here, and that this page",
		"is the one that was sealed. Verify with: sift certificate cert.pdf",
	}, "\n")
	if got != want {
		t.Fatalf("printed text changed; every sealed PDF re-renders differently now:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// TestPDFSealDetectsEditedText is the reason the digest exists: the embedded
// certificate is untouched, and the page still fails, because the words a
// reader would see are no longer the words that were sealed.
func TestPDFSealDetectsEditedText(t *testing.T) {
	c := verifiableCert(t)
	certJSON, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal certificate: %v", err)
	}
	doc, err := NewPDF().
		Text("Grade: B   Verdict: PASS").
		Text("Risk: 12/100").
		Seal(certJSON).
		Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}

	edited := bytes.Replace(doc, []byte("Grade: B"), []byte("Grade: A"), 1)
	if bytes.Equal(edited, doc) {
		t.Fatal("test setup: the edit did not apply to the content stream")
	}
	res, err := VerifyPDF(edited, nil, false)
	if err == nil {
		t.Fatal("a PDF with an edited page verified")
	}
	if res == nil || res.RenderedMatch {
		t.Fatalf("edited page reported as matching: %+v", res)
	}
	if !strings.Contains(err.Error(), "does not match the sealed rendering") {
		t.Errorf("unhelpful error: %v", err)
	}
}

// TestPDFWithoutSealIsRefused: a PDF printed before sealing existed must not be
// reported as verified just because it looks like a certificate.
func TestPDFWithoutSealIsRefused(t *testing.T) {
	doc, err := NewPDF().Text("Grade: B").Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	if _, err := PDFEvidenceOf(doc); err == nil {
		t.Fatal("an unsealed PDF was accepted")
	}
	if _, err := VerifyPDF(doc, nil, false); err == nil {
		t.Fatal("an unsealed PDF verified")
	}
	// A non-PDF must be rejected before any parsing.
	if _, err := PDFEvidenceOf([]byte(`{"assessment":{}}`)); err == nil {
		t.Fatal("JSON was accepted as a PDF")
	}
}

// pdfInsertShiftingXref inserts block at offset at and rewrites the last
// cross-reference table so every in-use offset still points at its object. It is
// how a careful forger would keep a PDF structurally valid while adding an
// object the verifier is not supposed to see.
func pdfInsertShiftingXref(t *testing.T, doc, block []byte, at int) []byte {
	t.Helper()

	out := make([]byte, 0, len(doc)+len(block))
	out = append(out, doc[:at]...)
	out = append(out, block...)
	out = append(out, doc[at:]...)
	delta := len(block)

	i := bytes.LastIndex(out, []byte("\nxref\n"))
	if i < 0 {
		t.Fatal("test setup: no xref table")
	}
	i++
	tail := out[i:]

	firstNL := bytes.IndexByte(tail, '\n')
	if firstNL < 0 {
		t.Fatal("test setup: xref header is not terminated")
	}
	hdrEnd := firstNL + 1 + bytes.IndexByte(tail[firstNL+1:], '\n')
	fields := strings.Fields(string(tail[firstNL+1 : hdrEnd]))
	if len(fields) != 2 {
		t.Fatalf("test setup: xref subsection header is %q", string(tail[firstNL+1:hdrEnd]))
	}
	count, err := strconv.Atoi(fields[1])
	if err != nil {
		t.Fatalf("test setup: xref count: %v", err)
	}

	pos := hdrEnd + 1
	var rebuilt bytes.Buffer
	rebuilt.Write(tail[:pos])
	for k := 0; k < count; k++ {
		entry := tail[pos : pos+20]
		pos += 20
		if entry[17] == 'n' {
			off, err := strconv.Atoi(strings.TrimSpace(string(entry[:10])))
			if err != nil {
				t.Fatalf("test setup: xref offset %q: %v", entry[:10], err)
			}
			fmt.Fprintf(&rebuilt, "%010d 00000 n \n", off+delta)
			continue
		}
		rebuilt.Write(entry)
	}
	trailer := tail[pos:]
	end := bytes.Index(trailer, []byte("startxref"))
	if end < 0 {
		t.Fatal("test setup: no startxref after the table")
	}
	rebuilt.Write(trailer[:end])
	fmt.Fprintf(&rebuilt, "startxref\n%d\n%%%%EOF\n", i)

	return append(out[:i], rebuilt.Bytes()...)
}

// TestPDFReadsObjectsThroughXrefNotByScanning is the parser-confusion attack.
//
// The verifier used to find objects by searching the file for "\n<num> 0 obj"
// and taking the first hit. So: take a sealed certificate, change the real page
// to say grade A, then insert a decoy object with the page's content number,
// holding the original grade-B text, near the top of the file. Fix the xref to
// point at the real objects. A viewer reads the xref and shows grade A; a
// scanning verifier reads the decoy, hashes grade B, and says VALID.
//
// That file was built and confirmed against the released v0.17.0 binary before
// this test existed. Objects are now read at the offset the table gives, so the
// decoy is simply never looked at, and the real page fails the check.
func TestPDFReadsObjectsThroughXrefNotByScanning(t *testing.T) {
	c := verifiableCert(t)
	certJSON, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal certificate: %v", err)
	}
	p := NewPDF()
	for _, line := range PDFLines(c.Assessment, c) {
		p.Text(line)
	}
	genuine, err := p.Seal(certJSON).Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}

	objs := pdfParse(t, genuine)
	contentNum := mustRef(t, reContRef, objs[3], "page 1 contents")
	body := objs[contentNum]
	streamStart := strings.Index(body, "stream\n")
	streamEnd := strings.LastIndex(body, "\nendstream")
	if streamStart < 0 || streamEnd < 0 {
		t.Fatalf("test setup: content object has no stream: %q", body)
	}
	stream := body[streamStart+len("stream\n") : streamEnd]
	if !strings.Contains(stream, "Grade: B") {
		t.Fatalf("test setup: page 1 does not draw the grade: %q", stream)
	}

	// The real page now lies.
	forged := bytes.Replace(genuine, []byte("Grade: B"), []byte("Grade: A"), 1)
	if bytes.Equal(forged, genuine) {
		t.Fatal("test setup: the edit did not apply")
	}

	// The decoy carries the genuine text under the same object number, and sits
	// before every real object.
	decoy := []byte(fmt.Sprintf("\n%d 0 obj\n<< /Length %d >>\nstream\n%s\nendstream\nendobj\n",
		contentNum, len(stream), stream))
	attacked := pdfInsertShiftingXref(t, forged, decoy, len("%PDF-1.4\n"))

	expected := ExpectedPDFRenderedSHA256(c)
	got, err := PDFRenderedSHA256(attacked)
	if err != nil {
		t.Fatalf("PDFRenderedSHA256: %v", err)
	}
	if got == expected {
		t.Fatal("the verifier hashed the decoy object instead of the page a reader opens")
	}
	if _, err := VerifyPDF(attacked, nil, false); err == nil {
		t.Fatal("a PDF whose real page differs from its decoy verified")
	}
}

// TestPDFRefusesTamperedXrefOffset pins the fail-closed rule: an offset that
// does not land on the header the table promised is refused, not repaired by
// scanning for the object elsewhere.
func TestPDFRefusesTamperedXrefOffset(t *testing.T) {
	c := verifiableCert(t)
	certJSON, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal certificate: %v", err)
	}
	p := NewPDF()
	for _, line := range PDFLines(c.Assessment, c) {
		p.Text(line)
	}
	doc, err := p.Seal(certJSON).Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}

	i := bytes.LastIndex(doc, []byte("\nxref\n")) + 1
	// The free entry comes first, so object 1's entry is the one after it.
	// Locate it from the subsection header instead of hard-coding its width.
	tail := doc[i:]
	firstNL := bytes.IndexByte(tail, '\n')
	hdrEnd := firstNL + 1 + bytes.IndexByte(tail[firstNL+1:], '\n')
	entry := i + hdrEnd + 1 + 20
	off, err := strconv.Atoi(strings.TrimSpace(string(doc[entry : entry+10])))
	if err != nil {
		t.Fatalf("test setup: %v", err)
	}
	tampered := append([]byte{}, doc...)
	copy(tampered[entry:entry+10], []byte(fmt.Sprintf("%010d", off+1)))

	if _, err := PDFRenderedSHA256(tampered); err == nil {
		t.Fatal("a file whose xref points one byte off an object was accepted")
	}
	if _, err := PDFEvidenceOf(tampered); err == nil {
		t.Fatal("the seal was read from a file with a broken cross-reference table")
	}
}

// pdfRewriteObject replaces one object's body and rebuilds the file with a
// fresh cross-reference table, so the result stays well formed: a viewer
// follows the table and reaches the new body.
//
// The trailer is carried over verbatim. The attack under test is against what
// the page draws, not against the parser, so /Root and the catalog's
// /SiftEvidence reference must still point where they did.
func pdfRewriteObject(t *testing.T, doc []byte, num int, body string) []byte {
	t.Helper()
	objs := pdfParse(t, doc)
	if _, ok := objs[num]; !ok {
		t.Fatalf("test setup: no object %d", num)
	}
	objs[num] = body

	i := bytes.LastIndex(doc, []byte("trailer\n"))
	if i < 0 {
		t.Fatal("test setup: no trailer")
	}
	j := bytes.Index(doc[i:], []byte("startxref"))
	if j < 0 {
		t.Fatal("test setup: no startxref after the trailer")
	}
	trailer := doc[i : i+j]

	max := 0
	for n := range objs {
		if n > max {
			max = n
		}
	}

	var b bytes.Buffer
	b.WriteString("%PDF-1.4\n")
	offsets := make([]int, max+1)
	for n := 1; n <= max; n++ {
		body, ok := objs[n]
		if !ok {
			t.Fatalf("test setup: object %d missing from the document", n)
		}
		offsets[n] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n", n)
		b.WriteString(body)
		b.WriteString("endobj\n")
	}

	xrefAt := b.Len()
	b.WriteString("xref\n")
	fmt.Fprintf(&b, "0 %d\n", max+1)
	b.WriteString("0000000000 65535 f \n")
	for n := 1; n <= max; n++ {
		fmt.Fprintf(&b, "%010d 00000 n \n", offsets[n])
	}
	b.Write(trailer)
	fmt.Fprintf(&b, "startxref\n%d\n%%%%EOF\n", xrefAt)
	return b.Bytes()
}

// pdfSealedGenuine prints the verifiable certificate and returns the file, the
// page-1 content stream and the number of the object that holds it.
func pdfSealedGenuine(t *testing.T) ([]byte, int, string) {
	t.Helper()
	c := verifiableCert(t)
	certJSON, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal certificate: %v", err)
	}
	p := NewPDF()
	for _, line := range PDFLines(c.Assessment, c) {
		p.Text(line)
	}
	doc, err := p.Seal(certJSON).Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	objs := pdfParse(t, doc)
	contentNum := mustRef(t, reContRef, objs[3], "page 1 contents")
	body := objs[contentNum]
	start := strings.Index(body, "stream\n")
	end := strings.LastIndex(body, "\nendstream")
	if start < 0 || end < 0 {
		t.Fatalf("test setup: content object has no stream: %q", body)
	}
	return doc, contentNum, body[start+len("stream\n") : end]
}

// TestPDFRejectsNonTextDrawing is the attack the text digest cannot see.
//
// The rendered digest covers the literal strings a page draws: it walks the
// content streams looking for "(...)" followed by " Tj". Everything else a
// viewer obeys is outside it. So append to page 1's content stream a filled
// white rectangle over the grade line and the grade drawn again as a hex
// string — text, but not in the form the digest collects.
//
// Against the released v0.17.0 binary that file verified VALID. Rendered by a
// viewer, the grade reads A and the "Verdict: PASS" text beside it is painted
// over: five dark pixels on the genuine page, none on this one.
//
// The object check refuses it, and the two text-level checks below still pass —
// which is the point. They are not wrong, they are just not enough.
func TestPDFRejectsNonTextDrawing(t *testing.T) {
	genuine, contentNum, stream := pdfSealedGenuine(t)
	if !strings.Contains(stream, "Grade: B") {
		t.Fatalf("test setup: page 1 does not draw the grade: %q", stream)
	}

	overlay := "\nq\n1 1 1 rg\n50 738 495 16 re f\nQ\n" +
		"BT\n/F1 10 Tf\n50 744 Td\n<" + hex.EncodeToString([]byte("Grade: A")) + "> Tj\nET\n"
	newStream := stream + overlay
	attacked := pdfRewriteObject(t, genuine, contentNum,
		fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream\n", len(newStream), newStream))

	res, err := VerifyPDF(attacked, nil, false)
	if err == nil {
		t.Fatal("a PDF that paints over its grade and redraws it as a hex string verified")
	}
	if res == nil {
		t.Fatal("no result returned for a rejected PDF")
	}
	if !res.RenderedMatch {
		t.Fatal("test setup: the text digest should be unchanged — no new (...) string was added")
	}
	if !res.RenderingMatchesCertificate {
		t.Fatal("test setup: the text still equals the certificate's rendering; that is why it was not enough")
	}
	if res.ObjectsMatchCertificate {
		t.Fatal("the appended drawing was reported as part of the certificate")
	}
	if !strings.Contains(err.Error(), "object") {
		t.Errorf("unhelpful error: %v", err)
	}
}

// TestPDFRejectsSwappedFont pins the other half: a font dictionary is not text,
// so swapping /BaseFont changes how every line looks without changing a byte
// the digest hashes. It must not verify.
func TestPDFRejectsSwappedFont(t *testing.T) {
	genuine, _, _ := pdfSealedGenuine(t)
	objs := pdfParse(t, genuine)
	fontNum := mustRef(t, reFontRef, objs[3], "page 1 font")
	body := objs[fontNum]
	swapped := strings.Replace(body, "/Helvetica", "/Times-Roman", 1)
	if swapped == body {
		t.Fatalf("test setup: font object does not name Helvetica: %q", body)
	}

	res, err := VerifyPDF(pdfRewriteObject(t, genuine, fontNum, swapped), nil, false)
	if err == nil {
		t.Fatal("a PDF whose font was swapped after sealing verified")
	}
	if res == nil {
		t.Fatal("no result returned for a rejected PDF")
	}
	if !res.RenderingMatchesCertificate {
		t.Fatal("test setup: a font swap leaves the text digest unchanged")
	}
	if res.ObjectsMatchCertificate {
		t.Fatal("the swapped font dictionary was reported as part of the certificate")
	}
}

// TestPDFRejectsStrayObjectDefinition covers the mirror image of the decoy
// attack: leave the object the table names untouched and append a second
// definition of it that says something else. A reader that follows the table
// shows the genuine grade; a reader that takes the last definition it finds
// shows the forged one. The file is refused because it has two answers, not
// because one of them is preferred.
func TestPDFRejectsStrayObjectDefinition(t *testing.T) {
	genuine, contentNum, stream := pdfSealedGenuine(t)
	lie := strings.Replace(stream, "Grade: B", "Grade: A", 1)
	if lie == stream {
		t.Fatal("test setup: the page does not draw the grade")
	}
	stray := fmt.Sprintf("\n%d 0 obj\n<< /Length %d >>\nstream\n%s\nendstream\nendobj\n",
		contentNum, len(lie), lie)
	attacked := append(append([]byte{}, genuine...), stray...)

	res, err := VerifyPDF(attacked, nil, false)
	if err == nil {
		t.Fatal("a PDF with a second definition of its content object verified")
	}
	if res == nil {
		t.Fatal("no result returned for a rejected PDF")
	}
	if res.ObjectsMatchCertificate {
		t.Fatal("the stray definition was reported as part of the certificate")
	}
	if !strings.Contains(err.Error(), "does not name") {
		t.Errorf("unhelpful error: %v", err)
	}
}
