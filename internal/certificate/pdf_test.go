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
	"encoding/json"
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
	if got, want := pdfEncode("Maktab — 12"), "Maktab \\227 12"; got != want {
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

	doc, err := NewPDF().
		Text("Sift - Security Assessment Certificate (ss-cert/v1)").
		Text("Grade: B   Verdict: PASS").
		Text("A line long enough to wrap onto a second physical line so the digest covers wrapped text too: " + strings.Repeat("x", 200)).
		Seal(certJSON).
		Bytes()
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
