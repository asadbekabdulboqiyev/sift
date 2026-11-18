package certificate

import (
	"bytes"
	"fmt"
	"strings"
)

// pdf.go — a minimal, dependency-free PDF 1.4 writer.
//
// # Why hand-rolled
//
// A certificate must be printable on a machine with no network and no extra
// packages. Pulling a PDF library in for one page of Helvetica is not worth the
// supply-chain surface, so this file writes the 20-odd objects a PDF needs
// itself.
//
// # What went wrong before, and what keeps it from going wrong again
//
// The previous version wrote `/Font << /F1 3 0 R >>` and `/Contents 4 0 R` by
// counting objects with a separate variable instead of using the numbers the
// writer actually allocated. The result was a page that pointed at itself for a
// font and at a font for its content: every certificate PDF rendered as a
// completely blank page, in every viewer, while still being a structurally
// "valid" file. Nothing caught it because the old test only asserted the bytes
// were non-empty.
//
// So: object numbers are assigned deterministically (page i is object 3+3i, its
// font 4+3i, its content 5+3i) and each object header is written at the moment
// its body is written, so a reference can never name an object that does not
// exist. pdf_test.go resolves the cross-references and checks the referenced
// object types, rather than only asserting that a file was produced.
//
// # Layout rules
//
//   - A4, 595.28x841.89 pt, Helvetica 10 pt, 50 pt side margins. The HTML
//     document is A4, so the printed copy must be A4 too: a Letter sheet
//     shrinks the certificate by about 5% on a European printer and leaves a
//     wider white strip at the right edge.
//   - One Text() call is one logical line. A line too wide for the page is
//     wrapped, because a signature is 128 hex characters and a clipped
//     signature is the one line a reader must be able to read.
//   - A page that runs past the bottom margin spills onto a new page instead of
//     drawing text below y=0, where it is invisible.
//   - Text is encoded as WinAnsi. A rune WinAnsi cannot represent becomes "?"
//     rather than a broken octal escape that silently corrupts the string.
const (
	pdfPageWidth  = 595.28 // A4, portrait (210 mm)
	pdfPageHeight = 841.89 // A4, portrait (297 mm)
	pdfMarginX    = 50.0
	pdfTopY       = 789.0
	pdfBottomY    = 60.0
	pdfLineHeight = 15.0
	pdfFontSize   = 10.0
	pdfTextWidth  = pdfPageWidth - 2*pdfMarginX // 495.28 pt

	// pdfMaxLines is how many 15 pt lines fit between the top and bottom
	// margins: floor((789-60)/15) = 48.
	pdfMaxLines = 48
)

// PDF accumulates lines and writes them as a PDF document.
type PDF struct {
	pages [][]string
	// seal, when set, is the signed certificate JSON embedded in the PDF and
	// bound to the rendered text. See pdf_evidence.go.
	seal []byte
}

// NewPDF starts a PDF document with one blank page.
func NewPDF() *PDF {
	return &PDF{pages: [][]string{{}}}
}

// Page starts a new page.
func (p *PDF) Page() *PDF {
	p.pages = append(p.pages, []string{})
	return p
}

// Text appends a line to the current page. The line may be longer than the
// page is wide; Bytes wraps it.
func (p *PDF) Text(s string) *PDF {
	top := &p.pages[len(p.pages)-1]
	*top = append(*top, s)
	return p
}

// Bytes finalizes and returns the PDF bytes.
//
// The returned document may hold more pages than Page() was called, because a
// page that overflows spills onto the next one.
func (p *PDF) Bytes() ([]byte, error) {
	pages := p.layout()

	// The evidence object sits after the last page's content stream, so object
	// numbers stay contiguous: pages are 3+3i, fonts 4+3i, contents 5+3i, and
	// the seal is 3+3*pages.
	evObj := 0
	if p.seal != nil {
		evObj = 3 + 3*len(pages)
	}

	var b bytes.Buffer
	b.WriteString("%PDF-1.4\n")

	// offsets[n] is the byte offset of object n. Index 0 is unused, as in the
	// xref table.
	offsets := []int{0}
	writeObj := func(n int, body string) {
		for len(offsets) <= n {
			offsets = append(offsets, 0)
		}
		offsets[n] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n", n)
		b.WriteString(body)
		b.WriteString("endobj\n")
	}
	writeStream := func(n int, data []byte) {
		for len(offsets) <= n {
			offsets = append(offsets, 0)
		}
		offsets[n] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n<< /Length %d >>\nstream\n", n, len(data))
		b.Write(data)
		b.WriteString("\nendstream\nendobj\n")
	}

	// 1: catalog
	catalog := "<< /Type /Catalog /Pages 2 0 R"
	if evObj != 0 {
		catalog += fmt.Sprintf(" /SiftEvidence %d 0 R", evObj)
	}
	writeObj(1, catalog+" >>\n")

	// 2: page tree. Object numbers are assigned deterministically: page i is
	// 3+3i, its font 4+3i, its content 5+3i. Nothing is allocated by a counter
	// that can drift from what the dictionaries name — that drift is exactly
	// what made every certificate PDF blank.
	var kids strings.Builder
	for i := range pages {
		fmt.Fprintf(&kids, "%d 0 R ", 3+3*i)
	}
	writeObj(2, fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d /MediaBox [0 0 %.2f %.2f] >>\n",
		strings.TrimSpace(kids.String()), len(pages), pdfPageWidth, pdfPageHeight))

	for i, lines := range pages {
		pageObj, fontObj, contentObj := 3+3*i, 4+3*i, 5+3*i
		writeObj(pageObj, fmt.Sprintf(
			"<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 %d 0 R >> >> /Contents %d 0 R >>\n",
			fontObj, contentObj))
		writeObj(fontObj, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>\n")
		writeStream(contentObj, buildContent(lines))
	}

	if evObj != 0 {
		ev, err := pdfEvidenceStream(p.seal, pdfRenderedDigest(pages))
		if err != nil {
			return nil, err
		}
		writeStream(evObj, ev)
	}

	xrefOff := b.Len()
	numObjs := len(offsets) - 1
	b.WriteString("xref\n")
	fmt.Fprintf(&b, "0 %d\n", numObjs+1)
	b.WriteString("0000000000 65535 f \n")
	for n := 1; n <= numObjs; n++ {
		if offsets[n] == 0 {
			// A gap would make the xref table lie; refuse rather than emit it.
			return nil, fmt.Errorf("pdf: object %d was never written", n)
		}
		fmt.Fprintf(&b, "%010d 00000 n \n", offsets[n])
	}
	b.WriteString("trailer\n")
	fmt.Fprintf(&b, "<< /Size %d /Root 1 0 R >>\n", numObjs+1)
	b.WriteString("startxref\n")
	fmt.Fprintf(&b, "%d\n", xrefOff)
	b.WriteString("%%EOF\n")

	return b.Bytes(), nil
}

// layout wraps every line and splits each requested page into as many physical
// pages as it needs. An empty requested page stays one empty page: a caller who
// called Page() meant to start a new sheet.
func (p *PDF) layout() [][]string {
	maxLines := pdfMaxLines
	pages := make([][]string, 0, len(p.pages))
	for _, src := range p.pages {
		var lines []string
		for _, raw := range src {
			lines = append(lines, wrapText(raw, pdfFontSize, pdfTextWidth)...)
		}
		if len(lines) == 0 {
			pages = append(pages, nil)
			continue
		}
		for len(lines) > maxLines {
			pages = append(pages, lines[:maxLines])
			lines = lines[maxLines:]
		}
		pages = append(pages, lines)
	}
	if len(pages) == 0 {
		pages = [][]string{{}}
	}
	return pages
}

func buildContent(lines []string) []byte {
	var b bytes.Buffer
	b.WriteString("BT\n")
	fmt.Fprintf(&b, "/F1 %.0f Tf\n", pdfFontSize)
	fmt.Fprintf(&b, "%.0f %.0f Td\n", pdfMarginX, pdfTopY)
	for _, s := range lines {
		fmt.Fprintf(&b, "(%s) Tj\n", pdfEncode(s))
		fmt.Fprintf(&b, "0 %.0f Td\n", -pdfLineHeight)
	}
	b.WriteString("ET\n")
	return b.Bytes()
}

// winAnsiBytes encodes s as the bytes a WinAnsi string draws. A rune WinAnsi
// cannot represent becomes "?", which is exactly what the page shows, so the
// rendering digest hashes what a reader sees rather than what was intended.
func winAnsiBytes(s string) []byte {
	out := make([]byte, 0, len(s))
	for _, r := range s {
		code, ok := winAnsi(r)
		if !ok {
			code = '?'
		}
		out = append(out, code)
	}
	return out
}

// pdfEncode renders s as the body of a PDF literal string under WinAnsi
// encoding. The three delimiters are backslash-escaped; bytes outside printable
// ASCII are written as three-digit octal escapes, which is how a WinAnsi high
// byte is spelled in a literal string.
func pdfEncode(s string) string {
	var sb strings.Builder
	for _, code := range winAnsiBytes(s) {
		switch code {
		case '(', ')', '\\':
			sb.WriteByte('\\')
			sb.WriteByte(code)
			continue
		}
		if code < 32 || code > 126 {
			fmt.Fprintf(&sb, "\\%03o", code)
		} else {
			sb.WriteByte(code)
		}
	}
	return sb.String()
}

// winAnsi maps a rune to its WinAnsi code point. The encoding agrees with
// Latin-1 from 0xA0 up, so those runes pass through; the 0x80-0x9F range holds
// the typographic characters that show up in real prose, and it is mapped
// explicitly rather than guessed.
func winAnsi(r rune) (byte, bool) {
	switch r {
	case '\t', '\n', '\r':
		return ' ', true
	case '\u20ac': // €
		return 0x80, true
	case '\u2026': // …
		return 0x85, true
	case '\u2018': // '
		return 0x91, true
	case '\u2019': // '
		return 0x92, true
	case '\u201c': // "
		return 0x93, true
	case '\u201d': // "
		return 0x94, true
	case '\u2022': // •
		return 0x95, true
	case '\u2013': // –
		return 0x96, true
	case '\u2014': // —
		return 0x97, true
	case '\u00ab': // «
		return 0xab, true
	case '\u00bb': // »
		return 0xbb, true
	case '\u00b0': // °
		return 0xb0, true
	case '\u00b7': // ·
		return 0xb7, true
	case '\u00d7': // ×
		return 0xd7, true
	}
	if r >= 32 && r <= 126 {
		return byte(r), true
	}
	if r >= 160 && r <= 255 {
		return byte(r), true
	}
	return 0, false
}

// helveticaWidths[i] is the advance width of ASCII 32+i in 1/1000 em for
// Helvetica. It exists only to decide where to wrap: a wrong value costs a
// little whitespace, never correctness, which is why an approximate table is
// acceptable here but an approximate *reference* was not.
var helveticaWidths = [95]uint16{
	278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, // 32-47
	556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556, // 48-63
	1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778, // 64-79
	667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556, // 80-95
	333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, // 96-111
	556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584, // 112-126
}

// runeWidth returns the advance width of r in 1/1000 em. Anything WinAnsi
// cannot draw is measured as an average glyph, since it will be written as '?'.
func runeWidth(r rune) float64 {
	code, ok := winAnsi(r)
	if !ok {
		return 556
	}
	if code < 32 || code > 126 {
		return 556
	}
	return float64(helveticaWidths[int(code)-32])
}

// wrapText breaks s into lines that each fit inside maxWidth points at the
// given size. It prefers a space; a token with no space in it (a signature, a
// URL) is split at the character that fits. Nothing is ever dropped except the
// single space a break consumes.
func wrapText(s string, size, maxWidth float64) []string {
	s = strings.TrimRight(s, " ")
	if s == "" {
		return []string{""}
	}
	var out []string
	for _, para := range strings.Split(s, "\n") {
		out = append(out, wrapParagraph(para, size, maxWidth)...)
	}
	return out
}

func wrapParagraph(para string, size, maxWidth float64) []string {
	rs := []rune(para)
	if len(rs) == 0 {
		return []string{""}
	}
	var out []string
	for start := 0; start < len(rs); {
		end := start
		width := 0.0
		lastSpace := -1
		for end < len(rs) {
			w := runeWidth(rs[end]) * size / 1000
			if width+w > maxWidth {
				break
			}
			width += w
			if rs[end] == ' ' {
				lastSpace = end
			}
			end++
		}
		if end == len(rs) {
			out = append(out, string(rs[start:]))
			break
		}
		if lastSpace > start {
			out = append(out, string(rs[start:lastSpace]))
			start = lastSpace + 1
			continue
		}
		if end == start {
			end = start + 1 // one glyph wider than the whole line
		}
		out = append(out, string(rs[start:end]))
		start = end
	}
	return out
}
