package certificate

// pdf_evidence.go — makes a printed certificate verifiable on its own.
//
// # The problem
//
// A certificate JSON is self-verifying: the signature covers the assessment,
// and the document hash covers the rendered HTML that is embedded beside it.
// The PDF is not. It is a rendering: the text a reader sees is drawn by the
// writer, and nothing in it says "this is the text that was sealed". So a PDF
// on its own can only be trusted as far as the person who handed it over.
//
// # The fix
//
// The writer embeds a sealed envelope in the PDF and binds the visible text to
// it:
//
//   - the signed certificate JSON, so the signature and the document hash can
//     be checked with no other file and no network;
//   - SHA-256 over the exact bytes of every rendered line, in page order, so
//     editing a single character on the page breaks the check.
//
// The digest is taken over the WinAnsi bytes the page actually draws, after
// wrapping and after unrepresentable runes became "?". That means the verifier
// can recompute it by reading the content streams back — no font metrics, no
// layout engine, no HTML parser. A PDF whose visible text was altered fails,
// even though its embedded JSON is untouched.
//
// # Why the digest alone is not enough
//
// A digest stored in the file is only as trustworthy as the file. An editor who
// rewrites the page can rewrite the digest next to it, and then the page agrees
// with its own seal. That is not a hypothetical: with the certificate left
// untouched, a signed grade-B certificate could be printed onto a page claiming
// grade A, and every check the first version made said VALID.
//
// So the verifier does not stop at page == seal. It re-renders the pages the
// embedded certificate is supposed to produce (CertificatePDFLines in
// pdf_certificate.go, the same function the printer calls) and requires the
// page digest to equal that. The seal becomes redundant evidence rather than the
// authority: a rebuilt file fails because no issuer signed a page that says A.
//
// # What this does not prove
//
// The digest covers text, because text is what this writer draws. A future
// writer that draws rules or images would need those in the digest too; until
// then, claim "the words on this page are the words that were sealed", not
// "not one pixel changed".
//
// A PDF printed before this envelope existed has no /SiftEvidence object. It is
// rejected with a message pointing at the JSON certificate rather than being
// silently accepted: an unverifiable page must not look verified.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/asadbekabdulboqiyev/sift/internal/attest"
)

// PDFEvidenceVersion is the envelope schema. A verifier that meets an unknown
// version refuses it instead of guessing which fields it can trust.
const PDFEvidenceVersion = "sift-cert-pdf/v1"

// PDFEvidence is the envelope carried inside a sealed PDF.
type PDFEvidence struct {
	Version        string          `json:"version"`
	Certificate    json.RawMessage `json:"certificate"`
	RenderedSHA256 string          `json:"rendered_sha256"`
}

// Seal embeds the signed certificate in the PDF and binds the rendered text to
// it. It must be called before Bytes; a PDF built without it stays printable
// but not verifiable, and PDFEvidenceOf says so instead of passing it.
func (p *PDF) Seal(certJSON []byte) *PDF {
	p.seal = certJSON
	return p
}

// pdfEvidenceStream builds the base64 payload written as the /SiftEvidence
// object. Base64 keeps the stream ASCII, so a target name containing the bytes
// "endstream" cannot break the object scan.
func pdfEvidenceStream(certJSON []byte, digest string) ([]byte, error) {
	payload, err := json.Marshal(PDFEvidence{
		Version:        PDFEvidenceVersion,
		Certificate:    certJSON,
		RenderedSHA256: digest,
	})
	if err != nil {
		return nil, fmt.Errorf("certificate: seal pdf evidence: %w", err)
	}
	return []byte(base64.StdEncoding.EncodeToString(payload)), nil
}

// pdfRenderedDigest hashes the page text as it will be drawn: WinAnsi bytes per
// line, one newline after each. The verifier rebuilds the same bytes from the
// content streams, so the two sides share one definition of "the page".
func pdfRenderedDigest(pages [][]string) string {
	h := sha256.New()
	for _, page := range pages {
		for _, line := range page {
			h.Write(winAnsiBytes(line))
			h.Write([]byte{'\n'})
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// PDFEvidenceOf reads the sealed envelope out of a PDF.
//
// Every failure is a refusal with a reason a reader can act on: not a PDF, no
// envelope (printed before sealing), unknown version, damaged payload.
func PDFEvidenceOf(data []byte) (*PDFEvidence, error) {
	doc, err := parsePDFDoc(data)
	if err != nil {
		return nil, err
	}

	catalog, err := doc.object(doc.root)
	if err != nil {
		return nil, err
	}
	m := reSiftEvidence.FindSubmatch(catalog)
	if m == nil {
		return nil, fmt.Errorf("certificate: this PDF carries no seal, so it cannot be verified on its own — it was printed before PDFs embedded their certificate. Verify the .json certificate instead, or re-issue the PDF from it")
	}
	evNum, err := strconv.Atoi(string(m[1]))
	if err != nil {
		return nil, fmt.Errorf("certificate: PDF catalog names a bad /SiftEvidence object")
	}

	obj, err := doc.object(evNum)
	if err != nil {
		return nil, err
	}
	body, err := pdfStreamOf(obj)
	if err != nil {
		return nil, err
	}

	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
	if err != nil {
		return nil, fmt.Errorf("certificate: PDF seal payload is damaged (base64): %w", err)
	}

	var ev PDFEvidence
	if err := json.Unmarshal(raw, &ev); err != nil {
		return nil, fmt.Errorf("certificate: PDF seal payload is damaged (json): %w", err)
	}
	if ev.Version != PDFEvidenceVersion {
		return nil, fmt.Errorf("certificate: PDF seal version %q is not supported (this build reads %q)", ev.Version, PDFEvidenceVersion)
	}
	if len(ev.Certificate) == 0 {
		return nil, fmt.Errorf("certificate: PDF seal carries no certificate")
	}
	if strings.TrimSpace(ev.RenderedSHA256) == "" {
		return nil, fmt.Errorf("certificate: PDF seal carries no rendering digest")
	}
	return &ev, nil
}

// PDFRenderedSHA256 recomputes the digest of the visible text from the page
// content streams.
func PDFRenderedSHA256(data []byte) (string, error) {
	doc, err := parsePDFDoc(data)
	if err != nil {
		return "", err
	}

	contents, err := doc.pageContentObjects()
	if err != nil {
		return "", err
	}

	h := sha256.New()
	for _, num := range contents {
		n, err := strconv.Atoi(num)
		if err != nil {
			return "", fmt.Errorf("certificate: PDF page names a bad /Contents object")
		}
		obj, err := doc.object(n)
		if err != nil {
			return "", err
		}
		stream, err := pdfStreamOf(obj)
		if err != nil {
			return "", err
		}
		for _, line := range pdfContentLines(stream) {
			h.Write(line)
			h.Write([]byte{'\n'})
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// PDFVerifyResult is the outcome of verifying a printed certificate.
type PDFVerifyResult struct {
	Certificate *Certificate
	Check       TrustCheck

	// RenderedSHA256 is the digest recomputed from the pages, and
	// SealRenderedSHA256 the one the issuer wrote into the seal. RenderedMatch
	// is the answer to "is this the page that was sealed?".
	RenderedSHA256     string
	SealRenderedSHA256 string
	RenderedMatch      bool

	// ExpectedRenderedSHA256 is the digest the embedded certificate renders to,
	// computed here rather than read from the file. RenderedMatch only compares
	// the page with the seal, and a seal can be rewritten by whoever rewrote the
	// page; this is the value that cannot be. RenderingMatchesCertificate says
	// the page and the seal both equal it.
	ExpectedRenderedSHA256      string
	RenderingMatchesCertificate bool
}

// VerifyPDF checks a printed certificate without any side file: the embedded
// certificate must pass signature and document-hash verification, and the text
// drawn on the pages must be the text that certificate renders to.
//
// Two comparisons are made, and the second is the one that matters:
//
//   - page digest == seal digest — the page is the page the seal describes. On
//     its own this is weak: an editor can rewrite both.
//   - page digest == digest re-rendered from the embedded certificate — the page
//     is this certificate, not merely self-consistent. Without this, a signed
//     grade-B certificate could be printed onto a page claiming grade A with a
//     matching seal, and every signature check would still pass.
func VerifyPDF(data []byte, store *attest.TrustStore, requireAnchor bool) (*PDFVerifyResult, error) {
	ev, err := PDFEvidenceOf(data)
	if err != nil {
		return nil, err
	}

	c, check, verifyErr := VerifyBytesWithTrust(ev.Certificate, store, requireAnchor)

	got, err := PDFRenderedSHA256(data)
	if err != nil {
		return nil, err
	}
	res := &PDFVerifyResult{
		Certificate:        c,
		Check:              check,
		RenderedSHA256:     got,
		SealRenderedSHA256: strings.ToLower(strings.TrimSpace(ev.RenderedSHA256)),
		RenderedMatch:      got == strings.ToLower(strings.TrimSpace(ev.RenderedSHA256)),
	}
	if verifyErr != nil {
		return res, verifyErr
	}

	res.ExpectedRenderedSHA256 = ExpectedPDFRenderedSHA256(c)
	res.RenderingMatchesCertificate = res.ExpectedRenderedSHA256 != "" &&
		got == res.ExpectedRenderedSHA256 &&
		res.SealRenderedSHA256 == res.ExpectedRenderedSHA256

	if !res.RenderedMatch {
		return res, fmt.Errorf("certificate: the visible text of this PDF does not match the sealed rendering (page %s, seal %s) — the printed copy was altered after signing", shortDigest(got), shortDigest(res.SealRenderedSHA256))
	}
	if !res.RenderingMatchesCertificate {
		return res, fmt.Errorf("certificate: this PDF's seal was written for text that this certificate does not render (page %s, expected %s) — the file was rebuilt after signing, so the page is not the sealed document", shortDigest(got), shortDigest(res.ExpectedRenderedSHA256))
	}
	return res, nil
}

func shortDigest(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[:16] + "..."
}

var (
	reSiftEvidence = regexp.MustCompile(`/SiftEvidence\s+(\d+)\s+0\s+R`)
	reObjRef       = regexp.MustCompile(`(\d+)\s+0\s+R`)
	reContentsRef  = regexp.MustCompile(`/Contents\s+(\d+)\s+0\s+R`)
	reContentsArr  = regexp.MustCompile(`/Contents\s*\[`)
	rePagesRef     = regexp.MustCompile(`/Pages\s+(\d+)\s+0\s+R`)
	reKidsArray    = regexp.MustCompile(`(?s)/Kids\s*\[([^\]]*)\]`)
	reTrailerSize  = regexp.MustCompile(`/Size\s+(\d+)`)
	reTrailerRoot  = regexp.MustCompile(`/Root\s+(\d+)\s+0\s+R`)
)

// pdfDoc locates objects the way a reader does: through the cross-reference
// table, not by scanning for text that looks like an object header.
//
// # Why this matters
//
// The first version searched the file for "\n<num> 0 obj" and took the first
// hit. That is not how a PDF is read, and the difference is exploitable: insert
// an object header with the genuine page's number near the top of the file,
// point the real page's content at the forged text, and fix up the xref so a
// viewer shows the forged page. A verifier that scans finds the decoy first and
// hashes the genuine text, so it reports VALID while the page a reader opens
// says something else. That attack was built and confirmed against the strict
// re-render check before this type existed.
//
// So the table is the authority. Every object is read from the offset the xref
// gives, and the header there must name the object the table promised; anything
// else is refused rather than guessed at.
//
// # What it refuses
//
// Cross-reference streams (PDF 1.5+), incremental updates (/Prev), and a
// document with no catalog. None of these appear in a file this package wrote,
// so meeting one means the file was produced or re-saved by something else, and
// the honest answer is "re-print it from the certificate" rather than a verdict
// based on a parse we do not trust.
type pdfDoc struct {
	data    []byte
	offsets map[int]int
	root    int
}

// parsePDFDoc reads the last cross-reference table and the trailer.
func parsePDFDoc(data []byte) (*pdfDoc, error) {
	if !bytes.HasPrefix(data, []byte("%PDF-")) {
		return nil, fmt.Errorf("certificate: not a PDF file (no %%PDF- header)")
	}

	marker := bytes.LastIndex(data, []byte("startxref"))
	if marker < 0 {
		return nil, fmt.Errorf("certificate: PDF has no startxref pointer, so its cross-reference table cannot be found")
	}
	off, err := readPDFInt(data, marker+len("startxref"))
	if err != nil {
		return nil, fmt.Errorf("certificate: PDF startxref pointer is damaged: %w", err)
	}
	if off < 0 || off >= len(data) {
		return nil, fmt.Errorf("certificate: PDF startxref points outside the file")
	}
	if !bytes.HasPrefix(data[off:], []byte("xref")) {
		return nil, fmt.Errorf("certificate: this PDF uses a cross-reference stream (PDF 1.5+) instead of a table; this verifier does not read those — re-print the certificate from its JSON")
	}

	d := &pdfDoc{data: data, offsets: make(map[int]int)}
	pos := off + len("xref")
	for {
		pos = skipPDFSpace(data, pos)
		if pos >= len(data) {
			return nil, fmt.Errorf("certificate: PDF cross-reference table is truncated")
		}
		if bytes.HasPrefix(data[pos:], []byte("trailer")) {
			break
		}
		startNum, err := readPDFInt(data, pos)
		if err != nil {
			return nil, fmt.Errorf("certificate: PDF cross-reference subsection is damaged: %w", err)
		}
		countPos, err := skipPDFInt(data, pos)
		if err != nil {
			return nil, fmt.Errorf("certificate: PDF cross-reference subsection is damaged: %w", err)
		}
		count, err := readPDFInt(data, countPos)
		if err != nil {
			return nil, fmt.Errorf("certificate: PDF cross-reference subsection is damaged: %w", err)
		}
		pos, err = skipPDFInt(data, countPos)
		if err != nil {
			return nil, fmt.Errorf("certificate: PDF cross-reference subsection is damaged: %w", err)
		}
		// The subsection header ends at a line break; the entries start on the
		// next line. Skipping only the number would leave pos on "\n" and the
		// first entry would be read as an empty line.
		pos = skipPDFSpace(data, pos)
		if count < 0 || count > len(data) {
			return nil, fmt.Errorf("certificate: PDF cross-reference subsection claims %d entries", count)
		}

		for i := 0; i < count; i++ {
			line, next := readPDFLine(data, pos)
			fields := strings.Fields(line)
			if len(fields) < 3 {
				return nil, fmt.Errorf("certificate: PDF cross-reference entry is malformed: %q", line)
			}
			if fields[2] == "n" {
				entryOff, err := strconv.Atoi(fields[0])
				if err != nil || entryOff < 0 || entryOff >= len(data) {
					return nil, fmt.Errorf("certificate: PDF cross-reference entry %d points outside the file", startNum+i)
				}
				d.offsets[startNum+i] = entryOff
			}
			pos = next
		}
	}

	trailer := data[pos:]
	if bytes.Contains(trailer, []byte("/Prev")) {
		return nil, fmt.Errorf("certificate: this PDF has an incremental update (/Prev), so it has more than one version of its pages; this verifier reads one document only — re-print the certificate from its JSON")
	}
	if m := reTrailerSize.FindSubmatch(trailer); m == nil {
		return nil, fmt.Errorf("certificate: PDF trailer has no /Size")
	} else if size, err := strconv.Atoi(string(m[1])); err != nil || size <= 0 {
		return nil, fmt.Errorf("certificate: PDF trailer has an unusable /Size")
	}
	root := reTrailerRoot.FindSubmatch(trailer)
	if root == nil {
		return nil, fmt.Errorf("certificate: PDF trailer names no /Root catalog")
	}
	d.root, err = strconv.Atoi(string(root[1]))
	if err != nil {
		return nil, fmt.Errorf("certificate: PDF trailer /Root is not an object number")
	}
	return d, nil
}

// readPDFInt reads a non-negative decimal integer starting at pos.
func readPDFInt(data []byte, pos int) (int, error) {
	pos = skipPDFSpace(data, pos)
	start := pos
	for pos < len(data) && data[pos] >= '0' && data[pos] <= '9' {
		pos++
	}
	if pos == start {
		return 0, fmt.Errorf("expected a number at byte %d", start)
	}
	n, err := strconv.Atoi(string(data[start:pos]))
	if err != nil {
		return 0, err
	}
	return n, nil
}

// skipPDFInt returns the position just past the integer that starts at pos.
func skipPDFInt(data []byte, pos int) (int, error) {
	pos = skipPDFSpace(data, pos)
	start := pos
	for pos < len(data) && data[pos] >= '0' && data[pos] <= '9' {
		pos++
	}
	if pos == start {
		return 0, fmt.Errorf("expected a number at byte %d", start)
	}
	return pos, nil
}

func skipPDFSpace(data []byte, pos int) int {
	for pos < len(data) {
		switch data[pos] {
		case ' ', '\t', '\r', '\n', '\f', 0:
			pos++
		default:
			return pos
		}
	}
	return pos
}

// readPDFLine returns the line starting at pos and the position after it.
func readPDFLine(data []byte, pos int) (string, int) {
	end := bytes.IndexByte(data[pos:], '\n')
	if end < 0 {
		return string(data[pos:]), len(data)
	}
	return string(data[pos : pos+end]), pos + end + 1
}

// object returns the body of object num, from its header through "endobj".
//
// The header at the table's offset must name this object. A mismatch is not
// repaired or retried: it means the table and the bytes disagree, which is what
// a file looks like when someone tried to show one reader a different document
// than another.
func (d *pdfDoc) object(num int) ([]byte, error) {
	off, ok := d.offsets[num]
	if !ok {
		return nil, fmt.Errorf("certificate: PDF object %d is not in the cross-reference table", num)
	}
	rest := d.data[off:]
	want := strconv.Itoa(num) + " 0 obj"
	if !bytes.HasPrefix(rest, []byte(want)) {
		return nil, fmt.Errorf("certificate: the cross-reference table points object %d at %q, not at its header — the file is malformed or was tampered with", num, headBytes(rest, 24))
	}
	end := bytes.Index(rest, []byte("endobj"))
	if end < 0 {
		return nil, fmt.Errorf("certificate: PDF object %d is truncated", num)
	}
	return rest[:end], nil
}

func headBytes(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	return string(b)
}

// pdfStreamOf returns the bytes between "stream" and "endstream" in an object.
func pdfStreamOf(obj []byte) ([]byte, error) {
	i := bytes.Index(obj, []byte("stream"))
	if i < 0 {
		return nil, fmt.Errorf("certificate: PDF object has no stream")
	}
	start := i + len("stream")
	// The keyword is followed by CRLF or LF; a bare CR is legal too.
	switch {
	case bytes.HasPrefix(obj[start:], []byte("\r\n")):
		start += 2
	case bytes.HasPrefix(obj[start:], []byte("\n")):
		start++
	case bytes.HasPrefix(obj[start:], []byte("\r")):
		start++
	}
	end := bytes.Index(obj[start:], []byte("endstream"))
	if end < 0 {
		return nil, fmt.Errorf("certificate: PDF stream is not terminated")
	}
	return obj[start : start+end], nil
}

// pageContentObjects lists the /Contents object number of every page, in the
// order the page tree names them.
//
// The tree is reached from the trailer's catalog: /Root -> /Pages -> /Kids. A
// page that draws an array of content streams is refused rather than guessed at;
// this writer never produces one.
func (d *pdfDoc) pageContentObjects() ([]string, error) {
	catalog, err := d.object(d.root)
	if err != nil {
		return nil, err
	}
	pagesRef := rePagesRef.FindSubmatch(catalog)
	if pagesRef == nil {
		return nil, fmt.Errorf("certificate: PDF catalog names no page tree")
	}
	pagesNum, err := strconv.Atoi(string(pagesRef[1]))
	if err != nil {
		return nil, fmt.Errorf("certificate: PDF catalog /Pages is not an object number")
	}
	pages, err := d.object(pagesNum)
	if err != nil {
		return nil, err
	}
	kids := reKidsArray.FindSubmatch(pages)
	if kids == nil {
		return nil, fmt.Errorf("certificate: PDF page tree has no /Kids array")
	}

	var out []string
	for _, ref := range reObjRef.FindAllSubmatch(kids[1], -1) {
		pageNum, err := strconv.Atoi(string(ref[1]))
		if err != nil {
			return nil, fmt.Errorf("certificate: PDF page tree names a bad object number")
		}
		page, err := d.object(pageNum)
		if err != nil {
			return nil, err
		}
		if reContentsArr.Match(page) {
			return nil, fmt.Errorf("certificate: PDF page %d draws an array of content streams; this verifier reads single-stream pages only", pageNum)
		}
		m := reContentsRef.FindSubmatch(page)
		if m == nil {
			return nil, fmt.Errorf("certificate: PDF page %d names no /Contents", pageNum)
		}
		out = append(out, string(m[1]))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("certificate: PDF page tree names no pages")
	}
	return out, nil
}

// pdfContentLines extracts the text operands of every "Tj" operator in a
// content stream, decoding PDF literal-string escapes back to bytes.
//
// Only literals are handled: this writer emits "(text) Tj" and nothing else, so
// a hex string here would mean the file was produced by another tool and the
// digest comparison should fail rather than be guessed at.
func pdfContentLines(stream []byte) [][]byte {
	var out [][]byte
	for i := 0; i < len(stream); i++ {
		if stream[i] != '(' {
			continue
		}
		var buf []byte
		j := i + 1
		for j < len(stream) {
			c := stream[j]
			if c == '\\' && j+1 < len(stream) {
				n := stream[j+1]
				if n >= '0' && n <= '7' {
					val, k := 0, 0
					for k < 3 && j+1+k < len(stream) && stream[j+1+k] >= '0' && stream[j+1+k] <= '7' {
						val = val*8 + int(stream[j+1+k]-'0')
						k++
					}
					buf = append(buf, byte(val))
					j += 1 + k
					continue
				}
				switch n {
				case 'n':
					buf = append(buf, '\n')
				case 'r':
					buf = append(buf, '\r')
				case 't':
					buf = append(buf, '\t')
				case 'b':
					buf = append(buf, '\b')
				case 'f':
					buf = append(buf, '\f')
				default:
					buf = append(buf, n)
				}
				j += 2
				continue
			}
			if c == ')' {
				break
			}
			buf = append(buf, c)
			j++
		}
		if j < len(stream) && stream[j] == ')' && bytes.HasPrefix(stream[j+1:], []byte(" Tj")) {
			out = append(out, buf)
		}
		i = j
	}
	return out
}
