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
	if !bytes.HasPrefix(data, []byte("%PDF-")) {
		return nil, fmt.Errorf("certificate: not a PDF file (no %%PDF- header)")
	}

	m := reSiftEvidence.FindSubmatch(data)
	if m == nil {
		return nil, fmt.Errorf("certificate: this PDF carries no seal, so it cannot be verified on its own — it was printed before PDFs embedded their certificate. Verify the .json certificate instead, or re-issue the PDF from it")
	}

	obj, err := pdfObject(data, string(m[1]))
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
	if !bytes.HasPrefix(data, []byte("%PDF-")) {
		return "", fmt.Errorf("certificate: not a PDF file (no %%PDF- header)")
	}

	contents, err := pdfPageContentObjects(data)
	if err != nil {
		return "", err
	}

	h := sha256.New()
	for _, num := range contents {
		obj, err := pdfObject(data, num)
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
}

// VerifyPDF checks a printed certificate without any side file: the embedded
// certificate must pass signature and document-hash verification, and the text
// drawn on the pages must hash to the value in the seal.
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
	if !res.RenderedMatch {
		return res, fmt.Errorf("certificate: the visible text of this PDF does not match the sealed rendering (page %s, seal %s) — the printed copy was altered after signing", shortDigest(got), shortDigest(res.SealRenderedSHA256))
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
)

// pdfObject returns the text of object n, from "n 0 obj" through "endobj".
func pdfObject(data []byte, num string) ([]byte, error) {
	needle := []byte("\n" + num + " 0 obj")
	i := bytes.Index(data, needle)
	if i < 0 {
		return nil, fmt.Errorf("certificate: PDF object %s is missing", num)
	}
	start := i + 1
	rest := data[start:]
	end := bytes.Index(rest, []byte("endobj"))
	if end < 0 {
		return nil, fmt.Errorf("certificate: PDF object %s is truncated", num)
	}
	return rest[:end], nil
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

// pdfPageContentObjects lists the /Contents object number of every page, in the
// order the page tree names them.
func pdfPageContentObjects(data []byte) ([]string, error) {
	kidsAt := bytes.Index(data, []byte("/Kids ["))
	if kidsAt < 0 {
		return nil, fmt.Errorf("certificate: PDF page tree has no /Kids array")
	}
	kids := data[kidsAt:]
	if end := bytes.IndexByte(kids, ']'); end >= 0 {
		kids = kids[:end]
	} else {
		return nil, fmt.Errorf("certificate: PDF page tree /Kids array is not closed")
	}

	var out []string
	for _, ref := range reObjRef.FindAllStringSubmatch(string(kids), -1) {
		obj, err := pdfObject(data, ref[1])
		if err != nil {
			return nil, err
		}
		m := reContentsRef.FindSubmatch(obj)
		if m == nil {
			return nil, fmt.Errorf("certificate: PDF page %s names no /Contents", ref[1])
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
