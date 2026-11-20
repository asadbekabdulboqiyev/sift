package main

// cmdCertificate implements `Sift certificate` — issue and verify
// Ed25519-signed security assessment certificates (ss-cert/v1 and v2, pure English).
//
// The command is zero-flag by design: point it at a file and it works out what
// the file is.
//
//	Sift certificate                        # short guide
//	Sift certificate pentest.json           # issue cert.json/.html/.pdf
//	Sift certificate cert.json              # verify it
//	Sift certificate cert.pdf               # verify a printed copy
//	Sift certificate --explain              # plain-English explanation
//
// The old flag forms still work (`--from`, `--verify --cert`); nothing that
// scripts already use was removed.

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/asadbekabdulboqiyev/sift/internal/attest"
	"github.com/asadbekabdulboqiyev/sift/internal/authz"
	"github.com/asadbekabdulboqiyev/sift/internal/certificate"
)

// defaultCertificateKeyPath is the persistent sealing identity. It lives with
// the rest of the local state so every certificate this machine issues carries
// the same signer and re-sealing does not require hunting for a key file.
func defaultCertificateKeyPath() string {
	return filepath.Join(authz.ConfigHome(), "certificate-key.pem")
}

func cmdCertificate() {
	var (
		from      string
		out       string
		format    string
		keyPath   string
		issuer    string
		verify    bool
		certPath  string
		explain   bool
		quiet     bool
		trustPath string
		require   bool
		asJSON    bool
	)

	fs := flag.NewFlagSet("certificate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	fs.StringVar(&from, "from", "", "pentest JSON report to certify (optional: a positional file is auto-detected)")
	fs.StringVar(&out, "out", "cert", "output certificate stem (json/html/pdf derived from it)")
	fs.StringVar(&format, "format", "all", "output format: json, html, pdf, all")
	fs.StringVar(&keyPath, "key", "", "Ed25519 keypair PEM that seals the certificate (default: persistent key in the Sift home)")
	fs.StringVar(&issuer, "issuer", "Sift assessment", "certificate issuer name")
	fs.BoolVar(&verify, "verify", false, "force verify mode")
	fs.StringVar(&certPath, "cert", "", "certificate file to verify")
	fs.BoolVar(&explain, "explain", false, "explain what the certificate is and how to get/check one")
	fs.BoolVar(&quiet, "quiet", false, "only print the result, not the next steps")
	fs.StringVar(&trustPath, "trust-store", "", "issuer trust store (JSON file or key directory); default: $SIFT_HOME/trust.json when it exists")
	fs.BoolVar(&require, "require-anchor", false, "fail unless the signer is in the trust store")
	fs.BoolVar(&asJSON, "json", false, "emit a machine-readable verification report")

	if err := fs.Parse(os.Args[2:]); err != nil {
		if err == flag.ErrHelp {
			printCertificateGuide(false)
			return
		}
		fatal(fmt.Errorf("certificate: %w", err))
	}

	positional := fs.Arg(0)

	// Go's flag package stops at the first non-flag argument, so the natural
	// `Sift certificate cert.json --require-anchor` would leave the trailing
	// flags unparsed. Re-parse them so flags work on either side of the file
	// name; the positional captured above is already safe.
	if trailing := fs.Args(); len(trailing) > 1 && strings.HasPrefix(trailing[1], "-") {
		if err := fs.Parse(trailing[1:]); err != nil {
			if err == flag.ErrHelp {
				printCertificateGuide(false)
				return
			}
			fatal(fmt.Errorf("certificate: %w", err))
		}
	}

	// A verify run that names an output asks for a fresh printable copy. This is
	// how an old PDF — printed before PDFs carried their seal — is replaced from
	// the certificate that still verifies.
	formatSet, outSet := false, false
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "format":
			formatSet = true
		case "out":
			outSet = true
		}
	})
	reissue := ""
	if !asJSON && (outSet || (formatSet && (format == "pdf" || format == "all"))) {
		reissue = out
	}

	if explain || (positional == "" && from == "" && certPath == "" && !verify && !hasCertFlags(fs)) {
		printCertificateGuide(explain)
		return
	}

	// Normalise the three ways to name a file into one path + intent.
	if certPath == "" && verify {
		certPath = positional
	}
	if from == "" && !verify && certPath == "" {
		from = positional
	}

	// A bare file argument decides issue vs verify by its contents.
	if from != "" && certPath == "" {
		kind, err := detectCertificateInput(from)
		if err != nil {
			fatal(err)
		}
		if kind == inputCertificate || kind == inputCertificatePDF {
			certPath = from
			from = ""
		}
	}

	if certPath != "" {
		verifyCertificateFile(certPath, quiet, trustPath, require, asJSON, reissue)
		return
	}

	if from == "" {
		fatal(fmt.Errorf("no input file. Try:\n  Sift certificate pentest.json    # issue\n  Sift certificate cert.json       # verify\n  Sift certificate --explain      # what is this?"))
	}

	issueCertificate(from, out, format, keyPath, issuer, quiet)
}

// hasCertFlags reports whether the operator passed any flag at all, so a bare
// `certificate --format html` still reaches the "no input" error instead of the
// guide.
func hasCertFlags(fs *flag.FlagSet) bool {
	found := false
	fs.Visit(func(*flag.Flag) { found = true })
	return found
}

type certificateInput int

const (
	inputUnknown certificateInput = iota
	inputCertificate
	inputCertificatePDF
	inputPentestReport
)

// detectCertificateInput sniffs a JSON file. A certificate carries "assessment"
// and "signature"; a pentest report carries "target" and a risk/grade summary.
func detectCertificateInput(path string) (certificateInput, error) {
	raw, err := os.ReadFile(filepath.Clean(path)) // #nosec G304 -- path is an operator-selected input file
	if err != nil {
		if os.IsNotExist(err) {
			return inputUnknown, fmt.Errorf("file not found: %s", path)
		}
		return inputUnknown, fmt.Errorf("read %s: %w", path, err)
	}
	// A printed certificate is a PDF. It is detected before the JSON probe so
	// `Sift certificate cert.pdf` lands in verify mode, not in "not JSON".
	if bytes.HasPrefix(raw, []byte("%PDF-")) {
		return inputCertificatePDF, nil
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return inputUnknown, fmt.Errorf("%s is not JSON — expected a pentest report or a certificate: %w", path, err)
	}
	if _, ok := probe["assessment"]; ok {
		if _, ok := probe["signature"]; ok {
			return inputCertificate, nil
		}
	}
	if _, ok := probe["target"]; ok {
		return inputPentestReport, nil
	}
	// A load-run attestation bundle carries "format": "vpmp/v1". It is not a
	// certificate, so point the operator at the verifier that understands it
	// instead of reporting a flat "not JSON we know".
	if format, ok := probe["format"]; ok && strings.Contains(string(format), attest.FormatID) {
		return inputUnknown, fmt.Errorf("%s is an attestation bundle (format %q), not a certificate.\nVerify it with:\n  Sift verify --bundle %s", path, attest.FormatID, path)
	}
	return inputUnknown, fmt.Errorf("%s is JSON but not a file we can use — expected a pentest report (needs \"target\"), a certificate (needs \"assessment\"+\"signature\"), or an attestation bundle (needs \"format\":%q)", path, attest.FormatID)
}

func verifyCertificateFile(path string, quiet bool, trustPath string, requireAnchor bool, asJSON bool, reissue string) {
	data, err := os.ReadFile(filepath.Clean(path)) // #nosec G304 -- path is an operator-selected certificate file
	if err != nil {
		fatal(fmt.Errorf("read certificate: %w", err))
	}

	store, err := loadVerifyTrustStore(trustPath, requireAnchor)
	if err != nil {
		fatal(err)
	}

	// A printed certificate verifies from the PDF alone: the signed JSON and a
	// digest of the visible text are embedded in the file. Detect it here as
	// well as in detectCertificateInput so `--cert` and `--verify` reach it too.
	if bytes.HasPrefix(data, []byte("%PDF-")) {
		// A PDF already is the printable copy; re-issuing it would only
		// re-render the same pages.
		verifyCertificatePDFFile(path, data, store, requireAnchor, quiet, asJSON)
		return
	}

	c, check, err := certificate.VerifyBytesWithTrust(data, store, requireAnchor)
	if err != nil {
		if asJSON {
			if emitErr := emitCertificateVerifyJSON(path, nil, check, err); emitErr != nil {
				fmt.Fprintln(os.Stderr, emitErr)
			}
			exitProcess(1)
		}
		fmt.Fprintln(os.Stderr, "INVALID —", err)
		exitProcess(1)
	}

	if asJSON {
		if err := emitCertificateVerifyJSON(path, c, check, nil); err != nil {
			fatal(err)
		}
		return
	}

	a := c.Assessment
	total := a.Counts.Critical + a.Counts.High + a.Counts.Medium + a.Counts.Low + a.Counts.Info
	fmt.Printf("VALID — %s Ed25519 certificate\n", c.Version)
	fmt.Printf("  target:    %s\n", a.Target)
	fmt.Printf("  grade:     %s\n", a.Grade)
	fmt.Printf("  verdict:   %s\n", a.Verdict)
	fmt.Printf("  risk:      %d/100\n", a.RiskScore)
	fmt.Printf("  findings:  %d (c %d h %d m %d l %d i %d)\n",
		total, a.Counts.Critical, a.Counts.High, a.Counts.Medium, a.Counts.Low, a.Counts.Info)
	fmt.Printf("  signer:    %s...\n", firstN(c.PublicKey, 16))
	fmt.Printf("  issuer:    %s\n", certificateIssuerLine(check))
	fmt.Printf("  signed at: %s\n", displayTime(c.SignedAt))
	if reissue != "" {
		pdfPath := strings.TrimSuffix(reissue, filepath.Ext(reissue)) + ".pdf"
		if err := atomicWriteFile(pdfPath, renderPDF(c.Assessment, c), 0o644); err != nil { // #nosec G306 G703 -- out path is the caller's own CLI output target
			fatal(fmt.Errorf("write %s: %w", pdfPath, err))
		}
		fmt.Printf("  reprinted: %s (sealed PDF, verifies on its own)\n", pdfPath)
	}

	if quiet {
		return
	}
	fmt.Println()
	fmt.Println("The seal covers the assessment above and the rendered document body.")
	fmt.Println("Editing either one makes this check fail; verification needs no key and no network.")
	if c.HTML != "" {
		fmt.Println("The printable copy is inside the JSON (\"html\" field).")
	}
	if !check.Trusted() {
		fmt.Println()
		fmt.Println("Who signed this is not established: the certificate carries its own signer key.")
		fmt.Println("To check identity, pin the issuer once and verify again:")
		fmt.Println("  Sift trust add --key <issuer.pub> --label \"<name>\"")
		fmt.Printf("  Sift certificate %s --require-anchor\n", path)
	}
}

// verifyCertificatePDFFile checks a printed certificate: the embedded signed
// JSON must verify, and the text drawn on the pages must hash to the value in
// the seal. The second check is what makes the paper copy answerable — without
// it a valid JSON could be pasted into a PDF that says something else.
func verifyCertificatePDFFile(path string, data []byte, store *attest.TrustStore, requireAnchor, quiet, asJSON bool) {
	res, err := certificate.VerifyPDF(data, store, requireAnchor)
	if err != nil {
		if asJSON {
			if emitErr := emitCertificatePDFVerifyJSON(path, res, err); emitErr != nil {
				fmt.Fprintln(os.Stderr, emitErr)
			}
			exitProcess(1)
		}
		fmt.Fprintln(os.Stderr, "INVALID —", err)
		exitProcess(1)
	}

	if asJSON {
		if err := emitCertificatePDFVerifyJSON(path, res, nil); err != nil {
			fatal(err)
		}
		return
	}

	c := res.Certificate
	a := c.Assessment
	total := a.Counts.Critical + a.Counts.High + a.Counts.Medium + a.Counts.Low + a.Counts.Info
	fmt.Printf("VALID — %s Ed25519 certificate (printed copy)\n", c.Version)
	fmt.Printf("  target:    %s\n", a.Target)
	fmt.Printf("  grade:     %s\n", a.Grade)
	fmt.Printf("  verdict:   %s\n", a.Verdict)
	fmt.Printf("  risk:      %d/100\n", a.RiskScore)
	fmt.Printf("  findings:  %d (c %d h %d m %d l %d i %d)\n",
		total, a.Counts.Critical, a.Counts.High, a.Counts.Medium, a.Counts.Low, a.Counts.Info)
	fmt.Printf("  signer:    %s...\n", firstN(c.PublicKey, 16))
	fmt.Printf("  issuer:    %s\n", certificateIssuerLine(res.Check))
	fmt.Printf("  signed at: %s\n", displayTime(c.SignedAt))
	fmt.Printf("  page text: the certificate's own rendering (%s...)\n", firstN(res.RenderedSHA256, 16))
	fmt.Printf("  page objects: identical to the document this certificate renders (%d objects)\n", res.ObjectsChecked)
	if quiet {
		return
	}
	fmt.Println()
	fmt.Println("This PDF carries the signed certificate, and its pages are compared with")
	fmt.Println("the pages that certificate renders to — object by object, so a drawing, a")
	fmt.Println("hex string or a swapped font is caught along with the words. Editing the")
	fmt.Println("file, or rebuilding it around a real certificate, fails: the page must be")
	fmt.Println("the sealed document, not merely agree with a digest stored beside it.")
	fmt.Println("Verification needs no key, no network and no side file.")
	if !res.Check.Trusted() {
		fmt.Println()
		fmt.Println("Who signed this is not established: the certificate carries its own signer key.")
		fmt.Println("To check identity, pin the issuer once and verify again:")
		fmt.Println("  Sift trust add --key <issuer.pub> --label \"<name>\"")
		fmt.Printf("  Sift certificate %s --require-anchor\n", path)
	}
}

// certificateIssuerLine renders the identity half of a certificate report.
func certificateIssuerLine(check certificate.TrustCheck) string {
	fp := check.Fingerprint()
	switch check.Status {
	case attest.IssuerPinned:
		if check.Label != "" {
			return fmt.Sprintf("%s (pinned) %s", check.Label, fp)
		}
		return fmt.Sprintf("%s (pinned)", fp)
	case attest.IssuerUnpinned:
		return fmt.Sprintf("%s (unpinned: no trust store configured)", fp)
	case attest.IssuerUntrusted:
		return fmt.Sprintf("%s (UNTRUSTED: not in the trust store)", fp)
	default:
		return fp
	}
}

// certificateVerifyJSON is the machine-readable certificate report. The
// identity fields are separate from `valid` on purpose: a file can be internally
// consistent (valid) while its signer is not established (issuer_trust).
type certificateVerifyJSON struct {
	Valid             bool           `json:"valid"`
	Format            string         `json:"format"`
	Certificate       string         `json:"certificate"`
	CertificateID     string         `json:"certificate_id,omitempty"`
	Target            string         `json:"target,omitempty"`
	Grade             string         `json:"grade,omitempty"`
	Verdict           string         `json:"verdict,omitempty"`
	RiskScore         int            `json:"risk_score,omitempty"`
	IssuerName        string         `json:"issuer_name,omitempty"`
	SignerKey         string         `json:"signer_key,omitempty"`
	SignerFingerprint string         `json:"signer_fingerprint,omitempty"`
	IssuerTrust       string         `json:"issuer_trust,omitempty"`
	IssuerLabel       string         `json:"issuer_label,omitempty"`
	SignedAt          string         `json:"signed_at,omitempty"`
	PDF               *pdfVerifyJSON `json:"pdf,omitempty"`
	Error             string         `json:"error,omitempty"`
}

// pdfVerifyJSON reports the page-text binding for a printed certificate.
type pdfVerifyJSON struct {
	RenderedSHA256 string `json:"rendered_sha256,omitempty"`
	SealSHA256     string `json:"seal_sha256,omitempty"`
	// ExpectedSHA256 is what the embedded certificate renders to, computed by
	// the verifier. A page can match its seal and still differ from this: that
	// is a rebuilt file, not an intact one.
	ExpectedSHA256              string `json:"expected_sha256,omitempty"`
	RenderedMatches             bool   `json:"rendered_matches"`
	RenderingMatchesCertificate bool   `json:"rendering_matches_certificate"`
	// ObjectsMatchesCertificate is the stronger half: every object a reader can
	// reach is byte-identical to the object the certificate renders to. The
	// text digest cannot see a drawing operator, a hex string or a swapped
	// font; this can, because it compares the document, not the words.
	ObjectsMatchesCertificate bool `json:"objects_match_certificate"`
	// ObjectsChecked is how many objects were compared, so a reader of the JSON
	// can tell a one-page pass from a pass over a long annex.
	ObjectsChecked int `json:"objects_checked,omitempty"`
}

func emitCertificateVerifyJSON(path string, c *certificate.Certificate, check certificate.TrustCheck, verifyErr error) error {
	return writeCertificateVerifyJSON(certificateVerifyReport(path, c, check, verifyErr))
}

// emitCertificatePDFVerifyJSON is the same report for a printed certificate,
// with the page-text binding attached. `valid` stays the verdict on the whole
// file: a page whose text no longer matches the seal is not valid, even though
// its embedded certificate is.
func emitCertificatePDFVerifyJSON(path string, res *certificate.PDFVerifyResult, verifyErr error) error {
	var c *certificate.Certificate
	check := certificate.TrustCheck{}
	if res != nil {
		c = res.Certificate
		check = res.Check
	}
	out := certificateVerifyReport(path, c, check, verifyErr)
	out.PDF = &pdfVerifyJSON{}
	if res != nil {
		out.PDF.RenderedSHA256 = res.RenderedSHA256
		out.PDF.SealSHA256 = res.SealRenderedSHA256
		out.PDF.ExpectedSHA256 = res.ExpectedRenderedSHA256
		out.PDF.RenderedMatches = res.RenderedMatch
		out.PDF.RenderingMatchesCertificate = res.RenderingMatchesCertificate
		out.PDF.ObjectsMatchesCertificate = res.ObjectsMatchCertificate
		out.PDF.ObjectsChecked = res.ObjectsChecked
	}
	return writeCertificateVerifyJSON(out)
}

// certificateVerifyReport fills the fields shared by the JSON and PDF reports.
func certificateVerifyReport(path string, c *certificate.Certificate, check certificate.TrustCheck, verifyErr error) certificateVerifyJSON {
	out := certificateVerifyJSON{
		Valid:             verifyErr == nil,
		Format:            certificate.Version,
		Certificate:       path,
		SignerKey:         check.Key,
		SignerFingerprint: check.Fingerprint(),
		IssuerTrust:       string(check.Status),
		IssuerLabel:       check.Label,
	}
	if c != nil {
		out.CertificateID = c.CertificateID
		out.Target = c.Assessment.Target
		out.Grade = c.Assessment.Grade
		out.Verdict = c.Assessment.Verdict
		out.RiskScore = c.Assessment.RiskScore
		out.IssuerName = c.Assessment.Issuer
		out.SignedAt = c.SignedAt
	}
	if verifyErr != nil {
		out.Error = verifyErr.Error()
	}
	return out
}

func writeCertificateVerifyJSON(out certificateVerifyJSON) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func issueCertificate(from, out, format, keyPath, issuer string, quiet bool) {
	raw, err := os.ReadFile(filepath.Clean(from)) // #nosec G304 -- path is an operator-selected pentest report file
	if err != nil {
		fatal(fmt.Errorf("read report: %w", err))
	}
	report, err := certificate.ParsePentestReport(raw)
	if err != nil {
		fatal(err)
	}

	if keyPath == "" {
		keyPath = defaultCertificateKeyPath()
	}
	kp, created, err := attest.LoadOrCreateKeypairPEM(keyPath)
	if err != nil {
		fatal(fmt.Errorf("load sealing key: %w", err))
	}
	if created && !quiet {
		fmt.Fprintf(os.Stderr, "sealing key created: %s (mode 0600)\n", keyPath)
	}

	a := certificate.BuildAssessment(report, issuer, binaryVersion())
	cert, err := certificate.Issue(kp, a, "", "")
	if err != nil {
		fatal(fmt.Errorf("sign certificate: %w", err))
	}

	stem := strings.TrimSuffix(out, filepath.Ext(out))
	written := []string{}
	write := func(ext string, data []byte) {
		path := stem + ext
		if err := atomicWriteFile(path, data, 0o644); err != nil { // #nosec G306 G703 -- out path is the caller's own CLI output target
			fatal(fmt.Errorf("write %s: %w", path, err))
		}
		written = append(written, path)
	}

	jdata, err := json.MarshalIndent(cert, "", "  ")
	if err != nil {
		fatal(fmt.Errorf("marshal json: %w", err))
	}

	switch strings.ToLower(format) {
	case "json":
		write(".json", jdata)
	case "html":
		write(".html", []byte(certificate.HTML(cert)))
	case "pdf":
		write(".pdf", renderPDF(cert.Assessment, cert))
	case "all":
		write(".json", jdata)
		write(".html", []byte(certificate.HTML(cert)))
		write(".pdf", renderPDF(a, cert))
	default:
		fatal(fmt.Errorf("unknown --format %q (use json, html, pdf, all)", format))
	}

	if quiet {
		fmt.Fprintln(os.Stdout, strings.Join(written, " "))
		return
	}

	total := a.Counts.Critical + a.Counts.High + a.Counts.Medium + a.Counts.Low + a.Counts.Info
	fmt.Println("Certificate issued")
	fmt.Println()
	fmt.Printf("  target     %s\n", a.Target)
	fmt.Printf("  result     grade %s · risk %d/100 · %s\n", a.Grade, a.RiskScore, a.Verdict)
	fmt.Printf("  findings   %d (c %d h %d m %d l %d i %d)\n",
		total, a.Counts.Critical, a.Counts.High, a.Counts.Medium, a.Counts.Low, a.Counts.Info)
	fmt.Printf("  signer     %s…\n", firstN(cert.PublicKey, 16))
	fmt.Printf("  key file   %s\n", keyPath)
	fmt.Println()
	fmt.Println("  files")
	for _, p := range written {
		fmt.Printf("    %s\n", p)
	}
	fmt.Println()
	fmt.Println("Verify it (offline, no key needed):")
	if hasFile(written, stem+".json") {
		fmt.Printf("  Sift certificate %s.json\n", stem)
	} else {
		fmt.Printf("  Sift certificate <certificate>.json\n")
	}
	fmt.Println()
	fmt.Println("Share the .html copy for a printable view; the .json is the proof.")
	fmt.Println("Tip: the dashboard's Certificate page verifies a dropped file and issues from a dropped report.")
}

func hasFile(paths []string, want string) bool {
	for _, p := range paths {
		if p == want {
			return true
		}
	}
	return false
}

func firstN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func printCertificateGuide(explain bool) {
	fmt.Println(`Sift certificate — signed proof of a security assessment

  ISSUE a certificate from a pentest report:
    Sift certificate pentest.json

  VERIFY a certificate someone sent you:
    Sift certificate cert.json
    Sift certificate cert.pdf

  Re-print a PDF from a certificate:
    Sift certificate cert.json --format pdf --out cert

  Both forms are the same command: it looks at the file and knows which one
  you meant. No flags, no key hunting, no network. A PDF verifies on its own:
  it carries the signed certificate and a digest of the words on its pages, so
  an edited printout fails even when the JSON inside it is untouched.

  First issue creates a persistent sealing key at:
    ` + defaultCertificateKeyPath() + `
  Back that file up if you want to re-seal certificates as the same signer.`)

	if !explain {
		fmt.Println(`
  More:
    Sift certificate --explain     what the certificate proves
    Sift trust add --key issuer.pub --label "School #12"
    Sift certificate cert.json --require-anchor
    Sift pentest --target URL --authorized TICKET --format json`)
		return
	}

	fmt.Println(`
WHAT IT IS
  A certificate is one JSON file containing:
    · the assessment summary (target, grade, risk, findings, coverage),
    · the full printable document,
    · an Ed25519 signature over both.
  Anyone can check it with this binary. They need no key, no network and no
  access to your machine. If a single byte of the assessment or the document
  changes, verification fails.

WHAT IT PROVES — AND WHAT IT DOES NOT
  It proves: this report was sealed by this signing key, and the document you
  are reading is the one that was sealed.
  It does not prove: the target is secure, the scan was exhaustive, or the
  signer is a trusted authority. It is tamper-evident evidence, not a warranty.
  That is why every certificate states the coverage and marks untested
  categories as NOT TESTED instead of inventing a PASS.

WHO ISSUED IT — THE TRUST ANCHOR
  A certificate carries the key that signed it, so a passing check only proves
  the file is self-consistent: anyone can mint a keypair and seal any numbers.
  To establish identity, pin the issuer's public key once, out of band:

    Sift trust add --key school.pub --label "School #12"   # enrol once
    Sift certificate cert.json --require-anchor            # enforce it

  The pinned set lives at ` + defaultTrustStorePath() + ` and holds public keys
  only, so it is safe to review or commit. After that, a certificate from any
  other key is refused, and every report names the issuer it accepted.

  Precedence: --trust-store wins when given; otherwise the default store is used
  when it exists; --require-anchor turns "no store" into a failure.

HOW TO OBTAIN ONE
  1. Register the authorization the target owner gave you:
       Sift authorize add --pattern example.com --approver "Owner Name" --ticket TICKET-001
  2. Run the assessment:
       Sift pentest --target https://example.com --authorized TICKET-001 --format json
  3. Seal the report:
       Sift certificate pentest-example.com-....json
  4. Send cert.json (proof) and cert.html (readable copy).

HOW TO VERIFY ONE
  Command line:   Sift certificate cert.json
  Dashboard:      open the dashboard, Certificate page, drop cert.json
  Exit codes:     0 = VALID, 1 = INVALID (the reason is printed)

WHERE THE CODE LIVES
  internal/certificate — ss-cert/v1 sign/verify, document binding, HTML/PDF.
  The seal is excluded from the document hash by design, so printing or saving
  the HTML does not change what was signed.)`)
}

// renderPDF renders a printable certificate PDF.
//
// It must never panic on a nil certificate: callers pass nil when they only
// have an assessment to print, and a crash while writing the "readable copy" of
// a signed document is not an acceptable failure mode. Every envelope value is
// therefore read through a nil check, not dereferenced.
// renderPDF returns the printable copy of a certificate.
//
// It delegates to certificate.RenderPDF so the CLI, the dashboard and the
// verifier share one printer. Without a certificate there is nothing to seal;
// the PDF stays printable and verification says so instead of guessing.
func renderPDF(a certificate.Assessment, cert *certificate.Certificate) []byte {
	if cert != nil {
		out, err := certificate.RenderPDF(cert)
		if err != nil {
			fatal(fmt.Errorf("render pdf: %w", err))
		}
		return out
	}
	pdf := certificate.NewPDF()
	for _, line := range certificate.PDFLines(a, nil) {
		pdf.Text(line)
	}
	out, err := pdf.Bytes()
	if err != nil {
		fatal(fmt.Errorf("render pdf: %w", err))
	}
	return out
}

// binaryVersion is the build version stamped into issued certificates.
func binaryVersion() string { return buildVersion }

// displayTime formats an RFC3339 timestamp for human-readable CLI/PDF output
// without appending a redundant "UTC" suffix when the timezone is already present.
func displayTime(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || s == "0001-01-01T00:00:00Z" {
		return "-"
	}
	return s
}

func displayOrDash(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "-"
	}
	return s
}
