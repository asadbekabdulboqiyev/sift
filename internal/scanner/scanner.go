package scanner

import (
	"fmt"
	"syscall"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/scanner/auth"
	"github.com/asadbekabdulboqiyev/sift/internal/scanner/core"
	"github.com/asadbekabdulboqiyev/sift/internal/scanner/crawl"
	"github.com/asadbekabdulboqiyev/sift/internal/scanner/http"
	"github.com/asadbekabdulboqiyev/sift/internal/scanner/owasp"
	"github.com/asadbekabdulboqiyev/sift/internal/scanner/security"
	"github.com/asadbekabdulboqiyev/sift/internal/scanner/tls"
	"github.com/asadbekabdulboqiyev/sift/internal/scanner/waf"
	"github.com/asadbekabdulboqiyev/sift/internal/shared"
)

// ScanResult is the top-level output of a complete scan (re-exported from core).
type ScanResult = core.ScanResult

// Vuln is a single finding from a scan (re-exported from core).
type Vuln = core.Vuln

// TLSInfo contains the results of a TLS scan (re-exported from core).
type TLSInfo = core.TLSInfo

// CertInfo describes a single TLS certificate (re-exported from core).
type CertInfo = core.CertInfo

// CipherInfo describes a single TLS cipher suite (re-exported from core).
type CipherInfo = core.CipherInfo

// WAFInfo contains the results of a WAF detection scan (re-exported from core).
type WAFInfo = core.WAFInfo

// HTTPInfo contains the results of an HTTP scan (re-exported from core).
type HTTPInfo = core.HTTPInfo

// CORSInfo describes CORS policy findings (re-exported from core).
type CORSInfo = core.CORSInfo

// SecurityInfo contains the results of a security-header scan (re-exported from core).
type SecurityInfo = core.SecurityInfo

// SecurityDetail describes a single security-header check result (re-exported from core).
type SecurityDetail = core.SecurityDetail

// BySeverity sorts Vuln by severity (re-exported from core).
type BySeverity = core.BySeverity

// AuthType selects how a scan session authenticates against a target
// (re-exported from the auth subpackage).
type AuthType = auth.AuthType

// AuthNone and the following values enumerate the supported authentication modes.
const (
	AuthNone    AuthType = 0 // no authentication
	AuthForm    AuthType = 1 // POST credentials to a login URL, keep session cookies
	AuthCookie  AuthType = 2 // inject a raw Cookie header on every request (static override)
	AuthHeader  AuthType = 3 // inject a static header (e.g. Authorization: Bearer x)
	AuthBrowser AuthType = 4 // headless Chromium: OAuth / deep login flows in browser
)

// AuthConfig configures an authenticated scanning session
// (re-exported from the auth subpackage).
type AuthConfig = auth.AuthConfig

// AuthSession is an authenticated scanning session
// (re-exported from the auth subpackage).
type AuthSession = auth.AuthSession

// NewAuthSession creates an authenticated scanning session from the given
// config. Returns nil when no auth type is configured. Never logs credentials.
func NewAuthSession(cfg AuthConfig, timeout time.Duration) (*AuthSession, error) {
	return auth.NewAuthSession(cfg, timeout)
}

// Endpoint / CrawlResult / CrawlOptions / Crawler are the attack-surface
// crawl primitives (re-exported from the crawl subpackage).
type (
	// Endpoint describes a discovered URL and its HTTP method.
	Endpoint = crawl.Endpoint
	// CrawlResult holds the endpoints and forms found during a crawl.
	CrawlResult = crawl.CrawlResult
	// CrawlOptions configures the behaviour of a Crawler.
	CrawlOptions = crawl.CrawlOptions
)

// Crawler spiders a target to discover endpoints and forms.
type Crawler = crawl.Crawler

// NewCrawler returns a new crawler for the given start URL and options.
func NewCrawler(startURL string, opts CrawlOptions) *Crawler {
	return crawl.NewCrawler(startURL, opts)
}

// OWASP re-exports (facade) — implementation lives in the owasp subpackage.
type (
	// OWASPChecker runs the OWASP Top 10 probes against a target.
	OWASPChecker = owasp.OWASPChecker
	// OWASPReport holds the outcome of an OWASP Top 10 assessment.
	OWASPReport = owasp.OWASPReport
	// OWASPCategory describes the status of one OWASP Top 10 category.
	OWASPCategory = owasp.OWASPCategory
)

// NewOWASPChecker returns a new OWASP Top 10 checker for the given target.
func NewOWASPChecker(target string) *OWASPChecker {
	return owasp.NewOWASPChecker(target)
}

// Scan performs a full scan on target:port (TLS, HTTP, WAF, Security).
func Scan(target string, port int) (*ScanResult, error) {
	return ScanWithControl(target, port, nil)
}

// ScanWithControl is Scan with a dial-time check threaded into every phase.
// The control sees the resolved peer address before connect, so a caller that
// approved a target by class can refuse a rebind to a more restricted address.
// Nil keeps the original behaviour exactly. It scans with the default TLS
// configuration (certificate verification ON).
func ScanWithControl(target string, port int, control func(network, address string, c syscall.RawConn) error) (*ScanResult, error) {
	return ScanWithControlWithOptions(target, port, control, tls.Default)
}

// ScanWithControlWithOptions is ScanWithControl with an explicit TLS
// configuration. It lets an authorized lab accept a self-signed certificate
// through tls.Options{TLSVerify: false} without mutating the package default,
// so one scan's opt-out cannot leak into another scan. All four phases still
// receive the same dial-time control.
func ScanWithControlWithOptions(target string, port int, control func(network, address string, c syscall.RawConn) error, opts tls.Options) (*ScanResult, error) {
	start := time.Now()

	result := &ScanResult{
		Target:      target,
		ScanTime:    start,
		InsecureTLS: !opts.TLSVerify,
	}

	// TLS scan
	tlsInfo, err := tls.ScanTLSWithOptions(target, port, control, opts)
	if err == nil {
		result.TLS = tlsInfo
	}

	// HTTP scan
	httpTarget := fmt.Sprintf("http://%s", target)
	httpInfo, err := http.ScanHTTPWithControl(httpTarget, control)
	if err == nil {
		result.HTTP = httpInfo
	}

	// WAF scan
	wafInfo, err := waf.ScanWAFWithControl(httpTarget, control)
	if err == nil {
		result.WAF = wafInfo
	}

	// Security scan
	secInfo, err := security.ScanSecurityWithControl(httpTarget, control)
	if err == nil {
		result.Security = secInfo
	}

	// Calculate risk score
	result.Vulns = calculateVulns(result)
	result.RiskScore = calculateRiskScore(result)

	result.Duration = time.Since(start)
	return result, nil
}

// ScanTLS re-exports tls.ScanTLS for backward compatibility.
func ScanTLS(host string, port int) (*TLSInfo, error) {
	return tls.ScanTLS(host, port)
}

// ScanTLSWithControl re-exports tls.ScanTLSWithControl so callers that already
// hold a Guard can keep the dial-time authorization decision on TLS sockets.
func ScanTLSWithControl(host string, port int, control func(network, address string, c syscall.RawConn) error) (*TLSInfo, error) {
	return tls.ScanTLSWithControl(host, port, control)
}

// ScanWAF re-exports waf.ScanWAF for backward compatibility.
func ScanWAF(target string) (*WAFInfo, error) {
	return waf.ScanWAF(target)
}

// ScanWAFWithControl re-exports waf.ScanWAFWithControl.
func ScanWAFWithControl(target string, control func(network, address string, c syscall.RawConn) error) (*WAFInfo, error) {
	return waf.ScanWAFWithControl(target, control)
}

// ScanHTTP re-exports http.ScanHTTP for backward compatibility.
func ScanHTTP(target string) (*HTTPInfo, error) {
	return http.ScanHTTP(target)
}

// ScanHTTPWithControl re-exports http.ScanHTTPWithControl with a dial-time
// check installed on every probe. Callers on a scan path must use this so a
// DNS answer that flips to metadata/private space is refused at connect time.
func ScanHTTPWithControl(target string, control func(network, address string, c syscall.RawConn) error) (*HTTPInfo, error) {
	return http.ScanHTTPWithControl(target, control)
}

// ScanSecurity re-exports security.ScanSecurity for backward compatibility.
func ScanSecurity(target string) (*SecurityInfo, error) {
	return security.ScanSecurity(target)
}

// ScanSecurityWithControl re-exports security.ScanSecurityWithControl.
func ScanSecurityWithControl(target string, control func(network, address string, c syscall.RawConn) error) (*SecurityInfo, error) {
	return security.ScanSecurityWithControl(target, control)
}

// calculateVulns delegates to the shared canonical rule so the scanner and the
// standalone sift-scan CLI report identical IDs for the same target.
func calculateVulns(r *ScanResult) []Vuln {
	return shared.CalculateVulns(r)
}

// calculateRiskScore delegates to the shared canonical rule.
func calculateRiskScore(r *ScanResult) int {
	return shared.CalculateRiskScore(r)
}
