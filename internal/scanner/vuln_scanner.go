package scanner

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	proreport "github.com/asadbekabdulboqiyev/sift/internal/report"
)

// VulnScanner performs comprehensive vulnerability scanning
type VulnScanner struct {
	Target  string
	Client  *http.Client
	Results *VulnReport
	mu      sync.Mutex

	// ids is owned by this scanner instance. A scan run must never consume or
	// observe another run's ID sequence, even when runs execute concurrently.
	ids vulnIDGenerator
}

// vulnIDGenerator hands out sequential finding IDs for one scan run. Every
// scanner instance owns one, so parallel runs cannot perturb each other. The
// mutex keeps a single run safe when its checks emit findings from goroutines.
type vulnIDGenerator struct {
	mu    sync.Mutex
	count int
}

func (g *vulnIDGenerator) next(prefix string) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.count++
	return fmt.Sprintf("%s-%03d", prefix, g.count)
}

func (g *vulnIDGenerator) reset() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.count = 0
}

// nextVulnID is the run-scoped ID source. New code must use this method, never
// the package-level legacy helper below.
func (vs *VulnScanner) nextVulnID(prefix string) string {
	return vs.ids.next(prefix)
}

// VulnReport contains all scan results
type VulnReport struct {
	Target   string        `json:"target"`
	ScanTime time.Time     `json:"scan_time"`
	Duration time.Duration `json:"duration"`

	Critical []Vulnerability `json:"critical"`
	High     []Vulnerability `json:"high"`
	Medium   []Vulnerability `json:"medium"`
	Low      []Vulnerability `json:"low"`
	Info     []Vulnerability `json:"info"`

	OWASP map[string][]Vulnerability `json:"owasp"`

	RiskScore int    `json:"risk_score"`
	Grade     string `json:"grade"`

	TotalChecks int64 `json:"total_checks"`
	TotalFound  int64 `json:"total_found"`
	URLsChecked int64 `json:"urls_checked"`
}

// Vulnerability represents a single finding
type Vulnerability struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Category    string   `json:"category"`
	CVSS        float64  `json:"cvss"`
	CWE         string   `json:"cwe"`
	URL         string   `json:"url"`
	Parameter   string   `json:"parameter"`
	Evidence    string   `json:"evidence"`
	Impact      string   `json:"impact"`
	Remediation string   `json:"remediation"`
	References  []string `json:"references"`
	PoC         string   `json:"poc"`
}

// Legacy process-wide ID source. It is kept only for backward compatibility
// with existing tests and any external callers; scanner runs must use the
// instance-bound nextVulnID method instead. Do not add new call sites here.
var (
	vulnCounter int
	counterMu   sync.Mutex
)

func nextVulnID(prefix string) string {
	counterMu.Lock()
	defer counterMu.Unlock()
	vulnCounter++
	return fmt.Sprintf("%s-%03d", prefix, vulnCounter)
}

func resetVulnCounter() {
	counterMu.Lock()
	defer counterMu.Unlock()
	vulnCounter = 0
}

// NewVulnScanner creates a new vulnerability scanner
func NewVulnScanner(target string) *VulnScanner {
	return &VulnScanner{
		Target: target,
		Client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		Results: &VulnReport{
			OWASP: make(map[string][]Vulnerability),
		},
	}
}

// Scan runs all vulnerability checks and returns the report
func (vs *VulnScanner) Scan() *VulnReport {
	start := time.Now()
	vs.ids.reset()

	report := &VulnReport{
		Target:   vs.Target,
		ScanTime: start,
		OWASP:    make(map[string][]Vulnerability),
	}

	vs.Results = report

	var wg sync.WaitGroup
	checks := []func(){
		vs.scanSQLInjection,
		vs.scanXSS,
		vs.scanDirectoryTraversal,
		vs.scanOpenRedirect,
		vs.scanSecurityHeaders,
		vs.scanInfoDisclosure,
		vs.scanDefaultCredentials,
		vs.scanAPISecurity,
		vs.scanCookies,
		vs.scanCORS,
	}

	for _, check := range checks {
		wg.Add(1)
		fn := check
		go func() {
			defer wg.Done()
			fn()
		}()
	}
	wg.Wait()

	vs.compileReport(report)
	report.Duration = time.Since(start)
	return report
}

// addFinding is thread-safe and appends a vulnerability to the report
func (vs *VulnScanner) addFinding(v Vulnerability) {
	vs.mu.Lock()
	defer vs.mu.Unlock()

	report := vs.Results
	if report == nil {
		return
	}

	switch v.Severity {
	case "critical":
		report.Critical = append(report.Critical, v)
	case "high":
		report.High = append(report.High, v)
	case "medium":
		report.Medium = append(report.Medium, v)
	case "low":
		report.Low = append(report.Low, v)
	default:
		report.Info = append(report.Info, v)
	}

	if v.Category != "" {
		report.OWASP[v.Category] = append(report.OWASP[v.Category], v)
	}
	atomic.AddInt64(&report.TotalFound, 1)
}

// doRequest sends an HTTP request and returns the response
func (vs *VulnScanner) doRequest(method, url string, body io.Reader, headers http.Header) (*http.Response, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Sift-vulnscanner/1.0")
	if headers != nil {
		for k, vals := range headers {
			for _, v := range vals {
				req.Header.Set(k, v)
			}
		}
	}
	return vs.Client.Do(req)
}

// get performs a GET request
func (vs *VulnScanner) get(targetURL string) (*http.Response, error) {
	return vs.doRequest("GET", targetURL, nil, nil)
}

// postForm performs a POST with form data
func (vs *VulnScanner) postForm(targetURL string, data url.Values, headers http.Header) (*http.Response, error) {
	if headers == nil {
		headers = http.Header{}
	}
	if headers.Get("Content-Type") == "" {
		headers.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	return vs.doRequest("POST", targetURL, bytes.NewBufferString(data.Encode()), headers)
}

// normalizeURL ensures the target has a scheme
func normalizeURL(target string) string {
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		return "http://" + target
	}
	return target
}

// ---------------------------------------------------------------------------
// Report Compilation
// ---------------------------------------------------------------------------

func (vs *VulnScanner) compileReport(report *VulnReport) {
	// Calculate risk score from findings; a preset RiskScore with no findings
	// is honored so callers can re-derive only the grade for a given score.
	totalFindings := len(report.Critical) + len(report.High) + len(report.Medium) +
		len(report.Low) + len(report.Info)

	score := 100
	switch {
	case totalFindings > 0:
		score -= len(report.Critical) * 20
		score -= len(report.High) * 12
		score -= len(report.Medium) * 5
		score -= len(report.Low) * 2
		score -= len(report.Info) * 1
	case report.RiskScore > 0:
		score = report.RiskScore
	}

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	report.RiskScore = score

	// Grade — the shared ladder is the only definition of A..F in this tool.
	// The old local switch skipped C+/C and gave 59 an F instead of a D.
	report.Grade = proreport.GradeForScore(score)

	// Sort each severity bucket
	sortVulns(report.Critical)
	sortVulns(report.High)
	sortVulns(report.Medium)
	sortVulns(report.Low)
	sortVulns(report.Info)

	// Sort OWASP categories
	for cat := range report.OWASP {
		sortVulns(report.OWASP[cat])
	}
}

func sortVulns(vulns []Vulnerability) {
	sort.Slice(vulns, func(i, j int) bool {
		return vulns[i].CVSS > vulns[j].CVSS
	})
}
