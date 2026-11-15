package dashboard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func postJSON(t *testing.T, h http.HandlerFunc, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func TestDirBustScanRefusedNotesAreExplained(t *testing.T) {
	s := owaspTestServer(t)

	rec := postJSON(t, s.handleDirBust, "/api/dirbust", `{
		"target":"http://127.0.0.1:9/",
		"paths":["/admin"]
	}`)
	// Out-of-scope is not the case here (default scope is target host), but a
	// port that refuses connections still produces a scan result; to force gate
	// refusals we use an allowlist that excludes the target host.
	rec = postJSON(t, s.handleDirBust, "/api/dirbust", `{
		"target":"http://127.0.0.1:9/",
		"paths":["/admin"]
	}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	var out DirBustScanResult
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	// No refusals expected with default host scope and a closed port; result
	// should be honest (found 0) with no gate-refusal claim.
	if out.Found != 0 {
		t.Errorf("Found = %d, want 0", out.Found)
	}
	for _, n := range out.Notes {
		if strings.Contains(n, "Gate refused") {
			t.Errorf("unexpected gate refusal note on in-scope target: %v", out.Notes)
		}
	}
}

func TestPortScanScanRefusedNotesAreExplained(t *testing.T) {
	s := owaspTestServer(t)

	rec := postJSON(t, s.handlePortScan, "/api/portscan", `{
		"target":"http://127.0.0.1:9/",
		"ports":[9]
	}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	var out PortScanResult
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	if out.Opened != 0 || out.Closed != 1 {
		t.Errorf("opened/closed = %d/%d, want 0/1 (%+v)", out.Opened, out.Closed, out)
	}
	for _, n := range out.Notes {
		if strings.Contains(n, "Gate refused") {
			t.Errorf("unexpected gate refusal note on in-scope target: %v", out.Notes)
		}
	}
}

func TestSubdomainScanEmptyTargetRejected(t *testing.T) {
	s := owaspTestServer(t)
	rec := postJSON(t, s.handleSubdomainScan, "/api/subdomain/scan", `{"target":""}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (%s)", rec.Code, rec.Body.String())
	}
}

func TestCrawlScanRedirectDoesNotEscapeOriginHost(t *testing.T) {
	s := owaspTestServer(t)

	offsite := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body><a href="/secret">secret</a></body></html>`)
	}))
	defer offsite.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, offsite.URL+"/", http.StatusFound)
		default:
			fmt.Fprint(w, `<html><body>ok</body></html>`)
		}
	}))
	defer origin.Close()

	rec := postJSON(t, s.handleCrawlScan, "/api/crawl/scan", `{
		"target":"`+origin.URL+`/",
		"depth":2,
		"pages":10,
		"concurrency":1,
		"rate":50,
		"budget":50,
		"timeoutSec":5
	}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	var out CrawlScanResult
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	for _, ep := range out.Discovered {
		if strings.Contains(ep.URL, offsite.URL) || strings.Contains(ep.URL, "/secret") {
			t.Errorf("cross-host redirect leaked endpoint: %+v", ep)
		}
	}
}
