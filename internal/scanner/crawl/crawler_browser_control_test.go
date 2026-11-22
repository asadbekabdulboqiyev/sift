package crawl

// crawler_browser_control_test.go locks the browser-mode authorization seam:
// the gate's DialControl must reach browser.New() so Chromium's independent
// network stack is constrained by the same class decision as the plain HTTP
// crawler. It uses a fake browser factory, so no Chromium binary is required.

import (
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type recordingBrowser struct {
	html      string
	pageErr   error
	pages     int32
	closeCnt  int32
	pageCalls int32
}

func (f *recordingBrowser) Page(_ string, _ time.Duration) (string, error) {
	atomic.AddInt32(&f.pageCalls, 1)
	atomic.AddInt32(&f.pages, 1)
	return f.html, f.pageErr
}

func (f *recordingBrowser) Close() error {
	atomic.AddInt32(&f.closeCnt, 1)
	return nil
}

// installFakeBrowser swaps newCrawlBrowser for the duration of the test and
// records the control it was constructed with. No t.Parallel(): this is a
// package-level seam.
func installFakeBrowser(t *testing.T, fake *recordingBrowser, gotControl *func(network, address string, c syscall.RawConn) error, factoryCalls *int32) {
	t.Helper()
	original := newCrawlBrowser
	newCrawlBrowser = func(control func(network, address string, c syscall.RawConn) error) (browserPage, error) {
		atomic.AddInt32(factoryCalls, 1)
		if gotControl != nil {
			*gotControl = control
		}
		return fake, nil
	}
	t.Cleanup(func() { newCrawlBrowser = original })
}

func TestCrawlBrowserPassesDialControlToBrowserFactory(t *testing.T) {
	var controlCalls int32
	sentinel := func(network, address string, c syscall.RawConn) error {
		atomic.AddInt32(&controlCalls, 1)
		return nil
	}

	fake := &recordingBrowser{html: `<html><body><a href="/endpoint?q=1">link</a></body></html>`}
	var (
		gotControl   func(network, address string, c syscall.RawConn) error
		factoryCalls int32
	)
	installFakeBrowser(t, fake, &gotControl, &factoryCalls)

	cr := NewCrawler("http://sift.test/", CrawlOptions{
		UseBrowser: true,
		MaxPages:   1,
		Timeout:    time.Second,
	})
	cr.DialControl = sentinel
	res := cr.Crawl()

	if got := atomic.LoadInt32(&factoryCalls); got != 1 {
		t.Fatalf("browser factory calls = %d, want 1", got)
	}
	if gotControl == nil {
		t.Fatal("browser factory received nil control; gate decision was dropped")
	}
	// Functions are not comparable, so verify identity by side effect.
	if err := gotControl("tcp", "127.0.0.1:80", nil); err != nil {
		t.Fatalf("captured control: %v", err)
	}
	if got := atomic.LoadInt32(&controlCalls); got != 1 {
		t.Fatalf("captured control calls = %d, want 1", got)
	}
	if res.Pages != 1 {
		t.Fatalf("Pages = %d, want 1", res.Pages)
	}
	found := false
	for _, ep := range res.Endpoints {
		if strings.Contains(ep.URL, "/endpoint") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected discovered endpoint, got %+v", res.Endpoints)
	}
	if got := atomic.LoadInt32(&fake.closeCnt); got != 1 {
		t.Fatalf("browser Close calls = %d, want 1", got)
	}
}

func TestCrawlHTTPDoesNotConstructBrowser(t *testing.T) {
	fake := &recordingBrowser{html: "<html></html>"}
	var (
		gotControl   func(network, address string, c syscall.RawConn) error
		factoryCalls int32
	)
	installFakeBrowser(t, fake, &gotControl, &factoryCalls)

	cr := NewCrawler("http://sift.test/", CrawlOptions{UseBrowser: false, MaxPages: 1})
	cr.DialControl = func(network, address string, c syscall.RawConn) error { return nil }
	_ = cr.Crawl()

	if got := atomic.LoadInt32(&factoryCalls); got != 0 {
		t.Fatalf("HTTP mode constructed a browser %d times, want 0", got)
	}
}
