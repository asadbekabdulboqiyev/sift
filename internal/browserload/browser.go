// Package browserload provides browser-based load testing using a real
// Chromium-based browser via chromedp. This lets Sift measure how a
// target performs for an actual end user (JS rendering, CSS layout, image
// loading, XHR/fetch), which the plain HTTP engine cannot capture.
//
// Browser load testing is intentionally heavier than the HTTP engine: each
// virtual user is a real browser tab. It is meant for SPA/JS-rendered pages
// and end-user experience validation, not for raw throughput.
//
// See docs/ROADMAP.md for the full browser load testing rollout plan.
package browserload

import (
	"context"
	"fmt"
	"net/url"
	"sync"
	"syscall"
	"time"

	"github.com/chromedp/chromedp"

	"github.com/asadbekabdulboqiyev/sift/internal/scanner/browser"
)

const (
	// defaultRunTimeout bounds one page load, including Chrome startup.
	// There is no Runner-level timeout setting; 30s matches the browser
	// startup allowance in internal/scanner/browser (probeTimeout), so a
	// hung page cannot hold a tab or its Chrome process indefinitely.
	defaultRunTimeout = 30 * time.Second

	// maxConcurrentTabs caps simultaneous Chrome instances in RunConcurrent,
	// matching the documented "light 5-20 tabs" guidance above. Extra tabs
	// queue instead of failing, preserving one result slot per requested tab.
	maxConcurrentTabs = 20
)

// RunResult describes a single browser page-load measurement.
type RunResult struct {
	URL        string        `json:"url"`
	LoadTime   time.Duration `json:"load_time"`   // navigationStart → loadEventEnd
	DOMContent time.Duration `json:"dom_content"` // navigationStart → domContentLoadedEventEnd
	StatusCode int           `json:"status_code"`
	Error      string        `json:"error,omitempty"`
	JSErrors   []string      `json:"js_errors"` // console errors captured during load
}

// Runner executes page loads in a real browser.
type Runner struct {
	opts  []chromedp.ExecAllocatorOption
	close func() error
}

// defaultRunnerOptions are the launch flags shared by controlled and
// uncontrolled runners. Authorization flags are added separately by
// NewRunnerWithControl so the two stacks cannot drift apart.
func defaultRunnerOptions() []chromedp.ExecAllocatorOption {
	return []chromedp.ExecAllocatorOption{
		chromedp.Flag("headless", "new"),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-background-timer-throttling", true),
		chromedp.Flag("disable-backgrounding-occluded-windows", true),
		chromedp.Flag("disable-renderer-backgrounding", true),
		chromedp.Flag("disable-features", "TranslateUI"),
		chromedp.Flag("disable-ipc-flooding-protection", true),
		chromedp.Flag("no-first-run", true),
		chromedp.Flag("no-default-browser-check", true),
		chromedp.Flag("disable-default-apps", true),
		chromedp.Flag("disable-sync", true),
		chromedp.Flag("metrics-recording-only", true),
		chromedp.Flag("mute-audio", true),
		chromedp.Flag("remote-debugging-port", "0"),
	}
}

// NewRunner creates a headless Chrome runner with direct network access. It
// attempts to find a Chrome binary on the system; if none is found, Run() will
// return an error. Use NewRunnerWithControl inside the pentest gate.
func NewRunner() *Runner {
	return &Runner{
		opts:  defaultRunnerOptions(),
		close: func() error { return nil },
	}
}

// NewRunnerWithControl creates a runner whose Chromium traffic is forced
// through the same guard proxy used by browser crawl mode. Every navigation
// and page-initiated fetch is class-checked with control before a socket is
// opened, so browser load testing cannot be turned into an SSRF primitive
// when it is wired into a scan. The caller MUST call Close after the last Run.
func NewRunnerWithControl(control func(network, address string, c syscall.RawConn) error) (*Runner, error) {
	flags, closeFn, err := browser.GuardProxyOptions(control)
	if err != nil {
		return nil, fmt.Errorf("browserload: guard proxy: %w", err)
	}
	r := NewRunner()
	r.opts = append(r.opts, flags...)
	r.close = closeFn
	return r, nil
}

// Close releases resources owned by the Runner — the guard proxy listener and
// its in-flight tunnels when one was configured. Per-Run browser contexts are
// cancelled by Run itself. It is safe to call more than once.
func (r *Runner) Close() error {
	if r == nil || r.close == nil {
		return nil
	}
	return r.close()
}

// normalizeURL parses a target URL and supplies the default scheme.
//
// A bare host ("example.com") is what an operator types, and there is no
// browser load test without a scheme, so https is assumed — the same default
// the scanner uses. Everything else is left alone: this function must not
// rewrite a URL a target expects byte for byte.
func normalizeURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid url: %w", err)
	}
	if u.Scheme == "" {
		u.Scheme = "https"
		return u.String(), nil
	}
	return raw, nil
}

// Run loads url in a headless browser and returns performance timings. The
// context must be cancellable; Run respects ctx.Done() for the whole browser
// lifetime and also bounds each load with its own timeout.
func (r *Runner) Run(ctx context.Context, urlStr string) (*RunResult, error) {
	urlStr, err := normalizeURL(urlStr)
	if err != nil {
		return nil, err
	}

	// Keep the caller's context at the root so its cancellation tears down
	// Chrome too, instead of leaving an orphaned browser process behind.
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(ctx, r.opts...)
	defer cancelAlloc()

	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx, chromedp.WithLogf(func(fmt string, args ...interface{}) {}))
	defer cancelBrowser()

	// Set a real timeout wrapper (WithCancel had no deadline at all). Derive
	// it from browserCtx so actions still see the allocated browser.
	runCtx, cancelRun := context.WithTimeout(browserCtx, defaultRunTimeout)
	defer cancelRun()

	result := &RunResult{URL: urlStr}

	var js jsErrorLog
	_ = chromedp.Listen(runCtx, js.handle)
	snapshot := js.snapshot

	// Navigate first (void action)
	if err := chromedp.Do(runCtx, chromedp.Navigate(urlStr)); err != nil {
		result.Error = err.Error()
		result.JSErrors = snapshot()
		return result, err
	}

	// Then evaluate timing (returning values).
	navStart, err := chromedp.Run(runCtx, chromedp.Evaluate[float64](`performance.timing.navigationStart`))
	if err != nil {
		result.Error = err.Error()
		result.JSErrors = snapshot()
		return result, err
	}
	loadEnd, err := chromedp.Run(runCtx, chromedp.Evaluate[float64](`performance.timing.loadEventEnd`))
	if err != nil {
		result.Error = err.Error()
		result.JSErrors = snapshot()
		return result, err
	}
	domEnd, err := chromedp.Run(runCtx, chromedp.Evaluate[float64](`performance.timing.domContentLoadedEventEnd`))
	if err != nil {
		result.Error = err.Error()
		result.JSErrors = snapshot()
		return result, err
	}

	result.LoadTime = time.Duration(loadEnd-navStart) * time.Millisecond
	result.DOMContent = time.Duration(domEnd-navStart) * time.Millisecond
	result.JSErrors = snapshot()

	// Attempt to read the HTTP status code via fetch (may not always work
	// depending on page/cors). EvalAwaitPromise is required: without it the
	// result is the Promise object, not the status, and StatusCode stays 0.
	var status int
	if _, err := chromedp.Run(runCtx, chromedp.Evaluate[int](
		`fetch(window.location.href).then(r=>r.status).catch(()=>0)`,
		chromedp.EvalAwaitPromise,
	)); err != nil {
		// Ignore fetch errors - status may not be available
		status = 0
	}
	result.StatusCode = status

	return result, nil
}

// RunConcurrent runs n concurrent page loads against url. Results are returned
// in completion order. Use this for light browser load testing (e.g. 5-20
// concurrent tabs); for larger loads, use the HTTP engine instead.
func (r *Runner) RunConcurrent(ctx context.Context, url string, n int) ([]*RunResult, error) {
	if n < 0 {
		return nil, fmt.Errorf("concurrent browser runs: n = %d, want >= 0", n)
	}
	if n == 0 {
		return []*RunResult{}, nil
	}

	results := make([]*RunResult, n)
	errs := make([]error, n)

	// One Chrome instance per tab: acquire before spawning so at most
	// maxConcurrentTabs are live at once. Extra tabs queue (they still own a
	// result slot) rather than creating unbounded browser processes.
	sem := make(chan struct{}, maxConcurrentTabs)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		sem <- struct{}{}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i], errs[i] = r.Run(ctx, url)
		}(i)
	}

	// Wait for every tab to finish before handing the slice back. The previous
	// version returned on the first error, which let the remaining goroutines
	// keep writing into the slice the caller already owned — a data race that
	// only appeared when one tab failed while others were still loading.
	wg.Wait()

	for _, err := range errs {
		if err != nil {
			return results, err
		}
	}
	return results, nil
}
