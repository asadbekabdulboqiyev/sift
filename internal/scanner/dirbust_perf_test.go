package scanner

// dirbust_perf_test.go — measures title extraction on a 4 MB document and the
// dispatch cost of a large, already-cancelled path list.

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func BenchmarkExtractTitleLarge(b *testing.B) {
	html := []byte("<html><body>" + strings.Repeat("x", 4<<20) + "<TITLE>  Benchmark Title  </TITLE></body></html>")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = extractTitle(html)
	}
}

type dirBustBenchRequester struct{}

func (dirBustBenchRequester) Check(context.Context, string, string, bool) error {
	return errors.New("benchmark stop")
}

func (dirBustBenchRequester) Do(*http.Request) (*http.Response, error) {
	return nil, errors.New("benchmark stop")
}

func BenchmarkDirBustCancelledManyPaths(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	paths := make([]string, 4096)
	for i := range paths {
		paths[i] = "/path-" + strconv.Itoa(i)
	}
	req := dirBustBenchRequester{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = DirBust(ctx, "http://example.com", paths, req)
	}
}

// dirBustCountingRequester makes the dispatch count observable, so a
// regression to eager goroutine creation fails a test instead of only a
// benchmark allocation number.
type dirBustCountingRequester struct {
	checks atomic.Int64
	sends  atomic.Int64
}

func (r *dirBustCountingRequester) Check(context.Context, string, string, bool) error {
	r.checks.Add(1)
	return errors.New("cancelled run must not reach policy checks")
}

func (r *dirBustCountingRequester) Do(*http.Request) (*http.Response, error) {
	r.sends.Add(1)
	return nil, errors.New("cancelled run must not send requests")
}

func TestDirBustCancelledStopsDispatch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	paths := make([]string, 4096)
	for i := range paths {
		paths[i] = "/path-" + strconv.Itoa(i)
	}

	const base = "http://example.com"
	req := &dirBustCountingRequester{}
	res := DirBust(ctx, base, paths, req)

	if res.Target != base || res.Found != 0 || len(res.Entries) != 0 {
		t.Errorf("cancelled result = target %q, found %d, entries %d; want clean empty result", res.Target, res.Found, len(res.Entries))
	}
	// The semaphore admits at most 40 slots before ctx.Done wins. The old
	// per-path goroutine dispatch would have reached all 4096 checks.
	if got := req.checks.Load(); got > 40 {
		t.Errorf("policy checks = %d, want at most 40 for a cancelled run", got)
	}
	if got := req.sends.Load(); got != 0 {
		t.Errorf("HTTP sends = %d, want 0 for a cancelled run", got)
	}
}

// extractTitleReference is the original ToLower-based implementation, kept as
// a behavioral oracle for the optimized byte-path search.
func extractTitleReference(html string) string {
	start := strings.Index(strings.ToLower(html), "<title>")
	if start < 0 {
		return ""
	}
	start += 7
	end := strings.Index(strings.ToLower(html[start:]), "</title>")
	if end < 0 {
		return strings.TrimSpace(html[start:])
	}
	return strings.TrimSpace(html[start : start+end])
}

func TestExtractTitleMatchesReference(t *testing.T) {
	cases := []string{
		`<html><title>Hello World</title></html>`,
		`<html><body>no title</body></html>`,
		`<title>Only start</html>`,
		``,
		`<HTML><TiTlE>  Mixed Case  </tItLe></HTML>`,
		`<title>one</title><title>two</title>`,
		`<title>  spaced  </TITLE>`,
		`prefix < TITLE > not a tag <title>real</title>`,
		`<title>unicode: café straight</title>`,
	}
	for _, html := range cases {
		got := extractTitle([]byte(html))
		want := extractTitleReference(html)
		if got != want {
			t.Errorf("extractTitle(%q) = %q, reference = %q", html, got, want)
		}
	}
}
