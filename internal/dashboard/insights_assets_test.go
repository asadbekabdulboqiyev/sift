package dashboard

import (
	"strings"
	"testing"
)

// jsFunctionBody returns the full source of a function in app.js, from its
// signature through its matching closing brace. String literals are skipped so
// braces inside HTML/template strings do not close the function early. It is
// used below to assert the contract of small helpers that run in the browser
// and cannot be exercised directly from a Go test.
func jsFunctionBody(t *testing.T, js, sig string) string {
	t.Helper()
	start := strings.Index(js, sig)
	if start < 0 {
		t.Fatalf("could not find %q in app.js; the insights helper contract changed", sig)
	}

	i := start + len(sig) - 1 // the signature's opening '{'
	depth := 0
	var quote byte
	escaped := false
	for ; i < len(js); i++ {
		c := js[i]
		if quote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"', '`':
			quote = c
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return js[start : i+1]
			}
		}
	}
	t.Fatalf("unbalanced braces while reading %q from app.js", sig)
	return ""
}

// TestInsightsBadgesRenderAsMarkup guards a real rendering defect in the
// Insights/Digital-Twin/Bounty panels (app-14-insights.js).
//
// badge(text, tone) builds a <span class="ins-badge ..."> element, while
// kv(key, value) escapes its value. Every kv(label, badge(...)) call therefore
// fed escaped markup into innerHTML: operators saw the literal text
// "<span class=...>HIGH</span>" instead of a coloured status badge, on the
// Confidence, Capacity, Risk, Drift and Leakage rows of every report.
//
// The fix keeps untrusted text escaped: badge() wraps its markup in a trusted
// container, kv() unwraps that container instead of escaping it, and the two
// call sites that concatenate badge() straight into markup unwrap explicitly.
func TestInsightsBadgesRenderAsMarkup(t *testing.T) {
	js := string(dashboardJS)

	// badge() must mark its markup as trusted rather than returning a bare
	// string that kv() will escape a second time.
	badge := jsFunctionBody(t, js, "function badge(text, tone) {")
	if !strings.Contains(badge, "return trustedHTML(") {
		t.Errorf("badge() must wrap its <span> markup with trustedHTML() so kv() does not escape it again:\n%s", badge)
	}

	// kv() must unwrap a trusted value and escape every other value.
	kv := jsFunctionBody(t, js, "function kv(k, v) {")
	if !strings.Contains(kv, "__html") || !strings.Contains(kv, "esc(val)") {
		t.Errorf("kv() must insert trusted HTML verbatim and escape untrusted values:\n%s", kv)
	}

	if !strings.Contains(js, "function trustedHTML(html) {") {
		t.Error("the trustedHTML() helper is missing from app.js")
	}

	// These two renderers concatenate badge() directly into a markup string
	// (they do not go through kv()); they must unwrap or they would print
	// "[object Object]" now that badge() returns a wrapper.
	for _, needle := range []string{
		"badge(b.status, tone).__html",
		"badge(risk, risk === 'high' ? 'bad' : (risk === 'elevated' ? 'warn' : 'good')).__html",
	} {
		if !strings.Contains(js, needle) {
			t.Errorf("direct badge() concatenation must unwrap with .__html; missing %q", needle)
		}
	}
}
