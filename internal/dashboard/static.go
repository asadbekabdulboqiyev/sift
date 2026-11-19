package dashboard

import (
	"bytes"
	"embed"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// dashboardUIFS holds the UI shell and script assets embedded at build time.
//
//go:embed index.html style.css assets/*.js
var dashboardUIFS embed.FS

// dashboardAssets is kept for internal package tests/tools that inspect the
// embedded script parts; it aliases dashboardUIFS.
var dashboardAssets = dashboardUIFS

var (
	dashboardHTML = mustReadDashboardUI("index.html")
	dashboardCSS  = mustReadDashboardUI("style.css")
	// dashboardJS is the concatenated bundle, built once at start-up.
	dashboardJS = bundleDashboardJS()
)

func mustReadDashboardUI(name string) []byte {
	b, err := dashboardUIFS.ReadFile(name)
	if err != nil {
		panic("dashboard ui: " + name + ": " + err.Error())
	}
	return b
}

func bundleDashboardJS() []byte {
	paths, err := fs.Glob(dashboardUIFS, "assets/*.js")
	if err != nil {
		panic("dashboard assets: " + err.Error())
	}
	if len(paths) == 0 {
		panic("dashboard assets: no .js files embedded")
	}

	var buf bytes.Buffer
	for _, p := range paths {
		part, err := dashboardUIFS.ReadFile(p)
		if err != nil {
			panic("dashboard asset " + p + ": " + err.Error())
		}
		buf.Write(part)
		if len(part) > 0 && part[len(part)-1] != '\n' {
			buf.WriteByte('\n')
		}
	}
	return buf.Bytes()
}

// serveIndexHTML serves the dashboard shell with cache-busted asset URLs so the
// browser always loads assets for the current binary version.
func (s *Server) serveIndexHTML(w http.ResponseWriter) {
	v := url.QueryEscape(s.versionOrDefault())
	html := string(loadDashboardAsset("index.html", dashboardHTML))
	html = strings.Replace(html, `href="/style.css"`, fmt.Sprintf(`href="/style.css?v=%s"`, v), 1)
	html = strings.Replace(html, `src="/app.js"`, fmt.Sprintf(`src="/app.js?v=%s"`, v), 1)
	_, _ = w.Write([]byte(html))
}

// dashboardDevAssetsEnabled reports whether local on-disk UI assets should be
// used instead of the embedded bundle. This is explicit opt-in for development.
func dashboardDevAssetsEnabled() bool {
	return os.Getenv("SIFT_DASHBOARD_DEV_ASSETS") == "1"
}

// loadDashboardAsset returns the UI asset to serve. Embedded assets are the
// default: they ship with the binary, so a production dashboard can never pick
// up HTML/JS from a directory next to the process (a stale or attacker-writable
// `internal/dashboard` in the working directory would otherwise inject script
// into the dashboard origin, which can drive every API route).
//
// Local UI edits are still picked up when SIFT_DASHBOARD_DEV_ASSETS=1 is set
// explicitly, and only from the repository layout that opts in.
func loadDashboardAsset(name string, fallback []byte) []byte {
	if dashboardDevAssetsEnabled() {
		for _, p := range dashboardAssetCandidates(name) {
			b, err := os.ReadFile(p)
			if err == nil && len(b) > 0 {
				return b
			}
		}
	}
	return fallback
}

func dashboardAssetCandidates(name string) []string {
	candidates := []string{
		filepath.Join("internal", "dashboard", name),
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "internal", "dashboard", name))
	}
	return candidates
}

func loadDashboardJS() []byte {
	if !dashboardDevAssetsEnabled() {
		return dashboardJS
	}
	for _, dir := range dashboardAssetCandidates("assets") {
		paths, err := filepath.Glob(filepath.Join(dir, "*.js"))
		if err != nil || len(paths) == 0 {
			continue
		}
		// filepath.Glob returns lexicographic order, matching embedded bundle order.
		var buf bytes.Buffer
		ok := true
		for _, p := range paths {
			part, err := os.ReadFile(p)
			if err != nil {
				ok = false
				break
			}
			buf.Write(part)
			if len(part) > 0 && part[len(part)-1] != '\n' {
				buf.WriteByte('\n')
			}
		}
		if ok && buf.Len() > 0 {
			return buf.Bytes()
		}
	}
	return dashboardJS
}
func getDashboardDataDir() (string, error) {
	if d, err := os.UserConfigDir(); err == nil && d != "" {
		dir := filepath.Join(d, "Sift", "dashboard")
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return "", err
		}
		return dir, nil
	}
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		dir := filepath.Join(h, ".Sift", "dashboard")
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return "", err
		}
		return dir, nil
	}
	return "", fmt.Errorf("cannot determine user config/home dir")
}
