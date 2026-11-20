package dashboard

import (
	"net/http"
	"strings"
)

// assetRoutes registers the two bundled static assets. The HTML shell and the
// unknown-API fallback live in serveTail because they are the last match.
func assetRoutes() []appRoute {
	return []appRoute{
		{path: "/style.css", handler: (*Server).serveStyleCSS},
		{path: "/app.js", handler: (*Server).serveAppJS},
	}
}

// serveTail handles the fall-through cases: the JSON 404 for unknown API paths,
// the HTML shell, and the plain 404 for everything else. It runs only after no
// route in appRoutes matched, so an unknown /api/... path cannot fall through
// to the HTML shell and be mistaken for success by a caller.
func (s *Server) serveTail(w http.ResponseWriter, r *http.Request, path string) {
	if path == "/api" || strings.HasPrefix(path, "/api/") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"ok":false,"error":"unknown API endpoint"}`))
		return
	}
	if path == "/" || path == "/index.html" {
		s.serveIndex(w, r)
		return
	}
	http.NotFound(w, r)
}

func (s *Server) serveStyleCSS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(loadDashboardAsset("style.css", dashboardCSS))
}

func (s *Server) serveAppJS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(loadDashboardJS())
}

func (s *Server) serveIndex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	if r.Method == http.MethodHead {
		return
	}
	s.serveIndexHTML(w)
}
