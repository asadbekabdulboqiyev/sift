package dashboard

import (
	"net/http"
	"strings"
)

// appRouteHandler is a Server method used as a route target. Keeping the
// handler as a method expression makes the route tables plain data: they can
// be listed in dispatch order without any closure or registration side effect.
type appRouteHandler func(*Server, http.ResponseWriter, *http.Request)

// appRoute is one entry in the dashboard's UI/API dispatch table.
//
// prefix is optional. When set, the entry matches any path starting with it;
// otherwise the match is an exact path comparison. The prefix form exists for
// the one route that needs it (certificate downloads), so ordering stays
// explicit and identical to the original switch.
type appRoute struct {
	path    string
	prefix  string
	handler appRouteHandler
}

func (rt appRoute) matches(path string) bool {
	if rt.prefix != "" {
		return strings.HasPrefix(path, rt.prefix)
	}
	return path == rt.path
}

// appRoutes is assembled once, in dispatch order, from the four route groups.
// The order is security-relevant: the /api catch-all and the static shell live
// in the tail fallback, so a mistyped API path can never fall through to HTML.
var appRoutes = append(append(append(
	coreRoutes(),
	scanRoutes()...),
	insightsRoutes()...),
	assetRoutes()...)

// serveApp routes the UI, JSON API and WebSocket traffic.
//
// Every caller reaches this method through ServeHTTP, which runs the host gate,
// the security headers, the recover wrapper and the injected auth middleware
// first. Splitting the route table does not change that chain.
func (s *Server) serveApp(w http.ResponseWriter, r *http.Request) {
	// TRACE is disabled to avoid method-based reflection/XST-style scanner findings
	// and to keep behavior explicit in production-like deployments.
	if r.Method == http.MethodTrace {
		w.Header().Set("Allow", "GET, HEAD, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := r.URL.Path
	for _, rt := range appRoutes {
		if rt.matches(path) {
			rt.handler(s, w, r)
			return
		}
	}
	s.serveTail(w, r, path)
}
