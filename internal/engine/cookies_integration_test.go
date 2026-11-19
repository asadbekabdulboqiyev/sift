//go:build integration

package engine

import (
	"fmt"
	"github.com/asadbekabdulboqiyev/sift/internal/config"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// TestHTTPCookieJarSessionFlow verifies per-virtual-user cookie sessions:
// a Set-Cookie from the login step must be replayed on the next step.
func TestHTTPCookieJarSessionFlow(t *testing.T) {
	var mu sync.Mutex
	sessions := map[string]int{} // session id -> hit count

	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "sess-1", Path: "/"})
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/profile", func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("sid")
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		mu.Lock()
		sessions[c.Value]++
		mu.Unlock()
		fmt.Fprint(w, "ok")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	sc := &config.Scenario{
		Name:    "cookie-flow",
		BaseURL: srv.URL,
		Profile: config.Profile{Type: config.ProfileSteady, Users: 2, Duration: 1, Timeout: 5},
		Steps: []config.Step{
			{Name: "login", Method: "POST", URL: "/login"},
			{Name: "profile", URL: "/profile"},
		},
	}
	tel := runScenario(t, sc, time.Second)
	if tel.TotalErrors() != 0 {
		t.Fatalf("errors = %d, want 0: %v", tel.TotalErrors(), tel.Errors())
	}

	mu.Lock()
	hits := 0
	for _, n := range sessions {
		hits += n
	}
	mu.Unlock()
	if hits == 0 {
		t.Error("no authenticated /profile hits — cookies were not replayed")
	}
}
