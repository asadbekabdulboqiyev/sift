package replay

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/asadbekabdulboqiyev/sift/internal/authz"
)

// dialRecorder records the peers a control actually sees. It wraps the real
// authz hook so a test can tell "refused by the redirect pin" from "refused by
// the socket policy".
type dialRecorder struct {
	mu    sync.Mutex
	addrs []string
	base  func(string, string, syscall.RawConn) error
}

func (r *dialRecorder) control(network, address string, c syscall.RawConn) error {
	r.mu.Lock()
	r.addrs = append(r.addrs, address)
	r.mu.Unlock()
	if r.base != nil {
		return r.base(network, address, c)
	}
	return nil
}

func (r *dialRecorder) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.addrs...)
}

func runOnePacket(t *testing.T, pkt *Packet, cfg *ReplayConfig) *ReplayWorker {
	t.Helper()
	w := NewReplayWorker(0, cfg, &Capture{}, []*Packet{pkt})
	if err := w.Run(); err != nil {
		t.Fatalf("worker run: %v", err)
	}
	return w
}

// TestReplayCrossHostRedirectRefused pins the exfiltration path: the origin is
// allowed by a public approval (with an exception for the loopback fixture),
// and its redirect to a different port must stop at the redirect check. A 302
// stored on the packet proves ErrUseLastResponse, not a socket refusal.
func TestReplayCrossHostRedirectRefused(t *testing.T) {
	var targetHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		_, _ = w.Write([]byte("secret-from-other-host"))
	}))
	defer target.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target.URL+"/steal")
		w.WriteHeader(http.StatusFound)
	}))
	defer origin.Close()

	originAddr := strings.TrimPrefix(origin.URL, "http://")
	targetAddr := strings.TrimPrefix(target.URL, "http://")
	approved := authz.DialControl(authz.ClassPublic)
	rec := &dialRecorder{base: func(network, address string, c syscall.RawConn) error {
		if address == originAddr {
			return nil // the loopback fixture stands in for the public target
		}
		return approved(network, address, c)
	}}

	pkt := &Packet{Method: http.MethodGet, URL: origin.URL + "/start", Protocol: "http", IsRequest: true}
	cfg := &ReplayConfig{
		BaseURL: origin.URL, FollowRedirects: true,
		Pacing: PacingTiming, RateMultiplier: 1000, MaxConcurrency: 1,
		DialControl: rec.control,
	}
	w := runOnePacket(t, pkt, cfg)

	if pkt.Response == nil {
		t.Fatalf("no response recorded; errors: %v", w.GetErrors())
	}
	if pkt.Response.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302 (redirect refused and last response kept)", pkt.Response.StatusCode)
	}
	if strings.Contains(string(pkt.Response.Body), "secret-from-other-host") {
		t.Fatal("report body contains the cross-host response")
	}
	if got := targetHits.Load(); got != 0 {
		t.Fatalf("cross-host target saw %d requests, want 0", got)
	}
	for _, addr := range rec.seen() {
		if addr == targetAddr {
			t.Fatalf("control saw a dial to the cross-host target %s", targetAddr)
		}
	}
}

func TestReplaySameHostRedirectAllowedWithControl(t *testing.T) {
	var finalHits atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/final", func(w http.ResponseWriter, r *http.Request) {
		finalHits.Add(1)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/final", http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	rec := &dialRecorder{base: authz.DialControl(authz.ClassLoopback)}
	pkt := &Packet{Method: http.MethodGet, URL: srv.URL + "/start", Protocol: "http", IsRequest: true}
	cfg := &ReplayConfig{
		BaseURL: srv.URL, FollowRedirects: true,
		Pacing: PacingTiming, RateMultiplier: 1000, MaxConcurrency: 1,
		DialControl: rec.control,
	}
	w := runOnePacket(t, pkt, cfg)

	if pkt.Response == nil || pkt.Response.StatusCode != http.StatusOK {
		t.Fatalf("response = %+v, want 200; errors: %v", pkt.Response, w.GetErrors())
	}
	if got := finalHits.Load(); got != 1 {
		t.Fatalf("same-host final hits = %d, want 1", got)
	}
}

func TestReplaySchemeChangeRedirectRefused(t *testing.T) {
	for _, tc := range []struct {
		name     string
		newSrv   func(http.Handler) *httptest.Server
		toScheme string
	}{
		{"http to https", func(h http.Handler) *httptest.Server { return httptest.NewServer(h) }, "https"},
		{"https to http", func(h http.Handler) *httptest.Server { return httptest.NewTLSServer(h) }, "http"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := tc.newSrv(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", tc.toScheme+"://"+r.Host+"/final")
				w.WriteHeader(http.StatusFound)
			}))
			defer srv.Close()

			pkt := &Packet{Method: http.MethodGet, URL: srv.URL + "/start", Protocol: "http", IsRequest: true}
			cfg := &ReplayConfig{
				BaseURL: srv.URL, FollowRedirects: true, SkipTLSVerify: true,
				Pacing: PacingTiming, RateMultiplier: 1000, MaxConcurrency: 1,
				DialControl: authz.DialControl(authz.ClassLoopback),
			}
			w := runOnePacket(t, pkt, cfg)

			if pkt.Response == nil || pkt.Response.StatusCode != http.StatusFound {
				t.Fatalf("response = %+v, want 302 after scheme change; errors: %v", pkt.Response, w.GetErrors())
			}
		})
	}
}

func TestReplayCustomHeadersNotForwardedCrossHost(t *testing.T) {
	const secret = "captured-api-key-value"
	var forwarded atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") == secret {
			forwarded.Add(1)
		}
	}))
	defer target.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target.URL+"/steal")
		w.WriteHeader(http.StatusFound)
	}))
	defer origin.Close()

	pkt := &Packet{
		Method: http.MethodGet, URL: origin.URL + "/start", Protocol: "http", IsRequest: true,
		Headers: http.Header{"X-Api-Key": []string{secret}},
	}
	cfg := &ReplayConfig{
		BaseURL: origin.URL, FollowRedirects: true,
		Pacing: PacingTiming, RateMultiplier: 1000, MaxConcurrency: 1,
		DialControl: authz.DialControl(authz.ClassLoopback),
	}
	runOnePacket(t, pkt, cfg)

	if got := forwarded.Load(); got != 0 {
		t.Fatalf("cross-host target received the captured X-Api-Key %d times", got)
	}
}

func TestReplaySocketControlRefusesLoopbackUnderPublicApproval(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler must not be reached when the socket control refuses loopback")
	}))
	defer srv.Close()

	// "localhost" resolves to loopback; the public approval must refuse the
	// resolved peer at dial time, before any request reaches the handler.
	baseURL := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	pkt := &Packet{Method: http.MethodGet, URL: baseURL + "/x", Protocol: "http", IsRequest: true}
	cfg := &ReplayConfig{
		BaseURL: baseURL,
		Pacing:  PacingTiming, RateMultiplier: 1000, MaxConcurrency: 1,
		DialControl: authz.DialControl(authz.ClassPublic),
	}
	w := runOnePacket(t, pkt, cfg)

	if pkt.Response != nil {
		t.Fatalf("response recorded despite refused dial: %+v", pkt.Response)
	}
	errs := w.GetErrors()
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "more restrictive than the approved public class") {
		t.Fatalf("errors = %v, want the authz socket refusal", errs)
	}
}

func TestReplayNilControlKeepsHistoricalTransportAndRedirects(t *testing.T) {
	var finalHits atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/final", func(w http.ResponseWriter, r *http.Request) {
		finalHits.Add(1)
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/final", http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := &ReplayConfig{
		BaseURL: srv.URL, FollowRedirects: true,
		Pacing: PacingTiming, RateMultiplier: 1000, MaxConcurrency: 1,
	}
	pkt := &Packet{Method: http.MethodGet, URL: srv.URL + "/start", Protocol: "http", IsRequest: true}
	w := runOnePacket(t, pkt, cfg)

	tr, ok := w.conn.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T", w.conn.Transport)
	}
	if tr.DialContext != nil || tr.Proxy != nil {
		t.Fatal("nil DialControl changed the historical transport (DialContext or Proxy installed)")
	}
	if pkt.Response == nil || pkt.Response.StatusCode != http.StatusOK {
		t.Fatalf("response = %+v, want 200; errors: %v", pkt.Response, w.GetErrors())
	}
	if got := finalHits.Load(); got != 1 {
		t.Fatalf("same-host final hits = %d, want 1", got)
	}
}
