package authz

// proxy_test.go proves ProxyWithControl re-applies the gate decision to the
// destination when an HTTP proxy carries the request (CWE-290). The socket
// Control hook sees only the proxy address, so without this wrapper a target
// resolving to metadata/private space could be fetched by the proxy unnoticed.

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func proxyOnly(_ *http.Request) (*url.URL, error) {
	return &url.URL{Scheme: "http", Host: "127.0.0.1:3128"}, nil
}

func TestProxyWithControlNilPassthrough(t *testing.T) {
	// A nil control must leave the selector untouched so dev/tests keep the
	// historical direct behavior.
	if got := ProxyWithControl(proxyOnly, nil); got == nil {
		t.Fatal("nil control returned a nil proxy selector")
	}
	if got := ProxyWithControl(nil, func(_, _ string, _ syscall.RawConn) error { return nil }); got != nil {
		t.Fatal("nil base must stay nil")
	}
}

func TestProxyWithControlSkipsCheckWithoutProxy(t *testing.T) {
	var checked atomic.Int32
	noProxy := func(*http.Request) (*url.URL, error) { return nil, nil }
	control := func(_, _ string, _ syscall.RawConn) error {
		checked.Add(1)
		return nil
	}
	req, err := http.NewRequest(http.MethodGet, "http://169.254.169.254/latest/meta-data/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	proxyURL, err := ProxyWithControl(noProxy, control)(req)
	if err != nil || proxyURL != nil {
		t.Fatalf("no-proxy selector: proxyURL=%v err=%v", proxyURL, err)
	}
	if got := checked.Load(); got != 0 {
		t.Fatalf("control called %d times with no proxy; want 0", got)
	}
}

func TestProxyWithControlChecksDestinationAddress(t *testing.T) {
	var seen []string
	control := func(_, address string, _ syscall.RawConn) error {
		seen = append(seen, address)
		return nil
	}
	// Literal IPs avoid DNS; the check must hit the destination, not the proxy.
	for _, tc := range []struct{ raw, want string }{
		{"https://169.254.169.254/x", "169.254.169.254:443"},
		{"http://169.254.169.254/x", "169.254.169.254:80"},
	} {
		seen = nil
		req, err := http.NewRequest(http.MethodGet, tc.raw, nil)
		if err != nil {
			t.Fatalf("NewRequest(%s): %v", tc.raw, err)
		}
		if _, err := ProxyWithControl(proxyOnly, control)(req); err != nil {
			t.Fatalf("wrapped selector(%s): %v", tc.raw, err)
		}
		if len(seen) != 1 || seen[0] != tc.want {
			t.Fatalf("checked addresses for %s = %v, want [%s]", tc.raw, seen, tc.want)
		}
	}
}

func TestProxyWithControlDerivesDefaultPort(t *testing.T) {
	// ws/wss have no http.NewRequest helper but are used by engine clients;
	// an omitted port must inherit 80/443 from the scheme.
	for _, tc := range []struct{ scheme, want string }{
		{"http", "169.254.169.254:80"},
		{"https", "169.254.169.254:443"},
		{"ws", "169.254.169.254:80"},
		{"wss", "169.254.169.254:443"},
	} {
		var seen []string
		control := func(_, address string, _ syscall.RawConn) error {
			seen = append(seen, address)
			return nil
		}
		req := &http.Request{URL: &url.URL{Scheme: tc.scheme, Host: "169.254.169.254"}}
		if _, err := ProxyWithControl(proxyOnly, control)(req); err != nil {
			t.Fatalf("%s: wrapped selector: %v", tc.scheme, err)
		}
		if len(seen) != 1 || seen[0] != tc.want {
			t.Fatalf("%s: checked addresses = %v, want [%s]", tc.scheme, seen, tc.want)
		}
	}
}

func TestProxyWithControlRefusesDestinationBeforeProxyDial(t *testing.T) {
	var proxyHits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	base := func(*http.Request) (*url.URL, error) { return proxyURL, nil }

	var controlCalls atomic.Int32
	control := func(_, address string, _ syscall.RawConn) error {
		controlCalls.Add(1)
		if strings.HasPrefix(address, "169.254.169.254") {
			return errors.New("refusing metadata destination")
		}
		return nil
	}
	client := &http.Client{
		Transport: &http.Transport{Proxy: ProxyWithControl(base, control)},
		Timeout:   2 * time.Second,
	}

	_, err = client.Get("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
	if err == nil {
		t.Fatal("expected the metadata destination to be refused")
	}
	if proxyHits.Load() != 0 {
		t.Fatalf("proxy received %d request(s); the destination must be refused before the proxy dial", proxyHits.Load())
	}
	if controlCalls.Load() == 0 {
		t.Fatal("control was never applied to the destination")
	}
}

// TestControlledTransportsUseProxyWithControl pins the wiring at every Go
// HTTP client in the pentest path that pairs a proxy selector with a dial
// control. The proxy tests above prove the helper works; this proves the
// callers actually apply it so none can silently drop the destination check.
func TestControlledTransportsUseProxyWithControl(t *testing.T) {
	for path, want := range map[string]string{
		"../scanner/auth/auth.go":    "authz.ProxyWithControl(http.ProxyFromEnvironment, control)",
		"../scanner/verify.go":       "authz.ProxyWithControl(http.ProxyFromEnvironment, control)",
		"../scanner/vuln_scanner.go": "authz.ProxyWithControl(tr.Proxy, control)",
	} {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("read %s: %v", path, err)
			continue
		}
		if !strings.Contains(string(src), want) {
			t.Errorf("%s does not wrap its proxy selector with the gate check; want %q", path, want)
		}
	}
}

func TestProxyWithControlAllowsApprovedDestination(t *testing.T) {
	var proxyHits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyHits.Add(1)
		fmt.Fprint(w, "APPROVED")
	}))
	defer proxy.Close()
	proxyURL, _ := url.Parse(proxy.URL)
	base := func(*http.Request) (*url.URL, error) { return proxyURL, nil }

	// A literal public IP that control approves: the wrapper must delegate to
	// the base selector and let the request reach the proxy (no DNS involved).
	control := func(_, address string, _ syscall.RawConn) error {
		if strings.HasPrefix(address, "169.254.169.254") {
			return errors.New("refusing metadata destination")
		}
		return nil
	}
	client := &http.Client{
		Transport: &http.Transport{Proxy: ProxyWithControl(base, control)},
		Timeout:   2 * time.Second,
	}
	resp, err := client.Get("http://93.184.216.34/resource")
	if err != nil {
		t.Fatalf("approved request: %v", err)
	}
	defer resp.Body.Close()
	if proxyHits.Load() != 1 {
		t.Fatalf("proxy hits = %d, want 1", proxyHits.Load())
	}
}
