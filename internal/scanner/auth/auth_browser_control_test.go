package auth

// auth_browser_control_test.go proves the auth-browser Chromium is subject to
// the scan gate's dial decision and is always torn down. It uses the
// newAuthBrowser seam, so no Chromium binary is required.

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type recordingAuthBrowser struct {
	body      string
	loginErr  error
	loginCall int32
	closeCall int32
}

func (f *recordingAuthBrowser) LoginForm(_, _, _, _, _ string, _ map[string]string, _ string, _ time.Duration) (bool, string, []*http.Cookie, error) {
	atomic.AddInt32(&f.loginCall, 1)
	return true, f.body, nil, f.loginErr
}

func (f *recordingAuthBrowser) Close() error {
	atomic.AddInt32(&f.closeCall, 1)
	return nil
}

// installAuthBrowser swaps the browser factory for the duration of the test
// and records the control it was constructed with. No t.Parallel(): this is a
// package-level seam.
func installAuthBrowser(t *testing.T, fake *recordingAuthBrowser, gotControl *func(network, address string, c syscall.RawConn) error, factoryCalls *int32) {
	t.Helper()
	original := newAuthBrowser
	newAuthBrowser = func(control func(network, address string, c syscall.RawConn) error) (authBrowser, error) {
		atomic.AddInt32(factoryCalls, 1)
		if gotControl != nil {
			*gotControl = control
		}
		return fake, nil
	}
	t.Cleanup(func() { newAuthBrowser = original })
}

func browserAuthConfig(control func(network, address string, c syscall.RawConn) error) AuthConfig {
	return AuthConfig{
		Type:         AuthBrowser,
		LoginURL:     "https://example.test/login",
		Username:     "user",
		Password:     "pass",
		SuccessMatch: "dashboard",
		DialControl:  control,
	}
}

func TestAuthBrowserPassesDialControlToBrowserFactory(t *testing.T) {
	var controlCalls int32
	sentinel := func(_, _ string, _ syscall.RawConn) error {
		atomic.AddInt32(&controlCalls, 1)
		return nil
	}
	fake := &recordingAuthBrowser{body: "<html>dashboard</html>"}
	var (
		gotControl   func(network, address string, c syscall.RawConn) error
		factoryCalls int32
	)
	installAuthBrowser(t, fake, &gotControl, &factoryCalls)

	sess, err := NewAuthSession(browserAuthConfig(sentinel), 0)
	if err != nil {
		t.Fatalf("NewAuthSession: %v", err)
	}
	if err := sess.Login(); err != nil {
		t.Fatalf("Login: %v", err)
	}

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
	if got := atomic.LoadInt32(&fake.loginCall); got != 1 {
		t.Fatalf("LoginForm calls = %d, want 1", got)
	}
	if got := atomic.LoadInt32(&fake.closeCall); got != 1 {
		t.Fatalf("browser Close calls = %d, want 1", got)
	}
	if !sess.OK() {
		t.Fatal("session should be OK after successful browser login")
	}
}

func TestAuthBrowserClosesBrowserOnLoginError(t *testing.T) {
	fake := &recordingAuthBrowser{
		body:     "<html>still login</html>",
		loginErr: errors.New("login failed"),
	}
	var factoryCalls int32
	installAuthBrowser(t, fake, nil, &factoryCalls)

	sess, err := NewAuthSession(browserAuthConfig(func(_, _ string, _ syscall.RawConn) error { return nil }), 0)
	if err != nil {
		t.Fatalf("NewAuthSession: %v", err)
	}
	if err := sess.Login(); err == nil {
		t.Fatal("Login should fail when the browser login fails")
	}
	if got := atomic.LoadInt32(&factoryCalls); got != 1 {
		t.Fatalf("browser factory calls = %d, want 1", got)
	}
	if got := atomic.LoadInt32(&fake.closeCall); got != 1 {
		t.Fatalf("browser Close calls = %d, want 1 on the error path", got)
	}
	if sess.OK() {
		t.Fatal("session must not be OK after a failed browser login")
	}
}

func TestAuthBrowserNilControlKeepsDirectNetworkOption(t *testing.T) {
	fake := &recordingAuthBrowser{body: "<html>dashboard</html>"}
	var (
		gotControl   func(network, address string, c syscall.RawConn) error
		factoryCalls int32
	)
	installAuthBrowser(t, fake, &gotControl, &factoryCalls)

	cfg := browserAuthConfig(nil)
	sess, err := NewAuthSession(cfg, 0)
	if err != nil {
		t.Fatalf("NewAuthSession: %v", err)
	}
	if err := sess.Login(); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if got := atomic.LoadInt32(&factoryCalls); got != 1 {
		t.Fatalf("browser factory calls = %d, want 1", got)
	}
	if gotControl != nil {
		t.Fatal("nil cfg.DialControl must be forwarded as nil, not replaced by an allow-all hook")
	}
	if got := atomic.LoadInt32(&fake.closeCall); got != 1 {
		t.Fatalf("browser Close calls = %d, want 1", got)
	}
}

// TestFormLoginDialControlReachesSocket proves the login POST itself is gated:
// ClientWithDialControl only covers the public client, so a form login without
// this hook would be a second uncontrolled egress path.
func TestFormLoginDialControlReachesSocket(t *testing.T) {
	var hits, controlCalls int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		fmt.Fprint(w, "welcome")
	}))
	defer up.Close()

	control := func(_, _ string, _ syscall.RawConn) error {
		atomic.AddInt32(&controlCalls, 1)
		return nil
	}
	sess, err := NewAuthSession(AuthConfig{
		Type:         AuthForm,
		LoginURL:     up.URL,
		Username:     "user",
		Password:     "pass",
		DialControl:  control,
		SuccessMatch: "welcome",
	}, 0)
	if err != nil {
		t.Fatalf("NewAuthSession: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("login POST hits = %d, want 1", got)
	}
	if got := atomic.LoadInt32(&controlCalls); got == 0 {
		t.Fatal("dial control never reached the login POST socket")
	}
	if !sess.OK() {
		t.Fatal("session should be OK after a successful controlled login")
	}
}

// TestFormLoginNilControlKeepsDirectBehavior pins the dev path: no hook means
// the login client keeps http.DefaultTransport.
func TestFormLoginNilControlKeepsDirectBehavior(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "welcome")
	}))
	defer up.Close()

	sess, err := NewAuthSession(AuthConfig{
		Type:         AuthForm,
		LoginURL:     up.URL,
		Username:     "user",
		Password:     "pass",
		SuccessMatch: "welcome",
	}, 0)
	if err != nil {
		t.Fatalf("NewAuthSession with nil control: %v", err)
	}
	if tr, ok := sess.authClient.Transport.(*http.Transport); ok && tr.DialContext != nil {
		t.Fatal("nil control must not install a DialContext hook")
	}
}
