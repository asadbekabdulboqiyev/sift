package dashboard

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/asadbekabdulboqiyev/sift/internal/authz"
)

// TestStartRunRefusesMetadataAndLinkLocal proves the dashboard load-test
// endpoint cannot be used as a credential-theft SSRF: targets that resolve to a
// cloud instance-metadata service or a link-local address are refused before the
// engine bridge is called.
func TestStartRunRefusesMetadataAndLinkLocal(t *testing.T) {
	targets := []string{
		"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
		"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
		"http://169.254.170.2/v2/credentials",
		"http://100.100.100.200/latest/meta-data/",
		"http://[fe80::1]/",
		"http://[fd00:ec2::254]/latest/meta-data/",
	}
	for _, target := range targets {
		s := NewServer()
		var called bool
		s.SetCommandHandler(func(cmd string, args map[string]interface{}) {
			called = true
		})

		body := `{"target_url":"` + target + `","users":1,"duration_seconds":1}`
		req := httptest.NewRequest("POST", "/api/run/start", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("%s: status = %d, want 403", target, w.Code)
		}
		if called {
			t.Errorf("%s: command handler fired - the run must not start", target)
		}
		if ct := w.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("%s: Content-Type = %q, want application/json", target, ct)
		}
	}
}

// TestStartRunAllowsOrdinaryTargets keeps normal load tests working: literal
// loopback and public addresses are permitted (DNS-free, so the test does not
// depend on network access).
func TestStartRunAllowsOrdinaryTargets(t *testing.T) {
	targets := []string{
		"http://127.0.0.1:9/health",
		"http://93.184.216.34/",
	}
	for _, target := range targets {
		s := NewServer()
		var called bool
		s.SetCommandHandler(func(cmd string, args map[string]interface{}) {
			called = true
		})

		body := `{"target_url":"` + target + `","users":1,"duration_seconds":1}`
		req := httptest.NewRequest("POST", "/api/run/start", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200 (body: %s)", target, w.Code, w.Body.String())
		}
		if !called {
			t.Errorf("%s: command handler did not fire", target)
		}
	}
}

// TestLoadDashboardAssetDefaultsToEmbedded guards against a production binary
// serving UI assets from the working directory: a planted internal/dashboard
// copy must be ignored unless the developer opts in explicitly.
func TestLoadDashboardAssetDefaultsToEmbedded(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "internal", "dashboard"), 0o755); err != nil {
		t.Fatal(err)
	}
	planted := []byte("<script>alert('pwned')</script>")
	if err := os.WriteFile(filepath.Join(dir, "internal", "dashboard", "index.html"), planted, 0o644); err != nil {
		t.Fatal(err)
	}

	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chdir(wd); err != nil {
			t.Fatalf("restore working directory: %v", err)
		}
	}()

	t.Setenv("SIFT_DASHBOARD_DEV_ASSETS", "")
	fallback := []byte("<html>embedded</html>")
	if got := loadDashboardAsset("index.html", fallback); string(got) != string(fallback) {
		t.Errorf("loadDashboardAsset served planted asset %q, want the embedded fallback", got)
	}

	t.Setenv("SIFT_DASHBOARD_DEV_ASSETS", "1")
	if got := loadDashboardAsset("index.html", fallback); string(got) != string(planted) {
		t.Errorf("loadDashboardAsset with dev assets = %q, want the on-disk asset", got)
	}
}

// TestRunTargetClass proves the start-run refusal decision can be handed to the
// dial hook. Metadata keeps its class, loopback stays loopback, and a
// classification failure falls back to ClassPublic, which is fail-closed at the
// dial control.
func TestRunTargetClass(t *testing.T) {
	cases := []struct {
		name   string
		target string
		want   authz.Class
	}{
		{"loopback literal", "http://127.0.0.1:8080/", authz.ClassLoopback},
		{"metadata literal", "http://169.254.169.254/", authz.ClassMetadata},
		{"malformed target", "://not a url", authz.ClassPublic},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := RunTargetClass(tc.target); got != tc.want {
				t.Fatalf("RunTargetClass(%q) = %v, want %v", tc.target, got, tc.want)
			}
		})
	}
}
