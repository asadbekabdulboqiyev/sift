package dashboard

// Coverage for the three untested upload helpers in insights_helpers.go:
// copyFileTo, readUploadedText and readUploadedFileByName. The sibling helpers
// (sanitizeUploadPath, saveMultipartFile) already have coverage elsewhere.

import (
	"bytes"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/asadbekabdulboqiyev/sift/internal/bounty"
)

func TestCopyFileToRejectsEscapingDestination(t *testing.T) {
	base := t.TempDir()
	src := filepath.Join(base, "source.txt")
	if err := os.WriteFile(src, []byte("payload"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	for _, tc := range []struct {
		name string
		dst  string
	}{
		{"parent", filepath.Join(base, "..", "sift-copy-escape-parent.txt")},
		{"nested", filepath.Join(base, "sub", "..", "..", "sift-copy-escape-nested.txt")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() { _ = os.Remove(tc.dst) }()
			err := copyFileTo(src, base, tc.dst)
			if err == nil {
				t.Fatal("copyFileTo accepted a destination outside baseDir")
			}
			if !strings.Contains(err.Error(), "escapes temp directory") {
				t.Fatalf("error = %q, want a path-escape rejection", err)
			}
			if _, statErr := os.Stat(tc.dst); !os.IsNotExist(statErr) {
				t.Fatalf("escape destination was created: stat error = %v", statErr)
			}
		})
	}
}

func TestCopyFileToRejectsOversizedSource(t *testing.T) {
	// bounty.MaxArtifactBytes is a compile-time constant (256 MiB), so the cap
	// is exercised with a sparse source file and a destination symlinked to
	// os.DevNull. That keeps the test fast and avoids a 256 MiB on-disk fixture.
	base := t.TempDir()
	src := filepath.Join(base, "source.bin")
	if err := os.WriteFile(src, nil, 0o600); err != nil {
		t.Fatalf("create source: %v", err)
	}
	if err := os.Truncate(src, bounty.MaxArtifactBytes+1); err != nil {
		t.Fatalf("extend source: %v", err)
	}
	dst := filepath.Join(base, "sink")
	if err := os.Symlink(os.DevNull, dst); err != nil {
		t.Fatalf("symlink dev null: %v", err)
	}

	err := copyFileTo(src, base, dst)
	if err == nil {
		t.Fatal("copyFileTo accepted a file above the artifact cap")
	}
	want := fmt.Sprintf("%d byte limit", bounty.MaxArtifactBytes)
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %q, want it to contain %q", err, want)
	}
}

func TestCopyFileToRejectsMissingSource(t *testing.T) {
	base := t.TempDir()
	dst := filepath.Join(base, "out", "copy.txt")

	err := copyFileTo(filepath.Join(base, "missing.txt"), base, dst)
	if err == nil {
		t.Fatal("copyFileTo accepted a missing source")
	}
	if !os.IsNotExist(err) {
		t.Fatalf("error = %v (%T), want a not-exist error", err, err)
	}
	if _, statErr := os.Stat(dst); !os.IsNotExist(statErr) {
		t.Fatalf("destination was created for a missing source: %v", statErr)
	}
}

func TestCopyFileToCopiesContentWithPrivateMode(t *testing.T) {
	base := t.TempDir()
	src := filepath.Join(base, "source.txt")
	content := []byte("trusted artifact bytes\n")
	if err := os.WriteFile(src, content, 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	dst := filepath.Join(base, "nested", "dir", "copy.txt")

	if err := copyFileTo(src, base, dst); err != nil {
		t.Fatalf("copyFileTo: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read destination: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("copied content = %q, want %q", got, content)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(dst)
		if err != nil {
			t.Fatalf("stat destination: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("destination mode = %o, want 600", perm)
		}
	}
}

type insightsTestUpload struct {
	field    string
	filename string
	content  string
}

// parseInsightsUploadRequest builds a parsed multipart request for the two
// readUploaded* helpers. The caller owns the returned request's temp files.
func parseInsightsUploadRequest(t *testing.T, fields map[string]string, uploads []insightsTestUpload) *http.Request {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatalf("write field %s: %v", k, err)
		}
	}
	for _, up := range uploads {
		fw, err := mw.CreateFormFile(up.field, up.filename)
		if err != nil {
			t.Fatalf("create form file %s/%s: %v", up.field, up.filename, err)
		}
		if _, err := fw.Write([]byte(up.content)); err != nil {
			t.Fatalf("write form file %s: %v", up.filename, err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/insights/bounty/verify-upload", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if err := req.ParseMultipartForm(1 << 20); err != nil {
		t.Fatalf("ParseMultipartForm: %v", err)
	}
	t.Cleanup(func() {
		if req.MultipartForm != nil {
			_ = req.MultipartForm.RemoveAll()
		}
	})
	return req
}

func TestReadUploadedTextFieldHandling(t *testing.T) {
	t.Run("missing field", func(t *testing.T) {
		req := parseInsightsUploadRequest(t, map[string]string{"other": "value"}, nil)
		if got := readUploadedText(req, "manifest_file"); got != "" {
			t.Fatalf("readUploadedText(missing) = %q, want empty", got)
		}
	})

	t.Run("trims content", func(t *testing.T) {
		req := parseInsightsUploadRequest(t, nil, []insightsTestUpload{
			{field: "manifest_file", filename: "manifest.json", content: "  {\"schema_version\":\"bounty/v1\"}\n\n"},
		})
		want := `{"schema_version":"bounty/v1"}`
		if got := readUploadedText(req, "manifest_file"); got != want {
			t.Fatalf("readUploadedText = %q, want %q", got, want)
		}
	})

	t.Run("caps content", func(t *testing.T) {
		big := strings.Repeat("x", (4<<20)+16)
		req := parseInsightsUploadRequest(t, nil, []insightsTestUpload{
			{field: "manifest_file", filename: "manifest.txt", content: big},
		})
		got := readUploadedText(req, "manifest_file")
		if len(got) != 4<<20 {
			t.Fatalf("readUploadedText length = %d, want %d", len(got), 4<<20)
		}
	})
}

func TestReadUploadedFileByNameMatchesBasenameAndCaps(t *testing.T) {
	const manifestName = "bounty-package.json"
	validManifest := `{"schema_version":"bounty/v1"}`

	t.Run("matches uploaded basename", func(t *testing.T) {
		req := parseInsightsUploadRequest(t, nil, []insightsTestUpload{
			{field: "wrong_field", filename: manifestName, content: validManifest},
		})
		if got := readUploadedFileByName(req, manifestName); got != validManifest {
			t.Fatalf("readUploadedFileByName = %q, want %q", got, validManifest)
		}
	})

	t.Run("crafted filename with matching basename is accepted", func(t *testing.T) {
		// The helper intentionally matches on filepath.Base only, never on the
		// supplied path: the path is not used as a filesystem destination here.
		req := parseInsightsUploadRequest(t, nil, []insightsTestUpload{
			{field: "wrong_field", filename: "/etc/attacker/" + manifestName, content: validManifest},
		})
		if got := readUploadedFileByName(req, manifestName); got != validManifest {
			t.Fatalf("crafted filename with matching basename = %q, want %q", got, validManifest)
		}
	})

	t.Run("different filename and missing name", func(t *testing.T) {
		req := parseInsightsUploadRequest(t, nil, []insightsTestUpload{
			{field: "other", filename: "evil.json", content: validManifest},
		})
		if got := readUploadedFileByName(req, manifestName); got != "" {
			t.Fatalf("mismatched basename returned %q, want empty", got)
		}
		if got := readUploadedFileByName(req, "missing.json"); got != "" {
			t.Fatalf("missing name returned %q, want empty", got)
		}
	})

	t.Run("caps content", func(t *testing.T) {
		big := strings.Repeat("z", (4<<20)+16)
		req := parseInsightsUploadRequest(t, nil, []insightsTestUpload{
			{field: "other", filename: manifestName, content: big},
		})
		if got := readUploadedFileByName(req, manifestName); len(got) != 4<<20 {
			t.Fatalf("capped length = %d, want %d", len(got), 4<<20)
		}
	})
}

func TestInsightsXRaySmallHelpers(t *testing.T) {
	t.Run("containsStr", func(t *testing.T) {
		ss := []string{"cpu", "memory"}
		if !containsStr(ss, "memory") {
			t.Fatal("containsStr missed an existing element")
		}
		if containsStr(ss, "network") {
			t.Fatal("containsStr reported a missing element")
		}
		if containsStr(nil, "cpu") {
			t.Fatal("containsStr(nil) reported a match")
		}
	})

	t.Run("removeStr", func(t *testing.T) {
		ss := []string{"cpu", "memory", "network", "memory"}
		got := removeStr(ss, "memory")
		if len(got) != 2 || got[0] != "cpu" || got[1] != "network" {
			t.Fatalf("removeStr = %v, want [cpu network]", got)
		}
		if got := removeStr([]string{"cpu"}, "disk"); len(got) != 1 || got[0] != "cpu" {
			t.Fatalf("removeStr(no match) = %v, want [cpu]", got)
		}
		if got := removeStr(nil, "cpu"); len(got) != 0 {
			t.Fatalf("removeStr(nil) = %v, want empty", got)
		}
	})

	t.Run("guessResourceUnit", func(t *testing.T) {
		for _, tc := range []struct{ name, want string }{
			{"cpu", "percent"},
			{"memory", "percent"},
			{"network", "percent"},
			{"memory_growth", "percent"},
			{"connections", "count"},
			{"server_response_time", "ms"},
			{"unknown", ""},
			{"", ""},
		} {
			if got := guessResourceUnit(tc.name); got != tc.want {
				t.Errorf("guessResourceUnit(%q) = %q, want %q", tc.name, got, tc.want)
			}
		}
	})
}
