package dashboard

// insights_artifact_path_test.go — the bounty verify-upload handler must not
// turn a manifest-declared artifact path into a filesystem probe. The manifest
// arrives in the request body, so art.Path is attacker-controlled; joining it
// onto the request temp directory and calling os.Stat on the result reported
// through "uploaded_artifacts" whether an arbitrary file on the host exists.

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// postBountyVerifyUpload posts a manifest (plus optional uploads) to the bounty
// verify-upload endpoint and returns the decoded JSON body.
func postBountyVerifyUpload(t *testing.T, manifest string, uploads map[string]string) (int, map[string]any) {
	t.Helper()

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if err := mw.WriteField("manifest", manifest); err != nil {
		t.Fatalf("write manifest field: %v", err)
	}
	for name, content := range uploads {
		fw, err := mw.CreateFormFile(name, name)
		if err != nil {
			t.Fatalf("create form file %s: %v", name, err)
		}
		if _, err := fw.Write([]byte(content)); err != nil {
			t.Fatalf("write form file %s: %v", name, err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/insights/bounty/verify-upload", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Origin", "http://"+req.Host)
	w := httptest.NewRecorder()
	NewServer().serveApp(w, req)

	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response (status %d): %v; body=%s", w.Code, err, w.Body.String())
	}
	return w.Code, out
}

// TestBountyVerifyUploadRejectsEscapingArtifactPath is the regression test for
// the artifact path oracle. A manifest artifact of "../<name>" resolves to a
// file the handler's temp directory does not contain; before the fix the
// handler os.Stat'ed it, recorded it in the saved map, and reported
// uploaded_artifacts=1 — proving the file exists. It must report 0 instead.
func TestBountyVerifyUploadRejectsEscapingArtifactPath(t *testing.T) {
	// The handler creates its temp dir directly under os.TempDir(), so a single
	// ".." climbs back into it. Placing the sentinel there makes the probe
	// deterministic on every platform.
	sentinel, err := os.CreateTemp("", "sift-l1-oracle-*")
	if err != nil {
		t.Fatalf("create sentinel: %v", err)
	}
	sentinelName := filepath.Base(sentinel.Name())
	if _, err := sentinel.WriteString("outside the upload directory\n"); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}
	if err := sentinel.Close(); err != nil {
		t.Fatalf("close sentinel: %v", err)
	}
	defer os.Remove(sentinel.Name())

	manifest := `{"schema_version":"1","artifacts":[{"role":"bundle","path":"../` + sentinelName + `","size":32,"sha256":"` +
		"0000000000000000000000000000000000000000000000000000000000000000" + `"}]}`

	_, out := postBountyVerifyUpload(t, manifest, nil)

	got, ok := out["uploaded_artifacts"]
	if !ok {
		t.Fatalf("response has no uploaded_artifacts field: %v", out)
	}
	n, ok := got.(float64)
	if !ok {
		t.Fatalf("uploaded_artifacts = %v (%T), want a number", got, got)
	}
	if n != 0 {
		t.Fatalf("uploaded_artifacts = %v, want 0: a traversal artifact path was resolved against the host filesystem", n)
	}
}

// TestBountyVerifyUploadStillResolvesUploadedArtifact pins the behaviour the
// oracle fix must not break: a plain relative artifact path that matches an
// uploaded file is still counted.
func TestBountyVerifyUploadStillResolvesUploadedArtifact(t *testing.T) {
	manifest := `{"schema_version":"1","artifacts":[{"role":"bundle","path":"bundle.json","size":9,"sha256":"` +
		"0000000000000000000000000000000000000000000000000000000000000000" + `"}]}`

	_, out := postBountyVerifyUpload(t, manifest, map[string]string{"bundle": "not a bundle"})

	got, ok := out["uploaded_artifacts"]
	if !ok {
		t.Fatalf("response has no uploaded_artifacts field: %v", out)
	}
	n, ok := got.(float64)
	if !ok {
		t.Fatalf("uploaded_artifacts = %v (%T), want a number", got, got)
	}
	if n != 1 {
		t.Fatalf("uploaded_artifacts = %v, want 1: an uploaded artifact with a safe relative path must still resolve", n)
	}
}
