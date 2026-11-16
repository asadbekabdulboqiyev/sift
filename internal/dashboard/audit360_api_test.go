package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAudit360StartMethodAndOriginGuards(t *testing.T) {
	s := NewServer()

	req := httptest.NewRequest(http.MethodGet, "/api/audit-360", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /api/audit-360 status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}

	// Cross-origin POST must be rejected before body/validation processing.
	req = httptest.NewRequest(http.MethodPost, "/api/audit-360", strings.NewReader(`{}`))
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Host", "127.0.0.1:8888")
	w = httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-origin POST status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestAudit360StartRejectsInvalidAndUnauthorizedRequests(t *testing.T) {
	s := NewServer()

	// Invalid JSON
	req := httptest.NewRequest(http.MethodPost, "/api/audit-360", strings.NewReader(`{`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid JSON status = %d, want %d (body=%s)", w.Code, http.StatusBadRequest, w.Body.String())
	}

	// Missing target_url -> validation error (bad request)
	req = httptest.NewRequest(http.MethodPost, "/api/audit-360", strings.NewReader(`{"mode":"passive"}`))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("missing target status = %d, want %d (body=%s)", w.Code, http.StatusBadRequest, w.Body.String())
	}

	// Invalid mode -> validation error.
	req = httptest.NewRequest(http.MethodPost, "/api/audit-360", strings.NewReader(`{"target_url":"http://127.0.0.1:8090","mode":"weird"}`))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid mode status = %d, want %d (body=%s)", w.Code, http.StatusBadRequest, w.Body.String())
	}

	// Standard mode requires explicit authorization confirmation.
	req = httptest.NewRequest(http.MethodPost, "/api/audit-360", strings.NewReader(`{"target_url":"http://127.0.0.1:8090","mode":"standard","authorized":false}`))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("standard without authorization status = %d, want %d (body=%s)", w.Code, http.StatusForbidden, w.Body.String())
	}
}

func TestAudit360StatusGuardsAndNotFound(t *testing.T) {
	s := NewServer()

	req := httptest.NewRequest(http.MethodPost, "/api/audit-360/status?job_id=x", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status endpoint = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/audit-360/status", nil)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("missing job_id status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/audit-360/status?job_id=missing", nil)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown job status = %d, want %d", w.Code, http.StatusNotFound)
	}
	var payload map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode status response: %v", err)
	}
	if ok, _ := payload["ok"].(bool); ok {
		t.Fatalf("unknown job ok=true, want false")
	}
}

func TestAudit360StreamGuards(t *testing.T) {
	s := NewServer()

	req := httptest.NewRequest(http.MethodPost, "/api/audit-360/stream?job_id=x", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST stream = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/audit-360/stream", nil)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("missing job_id stream = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestAudit360DownloadGuards(t *testing.T) {
	s := NewServer()

	req := httptest.NewRequest(http.MethodPost, "/api/audit-360/download?job_id=x&format=json", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST download = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}

	// Cross-origin GET must be rejected.
	req = httptest.NewRequest(http.MethodGet, "/api/audit-360/download?job_id=x&format=json", nil)
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Host", "127.0.0.1:8888")
	w = httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-origin download = %d, want %d", w.Code, http.StatusForbidden)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/audit-360/download?format=json", nil)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("missing job_id download = %d, want %d", w.Code, http.StatusBadRequest)
	}

	// Missing/unknown job is reported before format-specific rendering.
	req = httptest.NewRequest(http.MethodGet, "/api/audit-360/download?job_id=missing&format=xml", nil)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("missing job (any format) download = %d, want %d", w.Code, http.StatusNotFound)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/audit-360/download?job_id=missing&format=json", nil)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("missing job download = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestAudit360Helpers(t *testing.T) {
	s := NewServer()
	if got := s.demoStoreTargetURL(); got == "" {
		t.Fatal("demoStoreTargetURL returned empty string")
	}

	s.SetVersion("1.2.3")
	if got := s.versionOrDefault(); got != "1.2.3" {
		t.Fatalf("versionOrDefault() = %q, want 1.2.3", got)
	}

	if got := sanitizeAudit360DownloadID(""); got != "report" {
		t.Fatalf("sanitizeAudit360DownloadID(empty) = %q, want report", got)
	}
	if got := sanitizeAudit360DownloadID("sift360/abc:def"); got != "sift360_abc_def" {
		t.Fatalf("sanitizeAudit360DownloadID = %q, want sift360_abc_def", got)
	}
}
