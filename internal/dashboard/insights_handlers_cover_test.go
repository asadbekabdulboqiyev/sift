package dashboard

// Handler-level coverage for the insights routes that had none: bounty
// validate/status/verify-upload and X-Ray capabilities/correlate. Handlers are
// called directly, as in insights_leakage_test.go; route registration is
// asserted separately at the end of this file.

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/bounty"
	"github.com/asadbekabdulboqiyev/sift/internal/hostxray"
)

func isolateInsightsHandlerEnv(t *testing.T) {
	t.Helper()
	t.Setenv("SIFT_POLICY", filepath.Join(t.TempDir(), "no-policy.json"))
	t.Setenv("SIFT_ALLOW", "")
}

type insightsHandlerResponse struct {
	status int
	body   string
}

func callInsightsHandler(t *testing.T, handler func(*Server, http.ResponseWriter, *http.Request), method, path, body, contentType, origin string) insightsHandlerResponse {
	t.Helper()
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	handler(&Server{}, w, req)
	return insightsHandlerResponse{status: w.Code, body: w.Body.String()}
}

func decodeInsightsResponse(t *testing.T, resp insightsHandlerResponse) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(resp.body), &out); err != nil {
		t.Fatalf("decode response (status %d): %v; body=%s", resp.status, err, resp.body)
	}
	return out
}

func makeInsightsTestManifest(t *testing.T) bounty.Manifest {
	t.Helper()
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "report.md")
	scopePath := filepath.Join(dir, "scope.txt")
	if err := os.WriteFile(reportPath, []byte("# finding\n"), 0o600); err != nil {
		t.Fatalf("write report: %v", err)
	}
	if err := os.WriteFile(scopePath, []byte("example.test\n"), 0o600); err != nil {
		t.Fatalf("write scope: %v", err)
	}
	m, err := bounty.BuildManifest(bounty.PackageOptions{
		Program:    "QA Program",
		ReportPath: reportPath,
		ScopePath:  scopePath,
		CreatedAt:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	return m
}

func TestInsightsBountyValidateHandler(t *testing.T) {
	isolateInsightsHandlerEnv(t)

	t.Run("method guard", func(t *testing.T) {
		resp := callInsightsHandler(t, (*Server).handleInsightsBountyValidate, http.MethodGet,
			"/api/insights/bounty/validate", "", "", "")
		if resp.status != http.StatusMethodNotAllowed {
			t.Fatalf("status = %d, want 405; body=%s", resp.status, resp.body)
		}
	})

	t.Run("cross-origin guard", func(t *testing.T) {
		resp := callInsightsHandler(t, (*Server).handleInsightsBountyValidate, http.MethodPost,
			"/api/insights/bounty/validate", `{}`, "application/json", "https://evil.example")
		if resp.status != http.StatusForbidden {
			t.Fatalf("status = %d, want 403; body=%s", resp.status, resp.body)
		}
	})

	t.Run("malformed JSON", func(t *testing.T) {
		resp := callInsightsHandler(t, (*Server).handleInsightsBountyValidate, http.MethodPost,
			"/api/insights/bounty/validate", `{"manifest":`, "application/json", "")
		if resp.status != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body=%s", resp.status, resp.body)
		}
		out := decodeInsightsResponse(t, resp)
		if errText, _ := out["error"].(string); !strings.Contains(errText, "invalid JSON") {
			t.Fatalf("error = %v, want invalid JSON detail", out["error"])
		}
	})

	t.Run("missing manifest", func(t *testing.T) {
		resp := callInsightsHandler(t, (*Server).handleInsightsBountyValidate, http.MethodPost,
			"/api/insights/bounty/validate", `{"manifest":{}}`, "application/json", "")
		if resp.status != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body=%s", resp.status, resp.body)
		}
	})

	t.Run("digest mismatch is a failed verdict", func(t *testing.T) {
		m := makeInsightsTestManifest(t)
		m.PackageDigest = strings.Repeat("0", 64)
		body, err := json.Marshal(bountyValidateRequest{Manifest: m})
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		resp := callInsightsHandler(t, (*Server).handleInsightsBountyValidate, http.MethodPost,
			"/api/insights/bounty/validate", string(body), "application/json", "")
		if resp.status != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", resp.status, resp.body)
		}
		out := decodeInsightsResponse(t, resp)
		if out["verdict"] != bounty.VerdictFailed {
			t.Fatalf("verdict = %v, want %s", out["verdict"], bounty.VerdictFailed)
		}
	})

	t.Run("valid manifest", func(t *testing.T) {
		m := makeInsightsTestManifest(t)
		body, err := json.Marshal(bountyValidateRequest{Manifest: m})
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		resp := callInsightsHandler(t, (*Server).handleInsightsBountyValidate, http.MethodPost,
			"/api/insights/bounty/validate", string(body), "application/json", "")
		if resp.status != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", resp.status, resp.body)
		}
		out := decodeInsightsResponse(t, resp)
		if out["ok"] != true || out["verdict"] != bounty.VerdictUnverified {
			t.Fatalf("response = %v, want ok=true and verdict=unverified", out)
		}
		checks, ok := out["checks"].([]any)
		if !ok || len(checks) < 3 {
			t.Fatalf("checks = %v, want at least three results", out["checks"])
		}
	})
}

func TestInsightsBountyStatusHandler(t *testing.T) {
	isolateInsightsHandlerEnv(t)

	t.Run("method guard", func(t *testing.T) {
		resp := callInsightsHandler(t, (*Server).handleInsightsBountyStatus, http.MethodGet,
			"/api/insights/bounty/status", "", "", "")
		if resp.status != http.StatusMethodNotAllowed {
			t.Fatalf("status = %d, want 405; body=%s", resp.status, resp.body)
		}
	})

	t.Run("malformed JSON", func(t *testing.T) {
		resp := callInsightsHandler(t, (*Server).handleInsightsBountyStatus, http.MethodPost,
			"/api/insights/bounty/status", `{`, "application/json", "")
		if resp.status != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body=%s", resp.status, resp.body)
		}
		out := decodeInsightsResponse(t, resp)
		if errText, _ := out["error"].(string); !strings.Contains(errText, "invalid JSON") {
			t.Fatalf("error = %v, want invalid JSON detail", out["error"])
		}
	})

	t.Run("no events", func(t *testing.T) {
		resp := callInsightsHandler(t, (*Server).handleInsightsBountyStatus, http.MethodPost,
			"/api/insights/bounty/status", `{"events":[]}`, "application/json", "")
		if resp.status != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", resp.status, resp.body)
		}
		out := decodeInsightsResponse(t, resp)
		if out["state"] != "(none)" || out["events"] != float64(0) {
			t.Fatalf("response = %v, want state=(none) and events=0", out)
		}
	})

	t.Run("valid event chain", func(t *testing.T) {
		events := []bounty.Event{
			{
				At: "2026-01-01T00:00:00Z", Actor: "reporter", Role: bounty.RoleReporter,
				From: bounty.StateNone, To: bounty.StateSubmitted, Reason: "initial report",
			},
			{
				At: "2026-01-02T00:00:00Z", Actor: "triager", Role: bounty.RoleTriager,
				From: bounty.StateSubmitted, To: bounty.StateTriaged, Reason: "reviewed evidence",
			},
		}
		body, err := json.Marshal(bountyStatusRequest{Events: events})
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		resp := callInsightsHandler(t, (*Server).handleInsightsBountyStatus, http.MethodPost,
			"/api/insights/bounty/status", string(body), "application/json", "")
		if resp.status != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", resp.status, resp.body)
		}
		out := decodeInsightsResponse(t, resp)
		if out["state"] != string(bounty.StateTriaged) || out["events"] != float64(2) {
			t.Fatalf("response = %v, want state=triaged and events=2", out)
		}
		if out["last"] == nil {
			t.Fatal("response has no last event")
		}
	})

	t.Run("invalid event chain", func(t *testing.T) {
		body := `{"events":[{"at":"2026-01-01T00:00:00Z","actor":"reporter","role":"reporter","from":"","to":"rewarded","reason":"not allowed"}]}`
		resp := callInsightsHandler(t, (*Server).handleInsightsBountyStatus, http.MethodPost,
			"/api/insights/bounty/status", body, "application/json", "")
		if resp.status != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body=%s", resp.status, resp.body)
		}
	})
}

func TestInsightsXRayCapabilitiesHandler(t *testing.T) {
	isolateInsightsHandlerEnv(t)

	resp := callInsightsHandler(t, (*Server).handleInsightsXRayCapabilities, http.MethodGet,
		"/api/insights/xray/capabilities", "", "", "")
	if resp.status != http.StatusOK {
		t.Fatalf("GET status = %d, want 200; body=%s", resp.status, resp.body)
	}
	out := decodeInsightsResponse(t, resp)
	if out["ok"] != true || out["capabilities"] == nil {
		t.Fatalf("response = %v, want ok=true and capabilities", out)
	}

	resp = callInsightsHandler(t, (*Server).handleInsightsXRayCapabilities, http.MethodPost,
		"/api/insights/xray/capabilities", "", "", "")
	if resp.status != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d, want 405; body=%s", resp.status, resp.body)
	}
}

func TestInsightsXRayCorrelateHandler(t *testing.T) {
	isolateInsightsHandlerEnv(t)

	t.Run("method guard", func(t *testing.T) {
		resp := callInsightsHandler(t, (*Server).handleInsightsXRayCorrelate, http.MethodGet,
			"/api/insights/xray/correlate", "", "", "")
		if resp.status != http.StatusMethodNotAllowed {
			t.Fatalf("status = %d, want 405; body=%s", resp.status, resp.body)
		}
	})

	t.Run("cross-origin guard", func(t *testing.T) {
		resp := callInsightsHandler(t, (*Server).handleInsightsXRayCorrelate, http.MethodPost,
			"/api/insights/xray/correlate", `{}`, "application/json", "https://evil.example")
		if resp.status != http.StatusForbidden {
			t.Fatalf("status = %d, want 403; body=%s", resp.status, resp.body)
		}
	})

	t.Run("malformed JSON", func(t *testing.T) {
		resp := callInsightsHandler(t, (*Server).handleInsightsXRayCorrelate, http.MethodPost,
			"/api/insights/xray/correlate", `{"samples":`, "application/json", "")
		if resp.status != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body=%s", resp.status, resp.body)
		}
		out := decodeInsightsResponse(t, resp)
		if errText, _ := out["error"].(string); !strings.Contains(errText, "invalid JSON") {
			t.Fatalf("error = %v, want invalid JSON detail", out["error"])
		}
	})

	t.Run("missing samples and signals", func(t *testing.T) {
		resp := callInsightsHandler(t, (*Server).handleInsightsXRayCorrelate, http.MethodPost,
			"/api/insights/xray/correlate", `{"samples":[]}`, "application/json", "")
		if resp.status != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body=%s", resp.status, resp.body)
		}
	})

	t.Run("invalid window", func(t *testing.T) {
		resp := callInsightsHandler(t, (*Server).handleInsightsXRayCorrelate, http.MethodPost,
			"/api/insights/xray/correlate", `{"samples":[{}],"signals":[{}],"window":"not-a-duration"}`, "application/json", "")
		if resp.status != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body=%s", resp.status, resp.body)
		}
		out := decodeInsightsResponse(t, resp)
		if errText, _ := out["error"].(string); !strings.Contains(errText, "invalid window") {
			t.Fatalf("error = %v, want invalid window detail", out["error"])
		}
	})

	t.Run("happy path", func(t *testing.T) {
		ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		body, err := json.Marshal(xrayCorrelateRequest{
			Samples: []hostxray.Sample{{Timestamp: ts, Source: "test"}},
			Signals: []hostxray.Signal{{Timestamp: ts, RPS: 100, P99Ms: 20}},
			Window:  "5s",
		})
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		resp := callInsightsHandler(t, (*Server).handleInsightsXRayCorrelate, http.MethodPost,
			"/api/insights/xray/correlate", string(body), "application/json", "")
		if resp.status != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", resp.status, resp.body)
		}
		out := decodeInsightsResponse(t, resp)
		if out["ok"] != true {
			t.Fatalf("ok = %v, want true", out["ok"])
		}
		if _, present := out["indicators"]; !present {
			t.Fatalf("response has no indicators field: %v", out)
		}
	})
}

func postInsightsVerifyUpload(t *testing.T, fields map[string]string, uploads []insightsTestUpload) (int, string) {
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
			t.Fatalf("create form file %s: %v", up.filename, err)
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
	req.Header.Set("Origin", "http://"+req.Host)
	w := httptest.NewRecorder()
	(&Server{}).handleInsightsBountyVerifyUpload(w, req)
	return w.Code, w.Body.String()
}

func TestInsightsBountyVerifyUploadHandlerMissingFields(t *testing.T) {
	isolateInsightsHandlerEnv(t)

	t.Run("no manifest and no files", func(t *testing.T) {
		status, body := postInsightsVerifyUpload(t, nil, nil)
		if status != http.StatusBadRequest || !strings.Contains(body, "manifest JSON is required") {
			t.Fatalf("status = %d body = %s, want 400 with missing manifest detail", status, body)
		}
	})

	t.Run("file with wrong name does not supply the manifest", func(t *testing.T) {
		status, body := postInsightsVerifyUpload(t, nil, []insightsTestUpload{
			{field: "wrong_field", filename: "evil.json", content: `{"schema_version":"bounty/v1"}`},
		})
		if status != http.StatusBadRequest || !strings.Contains(body, "manifest JSON is required") {
			t.Fatalf("status = %d body = %s, want 400 with missing manifest detail", status, body)
		}
	})

	t.Run("invalid multipart body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/insights/bounty/verify-upload", strings.NewReader("not multipart"))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		(&Server{}).handleInsightsBountyVerifyUpload(w, req)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid multipart form") {
			t.Fatalf("status = %d body = %s, want 400 with invalid multipart detail", w.Code, w.Body.String())
		}
	})

	t.Run("invalid manifest JSON", func(t *testing.T) {
		status, body := postInsightsVerifyUpload(t, map[string]string{"manifest": "{"}, nil)
		if status != http.StatusBadRequest || !strings.Contains(body, "invalid manifest JSON") {
			t.Fatalf("status = %d body = %s, want 400 with invalid manifest detail", status, body)
		}
	})
}

func TestInsightsBountyVerifyUploadHandlerGuardsAndMissingArtifact(t *testing.T) {
	isolateInsightsHandlerEnv(t)

	t.Run("method guard", func(t *testing.T) {
		resp := callInsightsHandler(t, (*Server).handleInsightsBountyVerifyUpload, http.MethodGet,
			"/api/insights/bounty/verify-upload", "", "", "")
		if resp.status != http.StatusMethodNotAllowed {
			t.Fatalf("status = %d, want 405; body=%s", resp.status, resp.body)
		}
	})

	t.Run("cross-origin guard", func(t *testing.T) {
		resp := callInsightsHandler(t, (*Server).handleInsightsBountyVerifyUpload, http.MethodPost,
			"/api/insights/bounty/verify-upload", "", "application/json", "https://evil.example")
		if resp.status != http.StatusForbidden {
			t.Fatalf("status = %d, want 403; body=%s", resp.status, resp.body)
		}
	})

	t.Run("declared artifact without an upload is rejected", func(t *testing.T) {
		m := makeInsightsTestManifest(t)
		manifestJSON, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("marshal manifest: %v", err)
		}
		// No artifact files are uploaded, so the verifier cannot find the
		// manifest-declared report.md and scope.txt paths.
		status, body := postInsightsVerifyUpload(t, map[string]string{"manifest": string(manifestJSON)}, nil)
		if status != http.StatusConflict {
			t.Fatalf("status = %d, want 409 (verdict failed); body=%s", status, body)
		}
		// The contract is a structured failed verdict, not a generic bad
		// request: the manifest parsed, so the missing artifacts must surface
		// as check failures with reasons. Accepting 400 here would hide a
		// regression that collapses this into a malformed-form error.
		var out struct {
			OK      bool   `json:"ok"`
			Verdict string `json:"verdict"`
			Report  struct {
				Reasons []string `json:"reasons"`
				Checks  []struct {
					Name   string `json:"name"`
					Status string `json:"status"`
				} `json:"checks"`
			} `json:"report"`
		}
		if err := json.Unmarshal([]byte(body), &out); err != nil {
			t.Fatalf("decode 409 body: %v; body=%s", err, body)
		}
		if out.OK || out.Verdict != "failed" {
			t.Errorf("verdict = %q, ok = %v; want failed/false", out.Verdict, out.OK)
		}
		failed := map[string]bool{}
		for _, check := range out.Report.Checks {
			if check.Status == "fail" {
				failed[check.Name] = true
			}
		}
		if !failed["artifact:report"] || !failed["artifact:scope"] {
			t.Errorf("missing artifact checks: %v; body=%s", failed, body)
		}
		if len(out.Report.Reasons) < 2 {
			t.Errorf("report.reasons = %d entries, want at least 2; body=%s", len(out.Report.Reasons), body)
		}
	})
}

func TestInsightsBountyVerifyUploadHandlerHappyPath(t *testing.T) {
	isolateInsightsHandlerEnv(t)

	m := makeInsightsTestManifest(t)
	manifestJSON, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}

	// The manifest arrives as an uploaded file whose basename the handler
	// recognizes; report.md and scope.txt supply the declared artifacts.
	status, body := postInsightsVerifyUpload(t, nil, []insightsTestUpload{
		{field: "wrong_field", filename: "bounty-package.json", content: string(manifestJSON)},
		{field: "report", filename: "report.md", content: "# finding\n"},
		{field: "scope", filename: "scope.txt", content: "example.test\n"},
	})
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", status, body)
	}
	out := decodeInsightsResponse(t, insightsHandlerResponse{status: status, body: body})
	if out["ok"] != true || out["verdict"] != bounty.VerdictUnverified {
		t.Fatalf("response = %v, want ok=true and verdict=unverified", out)
	}
	if out["uploaded_artifacts"] != float64(3) {
		t.Fatalf("uploaded_artifacts = %v, want 3", out["uploaded_artifacts"])
	}
}

func TestInsightsRoutesRegistered(t *testing.T) {
	want := []string{
		"/api/insights/bounty/validate",
		"/api/insights/bounty/status",
		"/api/insights/bounty/verify-upload",
		"/api/insights/xray/capabilities",
		"/api/insights/xray/correlate",
	}
	registered := make(map[string]bool)
	for _, route := range insightsRoutes() {
		registered[route.path] = true
	}
	for _, path := range want {
		if !registered[path] {
			t.Errorf("insights route %s is not registered", path)
		}
	}
}
