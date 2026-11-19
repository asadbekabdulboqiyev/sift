//go:build integration

package engine

import (
	"bytes"
	"context"
	"github.com/asadbekabdulboqiyev/sift/internal/config"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRunWithTypedNilCaptureDoesNotPanic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sc := &config.Scenario{
		Name: "typed-nil-capture",
		Profile: config.Profile{
			Type:     config.ProfileSteady,
			Users:    1,
			Duration: 1,
			Timeout:  2,
		},
		Steps: []config.Step{{Name: "health", Method: "GET", URL: srv.URL}},
	}

	eng, err := New(sc)
	if err != nil {
		t.Fatal(err)
	}

	var typedNil *BufferCapture
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := eng.Run(ctx, RunOptions{Quiet: true, Capture: typedNil}); err != nil {
		t.Fatalf("run with typed-nil capture failed: %v", err)
	}
}

func TestEngineRunWithCapture(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("health-ok-body"))
	}))
	defer srv.Close()

	sc := &config.Scenario{
		Name: "capture-test",
		Profile: config.Profile{
			Type:     config.ProfileSteady,
			Users:    2,
			Duration: 1,
			Timeout:  2,
		},
		Steps: []config.Step{{Name: "health", Method: "GET", URL: srv.URL + "/health"}},
	}

	eng, err := New(sc)
	if err != nil {
		t.Fatal(err)
	}

	sink := NewBufferCapture(5, 1024)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := eng.Run(ctx, RunOptions{Quiet: true, Capture: sink}); err != nil {
		t.Fatal(err)
	}

	kept, _ := sink.Count()
	if kept == 0 {
		t.Fatal("expected at least one captured response")
	}

	var out bytes.Buffer
	if err := sink.Render(&out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "health-ok-body") {
		t.Errorf("captured body missing:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "step=health") {
		t.Errorf("step name missing:\n%s", out.String())
	}
}

func TestPoolGivesUniqueValues(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen[string(body)] = true
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sc := &config.Scenario{
		Name: "pool-test",
		Profile: config.Profile{
			Type: config.ProfileSteady, Users: 2, Duration: 1, Timeout: 2,
		},
		Steps: []config.Step{{
			Name: "reg", Method: "POST", URL: srv.URL,
			Body: `{"email":"{{pool}}"}`,
		}},
	}

	eng, err := New(sc)
	if err != nil {
		t.Fatal(err)
	}
	pool := []string{"p1@x.test", "p2@x.test", "p3@x.test"}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := eng.Run(ctx, RunOptions{Quiet: true, Pool: pool}); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seen) == 0 {
		t.Fatal("no requests captured")
	}
	for v := range seen {
		valid := false
		for _, p := range pool {
			if v == `{"email":"`+p+`"}` {
				valid = true
				break
			}
		}
		if !valid {
			t.Errorf("unexpected body %q — not from pool", v)
		}
	}
	if len(seen) < 2 {
		t.Errorf("only %d distinct payloads seen, want >=2 cycling through pool", len(seen))
	}
}
