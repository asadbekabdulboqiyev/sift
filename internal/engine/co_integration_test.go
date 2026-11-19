//go:build integration

package engine

import (
	"context"
	"github.com/asadbekabdulboqiyev/sift/internal/config"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// End to end: a paced run whose single worker cannot keep up reports a much
// higher average latency with correction enabled than without.
func TestCoordinatedOmissionInflation(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(40 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer slow.Close()

	run := func(co bool) time.Duration {
		sc := &config.Scenario{
			Name: "co-e2e",
			Profile: config.Profile{
				Users:               1,
				Duration:            3,
				RPS:                 200, // wants 200/s; one worker can do ~25/s
				Timeout:             5,
				CoordinatedOmission: co,
			},
			Steps: []config.Step{{Name: "hit", Method: "GET", URL: slow.URL + "/"}},
		}
		if err := sc.Normalize(); err != nil {
			t.Fatal(err)
		}
		eng, err := New(sc)
		if err != nil {
			t.Fatal(err)
		}
		tel, err := eng.Run(context.Background(), RunOptions{Quiet: true})
		if err != nil {
			t.Fatal(err)
		}
		return tel.Overall.Latency.Avg()
	}

	plain := run(false)
	corrected := run(true)
	t.Logf("avg latency: plain=%v corrected=%v", plain, corrected)

	if plain < 30*time.Millisecond {
		t.Errorf("plain avg = %v, want ~40ms (server sleep)", plain)
	}
	if corrected <= plain*3 {
		t.Errorf("corrected avg = %v, want > 3x plain (%v) — coordinated omission not corrected", corrected, plain)
	}
}
