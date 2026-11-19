package engine

import (
	"io"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/asadbekabdulboqiyev/sift/internal/config"
)

// prefillPool opens n connections to url through the shared transport with
// bounded concurrency and leaves them idle in the pool. It exists because the
// 10k-user start burst would otherwise overwhelm the OS listen backlog on
// localhost (macOS somaxconn=128 → RST → connection_error), not because of
// any engine defect. Returns the number of connections successfully pooled.
func prefillPool(t testing.TB, e *Engine, url string, n, concurrency int) int {
	t.Helper()
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var pooled atomic.Int64
	for i := 0; i < n; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			resp, err := e.client.Get(url)
			if err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			pooled.Add(1)
		}()
	}
	wg.Wait()
	t.Logf("transport pool pre-filled with %d/%d idle connections", pooled.Load(), n)
	return int(pooled.Load())
}

// powerTestUsers returns the virtual-user burst size for the loopback target in
// the current test binary. Bare builds use the calibrated tiers (10k on Linux,
// 2k elsewhere). Instrumented builds — `-race` or `-cover`/`-coverpkg` — scale
// down to 500 users: those modes stretch the process's effective concurrency
// window, and a burst that a bare build absorbs into a 128-entry loopback
// backlog is refused once instrumentation widens the window (measured ~20.5% of
// dials refused on macOS with both flags on). The concurrency-correctness
// assertions this test makes are still exercised at 500 users: they prove lock
// correctness, broad progress and failure-class separation, not absolute
// throughput.
func powerTestUsers() int {
	users := 10_000
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		users = 2_000
	}
	if buildInstrumented() {
		return 500
	}
	return users
}

// TestPowerPrecreatedJarsAreDistinct verifies pre-createJars fills every slot
// with an independent jar/client pair and the fast path returns them without
// rebuilding.
func TestPowerPrecreatedJarsAreDistinct(t *testing.T) {
	e, err := New(&config.Scenario{
		Name:    "precreate",
		Profile: config.Profile{Users: 4, Duration: 1, Timeout: 5},
		Steps:   []config.Step{{Name: "s", URL: "http://localhost/"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	e.precreateJars(4)

	if len(e.cookieJars) != 4 || len(e.jarClients) != 4 {
		t.Fatalf("after precreateJars(4): jars=%d clients=%d, want 4/4",
			len(e.cookieJars), len(e.jarClients))
	}
	for i := 0; i < 4; i++ {
		if e.cookieJars[i] == nil {
			t.Fatalf("jar[%d] not created", i)
		}
		if e.jarClients[i] == nil {
			t.Fatalf("client[%d] not created", i)
		}
		if e.jarClients[i].Jar != e.cookieJars[i] {
			t.Errorf("client[%d] not bound to its own jar", i)
		}
	}
	if e.cookieJars[0] == e.cookieJars[1] || e.jarClients[0] == e.jarClients[1] {
		t.Error("users share one jar/client — isolation broken")
	}
	// Fast path must return the same instances.
	if e.cookieJarFor(0) != e.cookieJars[0] {
		t.Error("cookieJarFor fast path did not return the pre-created jar")
	}
	if e.cookieJarFor(-1) != nil {
		t.Error("negative index must not create a jar")
	}
}

// TestPowerDroppedJarRecreatedLazily verifies dropCookieJar nils the slot and
// the next request lazily rebuilds a fresh, independent session.
func TestPowerDroppedJarRecreatedLazily(t *testing.T) {
	e, err := New(&config.Scenario{
		Name:    "drop",
		Profile: config.Profile{Users: 3, Duration: 1, Timeout: 5},
		Steps:   []config.Step{{Name: "s", URL: "http://localhost/"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	e.precreateJars(3)
	old := e.cookieJars[1]

	e.dropCookieJar(1)
	if e.cookieJars[1] != nil || e.jarClients[1] != nil {
		t.Fatal("dropCookieJar did not nil the slot")
	}

	fresh := e.cookieJarFor(1)
	if fresh == nil {
		t.Fatal("cookieJarFor did not recreate the dropped jar")
	}
	if fresh == old {
		t.Error("recreated jar is the same instance as the dropped one")
	}
	c := e.clientForJar(1)
	if c == nil || c.Jar != fresh {
		t.Error("clientForJar did not rebuild a client bound to the fresh jar")
	}
	// Unrelated users are untouched.
	if e.cookieJarFor(0) == nil || e.cookieJarFor(2) == nil {
		t.Error("drop of user 1 clobbered another user's session")
	}
}
