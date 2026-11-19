package engine

import (
	"testing"

	"github.com/asadbekabdulboqiyev/sift/internal/config"
)

// TestNoCookieLeakAcrossUsers ensures each virtual user keeps its own jar:
// with distinct cookies per user, no cross-contamination can occur.
func TestCookieJarPerUserIsolation(t *testing.T) {
	e, err := New(&config.Scenario{
		Name:    "jar",
		Profile: config.Profile{Users: 4, Duration: 1, Timeout: 5},
		Steps:   []config.Step{{Name: "s", URL: "http://localhost/"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	j1 := e.cookieJarFor(1)
	j2 := e.cookieJarFor(2)
	if j1 == nil || j2 == nil {
		t.Fatal("expected non-nil jars for valid user indexes with keep-alive on")
	}
	if j1 == j2 {
		t.Error("two users share one cookie jar")
	}
	if e.cookieJarFor(-1) != nil {
		t.Error("negative index must not create a jar")
	}
}
