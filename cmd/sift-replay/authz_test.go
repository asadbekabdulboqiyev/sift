package main

import (
	"strings"
	"testing"

	"github.com/asadbekabdulboqiyev/sift/internal/authz"
)

// TestReplayDialControl verifies that the CLI derives a socket-level gate from
// the operator-named base URL and refuses the credential-theft destination.
func TestReplayDialControl(t *testing.T) {
	if control, err := replayDialControl(""); err != nil || control != nil {
		t.Fatalf("empty base URL: control set=%t err=%v, want false/nil", control != nil, err)
	}

	control, err := replayDialControl("http://127.0.0.1:8080/replay")
	if err != nil {
		t.Fatalf("loopback base URL: %v", err)
	}
	if control == nil {
		t.Fatal("loopback base URL produced no socket control")
	}
	if err := control("tcp", "127.0.0.1:8080", nil); err != nil {
		t.Fatalf("approved loopback peer refused: %v", err)
	}
	if err := control("tcp", "169.254.169.254:80", nil); err == nil {
		t.Fatal("metadata peer was not refused by the loopback approval")
	}

	if _, err := replayDialControl("http://169.254.169.254/latest/meta-data"); err == nil {
		t.Fatal("metadata base URL was accepted")
	}
	if _, err := replayDialControl("http://metadata.google.internal/"); err == nil {
		t.Fatal("metadata hostname was accepted")
	}
}

// TestReplayPublicBaseControlRefusesLoopback is the CLI-side counterpart of
// the engine socket test: a public staging URL must not let replay reach the
// runner itself.
func TestReplayPublicBaseControlRefusesLoopback(t *testing.T) {
	control, err := replayDialControl("http://93.184.216.34/replay")
	if err != nil {
		t.Fatalf("public base URL: %v", err)
	}
	err = control("tcp", "127.0.0.1:8080", nil)
	if err == nil {
		t.Fatal("loopback peer was not refused by the public approval")
	}
	if !strings.Contains(err.Error(), authz.ClassPublic.String()) {
		t.Fatalf("refusal does not name the approved class: %v", err)
	}
}
