package audit360

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

// TestSubscribeOnFinishedJobDeliversTerminalEvent covers the SSE stall: a
// subscriber that arrives after the job finished used to receive only a
// "status" frame, while the stream handler only closes on completed/failed, so
// the stream stayed open until the client gave up.
func TestSubscribeOnFinishedJobDeliversTerminalEvent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	m := NewManagerWithSignerKey(filepath.Join(t.TempDir(), "audit360-key.pem"))
	id, err := m.Start(context.Background(), srv.URL, 5*time.Second, "", ModePassive)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	deadline := time.Now().Add(40 * time.Second)
	for {
		st, ok := m.Get(id)
		if !ok {
			t.Fatalf("job %s disappeared", id)
		}
		if st.State == "completed" || st.State == "failed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("job did not finish, state=%q", st.State)
		}
		time.Sleep(20 * time.Millisecond)
	}

	ch, cancel, ok := m.Subscribe(id)
	if !ok {
		t.Fatal("Subscribe on an existing job returned false")
	}
	defer cancel()

	select {
	case ev := <-ch:
		if ev.Type != "completed" && ev.Type != "failed" {
			t.Fatalf("first event after subscribing to a finished job = %q, want completed or failed", ev.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event delivered to a subscriber of a finished job")
	}
}
