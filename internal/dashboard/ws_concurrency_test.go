package dashboard

import (
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// TestBroadcastConcurrentWritesAreSerialized pins the fix for the concurrent
// WebSocket writer crash: snapshot and run-state broadcasts originate from
// different goroutines and used to call WriteMessage directly, which
// gorilla/websocket turns into a panic ("concurrent write to websocket
// connection") and takes the whole process down. Every write now goes through
// writeWS, so this must finish without a panic (and without a data race under
// -race).
func TestBroadcastConcurrentWritesAreSerialized(t *testing.T) {
	s := NewServer()
	srv := httptest.NewServer(s)
	defer srv.Close()

	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	conns := make([]*websocket.Conn, 0, 3)
	for i := 0; i < 3; i++ {
		c, _, err := websocket.DefaultDialer.Dial(url, nil)
		if err != nil {
			t.Fatalf("dial websocket: %v", err)
		}
		defer c.Close()
		conns = append(conns, c)
	}

	var drain sync.WaitGroup
	for _, c := range conns {
		drain.Add(1)
		go func(c *websocket.Conn) {
			defer drain.Done()
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			for {
				if _, _, err := c.ReadMessage(); err != nil {
					return
				}
			}
		}(c)
	}

	var panics atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					panics.Add(1)
				}
			}()
			for j := 0; j < 200; j++ {
				if i%2 == 0 {
					s.UpdateSnapshot(&LiveSnapshot{Timestamp: time.Now(), RPS: float64(j)})
				} else {
					s.SetRunState(&RunState{Status: "running", Progress: float64(j)})
				}
			}
		}(i)
	}
	wg.Wait()
	drain.Wait()

	if n := panics.Load(); n > 0 {
		t.Fatalf("%d goroutine(s) panicked writing to the same websocket connection", n)
	}
}
