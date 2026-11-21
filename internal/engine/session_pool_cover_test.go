package engine

// Priority-1 coverage for the per-worker session pool helpers in ws_client.go
// and raw_client.go. The tests exercise the full lifecycle: empty take, put,
// reuse, URL invalidation, drop after use, double-put, concurrent take/put and
// final closeSessions cleanup. No production code is modified.

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/asadbekabdulboqiyev/sift/internal/config"
)

// newPoolTestWSConn dials the shared echo server and returns a live WebSocket
// session plus its URL. The server helper is defined in enhanced_clients_test.go.
func newPoolTestWSConn(t *testing.T) (*websocket.Conn, string) {
	t.Helper()
	srv := newWSEchoServer(t)
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}
	t.Cleanup(func() { closeWS(conn) })
	return conn, wsURL
}

func TestWSPoolLifecycle(t *testing.T) {
	e := &Engine{}

	// Empty pool: nothing to take.
	if c, ok := e.takeWSConn(0, "ws://example.test"); c != nil || ok {
		t.Fatalf("empty takeWSConn = (%v, %v), want (nil, false)", c, ok)
	}

	conn, wsURL := newPoolTestWSConn(t)
	e.putWSConn(0, wsURL, conn)

	// A matching URL reuses the exact pooled pointer.
	got, ok := e.takeWSConn(0, wsURL)
	if !ok || got != conn {
		t.Fatalf("takeWSConn(match) = (%p, %v), want (%p, true)", got, ok, conn)
	}

	// A different URL invalidates the session and closes the stale socket.
	if c, ok := e.takeWSConn(0, "ws://other.example/socket"); c != nil || ok {
		t.Fatalf("takeWSConn(url change) = (%v, %v), want (nil, false)", c, ok)
	}
	if err := conn.WriteMessage(websocket.TextMessage, []byte("stale")); err == nil {
		t.Fatal("stale pooled WebSocket stayed open after URL change")
	}
	e.sessMu.Lock()
	n := len(e.wsConns)
	e.sessMu.Unlock()
	if n != 0 {
		t.Fatalf("wsConns after URL change = %d, want 0", n)
	}

	// A dropped session is also unavailable on the next take.
	conn2, _ := newPoolTestWSConn(t)
	e.putWSConn(1, wsURL, conn2)
	e.dropWSConn(1)
	if c, ok := e.takeWSConn(1, wsURL); c != nil || ok {
		t.Fatalf("takeWSConn after drop = (%v, %v), want (nil, false)", c, ok)
	}
	// Helper contract: dropWSConn only evicts; the caller keeps socket
	// ownership and closes it (closeWS before dropWSConn in wsPooled). Assert
	// that ownership boundary so a silent change is caught.
	if err := conn2.WriteMessage(websocket.TextMessage, []byte("still-open")); err != nil {
		t.Fatalf("dropWSConn closed a caller-owned socket: %v", err)
	}
	_ = conn2.Close()
}

func TestTCPPoolLifecycle(t *testing.T) {
	e := &Engine{}

	if c := e.takeTCPConn(0); c != nil {
		t.Fatalf("empty takeTCPConn = %v, want nil", c)
	}

	client, server := net.Pipe()
	defer func() { _ = server.Close() }()
	e.putTCPConn(0, client)

	if got := e.takeTCPConn(0); got != client {
		t.Fatalf("takeTCPConn = %p, want %p", got, client)
	}

	e.dropTCPConn(0)
	if c := e.takeTCPConn(0); c != nil {
		t.Fatalf("takeTCPConn after drop = %v, want nil", c)
	}
	// Helper contract: dropTCPConn only evicts; callers close the socket
	// (rawClientForUser closes it right after dropTCPConn). net.Pipe is
	// synchronous, so drain the local end while writing from the peer.
	readDone := make(chan struct{})
	go func() {
		buf := make([]byte, 1)
		_, _ = client.Read(buf)
		close(readDone)
	}()
	if _, err := server.Write([]byte("x")); err != nil {
		t.Fatalf("dropTCPConn closed a caller-owned socket: %v", err)
	}
	<-readDone
	_ = client.Close()
}

// TestSessionPoolKeepsOneConnectionPerUser pins the pool's effective cap: a
// second put for the same user index replaces the first entry rather than
// growing the map. The displaced connection is not closed by production code;
// this is recorded as an observation in the report, not changed here.
func TestSessionPoolKeepsOneConnectionPerUser(t *testing.T) {
	e := &Engine{}

	ws1, wsURL := newPoolTestWSConn(t)
	ws2, _ := newPoolTestWSConn(t)
	e.putWSConn(0, wsURL, ws1)
	e.putWSConn(0, wsURL, ws2)

	tcp1, srv1 := net.Pipe()
	tcp2, srv2 := net.Pipe()
	defer func() {
		_ = srv1.Close()
		_ = srv2.Close()
	}()
	e.putTCPConn(0, tcp1)
	e.putTCPConn(0, tcp2)

	e.sessMu.Lock()
	wsCount := len(e.wsConns)
	tcpCount := len(e.tcpConns)
	currentWS := e.wsConns[0]
	currentTCP := e.tcpConns[0]
	e.sessMu.Unlock()

	if wsCount != 1 || tcpCount != 1 {
		t.Fatalf("pool sizes after double put = (%d ws, %d tcp), want (1, 1)", wsCount, tcpCount)
	}
	if currentWS != ws2 {
		t.Fatal("second put did not become the current WebSocket session")
	}
	if currentTCP != tcp2 {
		t.Fatal("second put did not become the current TCP session")
	}
	// Helper contract: putTCPConn replaces an entry without closing it.
	// Production only puts after takeTCPConn returned nil, so no live socket
	// is displaced in normal operation; this pins the helper behavior. Drain
	// the pipe while writing so the synchronous pipe does not block the test.
	readDone := make(chan struct{})
	go func() {
		buf := make([]byte, 1)
		_, _ = tcp1.Read(buf)
		close(readDone)
	}()
	if _, err := srv1.Write([]byte("x")); err != nil {
		t.Fatalf("putTCPConn closed a displaced socket: %v", err)
	}
	<-readDone
}

func TestSessionPoolConcurrentTakePutDrop(t *testing.T) {
	e := &Engine{}
	const users = 8
	const rounds = 200

	var wg sync.WaitGroup
	for u := 0; u < users; u++ {
		wg.Add(1)
		go func(user int) {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				e.putWSConn(user, "ws://pool.test", nil)
				_, _ = e.takeWSConn(user, "ws://pool.test")
				e.putTCPConn(user, nil)
				_ = e.takeTCPConn(user)
				if i%7 == 0 {
					e.dropWSConn(user)
					e.dropTCPConn(user)
				}
			}
		}(u)
	}
	wg.Wait()

	e.sessMu.Lock()
	wsCount := len(e.wsConns)
	tcpCount := len(e.tcpConns)
	e.sessMu.Unlock()
	if wsCount > users || tcpCount > users {
		t.Fatalf("concurrent pool sizes = (%d ws, %d tcp), want at most %d each", wsCount, tcpCount, users)
	}
}

func TestCloseSessionsDrainsAllPools(t *testing.T) {
	e := &Engine{}

	ws, wsURL := newPoolTestWSConn(t)
	e.putWSConn(0, wsURL, ws)

	tcpClient, tcpServer := net.Pipe()
	e.putTCPConn(0, tcpClient)

	e.closeSessions()

	if err := ws.WriteMessage(websocket.TextMessage, []byte("x")); err == nil {
		t.Fatal("closeSessions left a WebSocket session open")
	}
	// net.Pipe writes block without a reader. A deadline turns a regression
	// here into a clear assertion instead of a test timeout. When the peer is
	// already closed, SetWriteDeadline itself reports the closed pipe; the
	// write below still returns promptly with an error, which is the outcome
	// this test asserts.
	_ = tcpServer.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := tcpServer.Write([]byte("x")); err == nil {
		t.Fatal("closeSessions left a TCP session open")
	}

	e.sessMu.Lock()
	wsNil := e.wsConns == nil && e.wsURLs == nil && e.tcpConns == nil && e.grpcConns == nil && e.cookieJars == nil
	e.sessMu.Unlock()
	if !wsNil {
		t.Fatal("closeSessions did not clear the session containers")
	}
}

// newCountingTCPEchoServer accepts TCP connections, counts them and echoes
// every payload back. It lets the reuse test prove that a second step did not
// dial a second socket.
func newCountingTCPEchoServer(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	accepts := &atomic.Int64{}
	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				buf := make([]byte, 1024)
				for {
					n, err := conn.Read(buf)
					if err != nil {
						return
					}
					if _, err := conn.Write(append([]byte("echo:"), buf[:n]...)); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	t.Cleanup(func() { _ = lis.Close() })
	return lis.Addr().String(), accepts
}

func TestRawClientForUserReusesPooledTCPConn(t *testing.T) {
	addr, accepts := newCountingTCPEchoServer(t)
	e := &Engine{keepAlive: true}
	step := config.Step{Body: "ping", AwaitResponse: true, Session: true}
	ctx := context.Background()

	res, body := e.rawClientForUser(0, ctx, "tcp", addr, step, nil, 2*time.Second)
	if res.errName != "" {
		t.Fatalf("first exchange: %s", res.errName)
	}
	if string(body) != "echo:ping" {
		t.Fatalf("first body = %q, want %q", body, "echo:ping")
	}
	first := e.takeTCPConn(0)
	if first == nil {
		t.Fatal("first exchange did not pool its TCP connection")
	}

	res, body = e.rawClientForUser(0, ctx, "tcp", addr, step, nil, 2*time.Second)
	if res.errName != "" {
		t.Fatalf("second exchange: %s", res.errName)
	}
	if string(body) != "echo:ping" {
		t.Fatalf("second body = %q, want %q", body, "echo:ping")
	}
	second := e.takeTCPConn(0)
	if second != first {
		t.Fatalf("second exchange replaced the pooled TCP conn (%p -> %p)", first, second)
	}
	if got := accepts.Load(); got != 1 {
		t.Fatalf("server accepted %d connections, want 1", got)
	}
}

// newCountingWSEchoServer is a local variant of newWSEchoServer that reports
// how many upgrades the server handled.
func newCountingWSEchoServer(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	upgrades := &atomic.Int64{}
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		upgrades.Add(1)
		defer func() { _ = c.Close() }()
		for {
			mt, msg, err := c.ReadMessage()
			if err != nil {
				return
			}
			if err := c.WriteMessage(mt, append([]byte("echo:"), msg...)); err != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)
	return "ws" + strings.TrimPrefix(srv.URL, "http"), upgrades
}

func TestWSClientForUserReusesPooledConn(t *testing.T) {
	wsURL, upgrades := newCountingWSEchoServer(t)
	e := &Engine{keepAlive: true}
	step := config.Step{Body: "hello", Session: true}
	ctx := context.Background()

	res, body := e.wsClientForUser(0, ctx, wsURL, step, nil, 2*time.Second)
	if res.errName != "" {
		t.Fatalf("first exchange: %s", res.errName)
	}
	if string(body) != "echo:hello" {
		t.Fatalf("first body = %q, want %q", body, "echo:hello")
	}
	first, ok := e.takeWSConn(0, wsURL)
	if !ok || first == nil {
		t.Fatal("first exchange did not pool its WebSocket connection")
	}

	res, body = e.wsClientForUser(0, ctx, wsURL, step, nil, 2*time.Second)
	if res.errName != "" {
		t.Fatalf("second exchange: %s", res.errName)
	}
	if string(body) != "echo:hello" {
		t.Fatalf("second body = %q, want %q", body, "echo:hello")
	}
	second, ok := e.takeWSConn(0, wsURL)
	if !ok || second != first {
		t.Fatalf("second exchange replaced the pooled WebSocket (%p -> %p, ok=%v)", first, second, ok)
	}
	if got := upgrades.Load(); got != 1 {
		t.Fatalf("server handled %d upgrades, want 1", got)
	}
}

// TestDropAfterFailedUseForcesRedial covers the eviction path: dropping a
// pooled socket after a failure makes the next call establish a fresh session.
func TestDropAfterFailedUseForcesRedial(t *testing.T) {
	addr, accepts := newCountingTCPEchoServer(t)
	e := &Engine{keepAlive: true}
	step := config.Step{Body: "ping", AwaitResponse: true, Session: true}
	ctx := context.Background()

	if res, _ := e.rawClientForUser(0, ctx, "tcp", addr, step, nil, 2*time.Second); res.errName != "" {
		t.Fatalf("initial exchange: %s", res.errName)
	}
	first := e.takeTCPConn(0)
	if first == nil {
		t.Fatal("initial exchange did not pool its connection")
	}

	// Simulate a failed iteration: evict and close exactly as tcpExchange does.
	e.dropTCPConn(0)
	_ = first.Close()

	if res, _ := e.rawClientForUser(0, ctx, "tcp", addr, step, nil, 2*time.Second); res.errName != "" {
		t.Fatalf("redial exchange: %s", res.errName)
	}
	if got := accepts.Load(); got != 2 {
		t.Fatalf("server accepted %d connections after drop, want 2", got)
	}
	if e.takeTCPConn(0) == first {
		t.Fatal("pool still holds the closed connection after drop")
	}
	e.closeSessions()
}
