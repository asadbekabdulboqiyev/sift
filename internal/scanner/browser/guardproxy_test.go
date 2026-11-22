package browser

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/authz"
)

func proxyHost(t *testing.T, p *guardProxy) string {
	t.Helper()
	return strings.TrimPrefix(p.addr(), "http://")
}

// rawProxyResponse sends a hand-written request to the proxy and parses the
// status line. http.Client cannot be used for refusals: it reports them as a
// transport error instead of exposing the proxy's response.
func rawProxyResponse(t *testing.T, proxyAddr, raw string) *http.Response {
	t.Helper()
	conn, err := net.Dial("tcp", strings.TrimPrefix(proxyAddr, "http://"))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(conn, raw); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read proxy response: %v", err)
	}
	return resp
}

func startTestProxy(t *testing.T, class authz.Class) *guardProxy {
	t.Helper()
	p, err := startGuardProxy(authz.DialControl(class), 0)
	if err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	t.Cleanup(func() { _ = p.close() })
	return p
}

func TestStartGuardProxyWithoutControlStartsNothing(t *testing.T) {
	p, err := startGuardProxy(nil, 0)
	if err != nil || p != nil {
		t.Fatalf("nil control must start no proxy: p=%v err=%v", p, err)
	}
}

func TestGuardProxyListensOnEphemeralLoopback(t *testing.T) {
	p := startTestProxy(t, authz.ClassLoopback)
	addr := proxyHost(t, p)
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host != "127.0.0.1" || port == "0" {
		t.Fatalf("proxy addr = %q (host=%q port=%q err=%v), want 127.0.0.1:<ephemeral>", addr, host, port, err)
	}
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	_ = conn.Close()

	if err := p.close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if conn, err := net.Dial("tcp", addr); err == nil {
		_ = conn.Close()
		t.Fatal("proxy still accepting after close")
	}
	// close() must be idempotent (New() calls it on a failed probe).
	if err := p.close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

func TestGuardProxyAbsoluteFormClassDecision(t *testing.T) {
	var hits atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "allowed")
	}))
	defer up.Close()

	allowed := startTestProxy(t, authz.ClassLoopback)
	refused := startTestProxy(t, authz.ClassPublic)

	do := func(p *guardProxy) *http.Response {
		return rawProxyResponse(t, p.addr(), fmt.Sprintf("GET %s/probe HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", up.URL, strings.TrimPrefix(up.URL, "http://")))
	}
	if resp := do(allowed); resp.StatusCode != http.StatusOK {
		t.Fatalf("approved loopback: status %d, want 200", resp.StatusCode)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("upstream hits = %d, want 1", got)
	}
	resp := do(refused)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unapproved loopback: status %d, want 403", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "authz: refusing") {
		t.Fatalf("refusal body = %q, want authz reason", body)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("refused request reached upstream (hits=%d)", got)
	}
}

func TestGuardProxyCONNECTClassDecision(t *testing.T) {
	var hits atomic.Int32
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "tls-ok")
	}))
	defer up.Close()
	upHost := strings.TrimPrefix(up.URL, "https://")

	allowed := startTestProxy(t, authz.ClassLoopback)
	refused := startTestProxy(t, authz.ClassPublic)

	// A real HTTPS client: proves the CONNECT tunnel carries TLS end-to-end.
	client := up.Client()
	tr := client.Transport.(*http.Transport).Clone()
	proxyURL, _ := url.Parse(allowed.addr())
	tr.Proxy = http.ProxyURL(proxyURL)
	client.Transport = tr
	resp, err := client.Get(up.URL + "/probe")
	if err != nil {
		t.Fatalf("GET via approved CONNECT proxy: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "tls-ok" {
		t.Fatalf("tunneled response = %d %q", resp.StatusCode, body)
	}

	// Raw CONNECT to the refused proxy must be denied BEFORE a 200 is written.
	r := rawProxyResponse(t, refused.addr(), fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", upHost, upHost))
	if r.StatusCode != http.StatusForbidden {
		t.Fatalf("refused CONNECT status = %d, want 403", r.StatusCode)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("refused CONNECT reached upstream (hits=%d)", got)
	}
}

func TestGuardProxyAppliesControlToDestinationAndSocket(t *testing.T) {
	var mu sync.Mutex
	type call struct {
		address string
		rawConn bool
	}
	var calls []call
	base := authz.DialControl(authz.ClassLoopback)
	counting := func(network, address string, c syscall.RawConn) error {
		mu.Lock()
		calls = append(calls, call{address: address, rawConn: c != nil})
		mu.Unlock()
		return base(network, address, c)
	}
	p, err := startGuardProxy(counting, 0)
	if err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	defer p.close()

	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer up.Close()
	client := up.Client()
	tr := client.Transport.(*http.Transport).Clone()
	proxyURL, _ := url.Parse(p.addr())
	tr.Proxy = http.ProxyURL(proxyURL)
	client.Transport = tr
	resp, err := client.Get(up.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()
	var sawCheck, sawSocket bool
	for _, c := range calls {
		if c.rawConn {
			sawSocket = true
		} else {
			sawCheck = true
		}
		if !strings.HasSuffix(c.address, strings.TrimPrefix(up.URL, "https://")) {
			t.Fatalf("control called for unexpected address %q", c.address)
		}
	}
	if !sawCheck || !sawSocket {
		t.Fatalf("control layers missing: check=%v socket=%v calls=%+v", sawCheck, sawSocket, calls)
	}
}

func TestGuardProxyRefusesLoopbackHostnamesUnderClassPublic(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "should-not-reach")
	}))
	defer up.Close()
	port := strings.TrimPrefix(up.URL, "http://")
	host, _, _ := net.SplitHostPort(port)
	p := startTestProxy(t, authz.ClassPublic)

	for _, target := range []string{host, "localhost"} {
		addr := net.JoinHostPort(target, strings.TrimPrefix(port, host+":"))
		// The port suffix above is the same for both hosts.
		if _, _, err := net.SplitHostPort(addr); err != nil {
			t.Fatalf("bad target %q: %v", addr, err)
		}
		r := rawProxyResponse(t, p.addr(), fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", addr, addr))
		if r.StatusCode != http.StatusForbidden {
			t.Errorf("CONNECT %s: status %d, want 403", addr, r.StatusCode)
		}
		r = rawProxyResponse(t, p.addr(), fmt.Sprintf("GET http://%s/x HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", addr, addr))
		if r.StatusCode != http.StatusForbidden {
			t.Errorf("GET %s: status %d, want 403", addr, r.StatusCode)
		}
	}
}

func TestGuardProxyPreservesRequestAndResponse(t *testing.T) {
	type seen struct {
		method, path, query, body, header string
	}
	got := make(chan seen, 1)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- seen{r.Method, r.URL.Path, r.URL.RawQuery, string(b), r.Header.Get("X-Test")}
		w.WriteHeader(http.StatusTeapot)
		_, _ = io.WriteString(w, "teapot")
	}))
	defer up.Close()
	p := startTestProxy(t, authz.ClassLoopback)
	proxyURL, _ := url.Parse(p.addr())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	req, err := http.NewRequest(http.MethodPatch, up.URL+"/path?k=v", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Test", "kept")
	req.Header.Set("Proxy-Authorization", "secret-must-be-stripped")
	req.Header.Set("Proxy-Connection", "keep-alive")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTeapot || string(body) != "teapot" {
		t.Fatalf("response = %d %q", resp.StatusCode, body)
	}
	s := <-got
	if s.method != http.MethodPatch || s.path != "/path" || s.query != "k=v" || s.body != "payload" || s.header != "kept" {
		t.Fatalf("origin saw %+v", s)
	}
}

func TestGuardProxyRejectsMalformedAuthority(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "hit")
	}))
	defer up.Close()
	upHost := strings.TrimPrefix(up.URL, "http://")
	p := startTestProxy(t, authz.ClassLoopback)

	cases := []string{
		fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", upHost),                                  // origin-form
		"CONNECT 127.0.0.1 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",                                                         // no port
		"CONNECT :443 HTTP/1.1\r\nHost: :443\r\n\r\n",                                                                   // no host
		fmt.Sprintf("CONNECT %s:abc HTTP/1.1\r\nHost: x\r\n\r\n", upHost),                                               // bad port
		fmt.Sprintf("GET http://:%s/x HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", strings.Split(upHost, ":")[1]), // no host
	}
	for i, raw := range cases {
		resp := rawProxyResponse(t, p.addr(), raw)
		if resp.StatusCode < 400 {
			t.Errorf("case %d: status %d, want rejection", i, resp.StatusCode)
		}
	}
}

func TestGuardProxyIsNotAnOpenProxy(t *testing.T) {
	var mu sync.Mutex
	checked := map[string]bool{}
	base := authz.DialControl(authz.ClassPublic)
	counting := func(network, address string, c syscall.RawConn) error {
		mu.Lock()
		checked[address] = true
		mu.Unlock()
		return base(network, address, c)
	}
	p, err := startGuardProxy(counting, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()

	targets := []string{"169.254.169.254:80", "100.100.100.200:80", "10.0.0.1:80", "[::1]:80"}
	for _, target := range targets {
		r := rawProxyResponse(t, p.addr(), fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target))
		if r.StatusCode != http.StatusForbidden {
			t.Errorf("CONNECT %s: status %d, want 403 (open proxy)", target, r.StatusCode)
		}
		r = rawProxyResponse(t, p.addr(), fmt.Sprintf("GET http://%s/x HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target, target))
		if r.StatusCode != http.StatusForbidden {
			t.Errorf("GET %s: status %d, want 403 (open proxy)", target, r.StatusCode)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	for _, target := range targets {
		if !checked[target] {
			t.Errorf("control never checked %q; the refusal was not authorization-driven", target)
		}
	}
}

func TestGuardProxyRejectsUnsupportedMethodsAndSchemes(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "hit")
	}))
	defer up.Close()
	host := strings.TrimPrefix(up.URL, "http://")
	p := startTestProxy(t, authz.ClassLoopback)
	cases := []string{
		fmt.Sprintf("TRACE http://%s/x HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host, host),
		fmt.Sprintf("FROB http://%s/x HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host, host),
		fmt.Sprintf("GET ftp://%s/x HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host, host),
		fmt.Sprintf("GET https://%s/x HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host, host),
	}
	for i, raw := range cases {
		resp := rawProxyResponse(t, p.addr(), raw)
		if resp.StatusCode < 400 {
			t.Errorf("case %d: status %d, want rejection", i, resp.StatusCode)
		}
	}
}

func TestSplitAuthority(t *testing.T) {
	parse := func(raw string) *http.Request {
		req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
		if err != nil {
			t.Fatalf("parse %q: %v", raw, err)
		}
		return req
	}
	cases := []struct {
		name, raw, host, port string
		wantErr               bool
	}{
		{"connect", "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n", "example.com", "443", false},
		{"connect-host-header", "CONNECT example.com:443 HTTP/1.1\r\n\r\n", "example.com", "443", false},
		{"connect-no-port", "CONNECT example.com HTTP/1.1\r\n\r\n", "", "", true},
		{"absolute-default-port", "GET http://example.com/x HTTP/1.1\r\nHost: example.com\r\n\r\n", "example.com", "80", false},
		{"absolute-explicit-port", "GET http://example.com:8080/x HTTP/1.1\r\nHost: example.com:8080\r\n\r\n", "example.com", "8080", false},
		{"absolute-ipv6", "GET http://[::1]:8080/x HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n", "::1", "8080", false},
		{"absolute-ipv6-default-port", "GET http://[::1]/x HTTP/1.1\r\nHost: [::1]\r\n\r\n", "::1", "80", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host, port, err := splitAuthority(parse(tc.raw))
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
			if host != tc.host || port != tc.port {
				t.Fatalf("got %q:%q, want %q:%q", host, port, tc.host, tc.port)
			}
		})
	}
}

func TestGuardProxyCloseTerminatesTunnels(t *testing.T) {
	// A raw TCP listener, not httptest.NewServer: a CONNECT tunnel carries no
	// HTTP request to the origin, so an http.Handler would never be invoked.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	upstreams := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			upstreams <- c
		}
	}()

	p := startTestProxy(t, authz.ClassLoopback)
	addr := proxyHost(t, p)
	const tunnels = 4
	conns := make([]net.Conn, 0, tunnels)
	for i := 0; i < tunnels; i++ {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		conns = append(conns, conn)
		_, _ = io.WriteString(conn, fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", ln.Addr(), ln.Addr()))
	}
	// Consume the 200 on one tunnel so the test also covers an established,
	// actively bridged connection (not just CONNECTs still in flight).
	br := bufio.NewReader(conns[0])
	if _, err := http.ReadResponse(br, nil); err != nil {
		t.Fatalf("first tunnel not established: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- p.close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("close: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("close did not return")
	}

	// Reading to EOF must complete; a clean EOF (err == nil) is the expected
	// outcome for a closed TCP stream, the point is that it does not block.
	drain := func(c net.Conn, label string) {
		t.Helper()
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		res := make(chan error, 1)
		go func() { _, err := io.Copy(io.Discard, c); res <- err }()
		select {
		case <-res:
		case <-time.After(2 * time.Second):
			t.Errorf("%s still open after close", label)
		}
	}
	for i, conn := range conns {
		drain(conn, fmt.Sprintf("browser tunnel %d", i))
		_ = conn.Close()
	}
	// Not every handler is guaranteed to have dialed upstream before close()
	// cancels it; drain whatever was established and check none leaks.
	upstreamSeen := 0
	for {
		select {
		case c := <-upstreams:
			drain(c, fmt.Sprintf("upstream tunnel %d", upstreamSeen))
			_ = c.Close()
			upstreamSeen++
		default:
			if upstreamSeen == 0 {
				t.Error("no upstream tunnel was established")
			}
			goto upstreamsDrained
		}
	}
upstreamsDrained:
	p.mu.Lock()
	remaining := len(p.conns)
	closed := p.closed
	p.mu.Unlock()
	if remaining != 0 || !closed {
		t.Fatalf("after close: tracked=%d closed=%v", remaining, closed)
	}
}

// TestGuardProxyWebSocketUpgradePreservesCoalescedFrame pins a subtle bug: on
// a 101 upgrade, http.ReadResponse's bufio.Reader may have already buffered
// the origin's first frame when it was coalesced with the handshake headers.
// The bridge must drain that reader; reading the raw socket would drop it.
func TestGuardProxyWebSocketUpgradePreservesCoalescedFrame(t *testing.T) {
	const payload = "FIRST-FRAME-PAYLOAD"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan struct{}, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		// Read the forwarded upgrade request so the proxy completes its write.
		_, _ = http.ReadRequest(bufio.NewReader(c))
		// Send the 101 headers AND the first data frame in a single write, so
		// http.ReadResponse's bufio.Reader buffers both at once.
		_, _ = io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"+payload)
		accepted <- struct{}{}
		// Keep the tunnel open briefly so the client can read the payload.
		_, _ = io.Copy(io.Discard, c)
	}()

	p := startTestProxy(t, authz.ClassLoopback)
	addr := ln.Addr().String()
	conn, err := net.Dial("tcp", strings.TrimPrefix(p.addr(), "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	_, _ = io.WriteString(conn, fmt.Sprintf("GET http://%s/ws HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n", addr, addr))

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	// The coalesced frame must arrive through the same buffered reader the
	// proxy used for the handshake. A raw-socket bridge loses these bytes.
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("read coalesced frame: %v (buffered bytes were dropped)", err)
	}
	if string(got) != payload {
		t.Fatalf("frame = %q, want %q", got, payload)
	}
	<-accepted
}
