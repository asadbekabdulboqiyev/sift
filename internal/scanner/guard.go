// guard.go is the production core.Requester: the single place where a probe's
// network access is decided.
//
// A vulnerability scanner is an offensive tool. The difference between a
// sanctioned assessment and an attack is entirely policy: who said you may
// touch this host, how hard you may push, and whether you actually stop. Guard
// is that policy, and probe.go makes it unskippable — every check family is
// written against the core.Requester interface, and Guard is the only real
// implementation.
//
// Guard enforces, in order:
//
//  1. structural validity  — http(s) only, no userinfo, a real host, a real
//     port. Enforced even under AllowAll.
//  2. an explicit scope allowlist — fail-closed: no allowlist and no AllowAll
//     means no probe, ever.
//  3. an intrusive opt-in — intrusive probes are off unless Intrusive is set.
//  4. a total request budget — reserved by CAS, so concurrent probes cannot
//     overshoot it.
//  5. a per-host rate limit — a token bucket keyed on the lowercased host.
//  6. a per-request timeout and a response size cap.
//  7. an identifiable User-Agent, so the scanned system's operator can see who
//     is probing.
//
// Check() answers the policy question without sending a byte; Do() re-checks
// scope (defense in depth), then actually sends. DryRun makes Do() refuse
// everything while still evaluating policy, so an operator can preview exactly
// what a scan would touch.
package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/authz"
	"github.com/asadbekabdulboqiyev/sift/internal/fingerprint"
	"github.com/asadbekabdulboqiyev/sift/internal/scanner/core"
)

// GuardConfig configures a Guard. The zero value is usable and safe: it
// refuses every request (fail-closed, no allowlist) until Allow or AllowAll is
// set.
type GuardConfig struct {
	// Allow is the scope allowlist. Fail-closed: an empty Allow with
	// AllowAll=false refuses every request.
	//
	// Each entry is one pattern. A pattern is "<netloc>" or
	// "<netloc> <pathPrefix>" (the two fields separated by whitespace, so a
	// CIDR mask and a path prefix can never be confused):
	//
	//	example.com                 exact host, any port, any path
	//	example.com:8443            exact host and effective port
	//	*.example.com               subdomains only (the apex does NOT match)
	//	10.0.0.0/8                  CIDR range
	//	[::1]:8080                  IPv6 literal, with port
	//	example.com /api            exact host, path under /api
	//	10.0.0.0/8 /internal        CIDR range, path under /internal
	//
	// Port matching uses the *effective* port: the URL's explicit port, or the
	// scheme default (80 for http, 443 for https). IPv6 literals must be
	// bracketed when a port is present.
	Allow []string

	// AllowAll authorises every structurally valid http(s) target. It does not
	// relax the intrusive gate.
	AllowAll bool

	// Intrusive enables intrusive probes (injection, traversal, SSRF, ...).
	// Off by default: they can mutate server state, and are only appropriate
	// with explicit written authorisation.
	Intrusive bool

	// RPS is the per-host sustained request rate. 0 means 10. Must be finite
	// and non-negative.
	RPS float64

	// Burst is the per-host token-bucket depth. 0 means ceil(RPS), minimum 1.
	Burst int

	// MaxRequests is the total request budget for the whole Guard. 0 means
	// 2000. Every request (successful or not) counts against it.
	MaxRequests int64

	// Timeout is the per-request timeout. 0 means 10s.
	Timeout time.Duration

	// MaxBodyBytes caps how many response bytes Guard will ever hand back.
	// 0 means core.DefaultProbeLimit.
	MaxBodyBytes int64

	// DryRun evaluates policy but never sends. Do() returns core.ErrDryRun.
	DryRun bool

	// Fingerprint, when non-empty, makes Guard's client present the given TLS
	// ClientHello (chrome_133, firefox, safari, ...) instead of Go's stock
	// hello. The matching User-Agent and Client Hints are stamped on each
	// request in Do(). Empty leaves the client unchanged.
	Fingerprint fingerprint.Profile

	// InsecureSkipVerify is passed through to the TLS client when Fingerprint
	// is set. Off by default; only flip it for self-signed lab targets.
	InsecureSkipVerify bool

	// DialControl, when set, is installed on the client's dialer. It runs with
	// the peer address already resolved, so a caller can re-apply the
	// authorization decision to the address actually dialed: the gate resolves
	// the target name, the dialer resolves it again, and DNS may answer
	// differently the second time. Nil leaves the dialer unchanged.
	DialControl func(network, address string, c syscall.RawConn) error

	// Proxy selects the HTTP proxy for a request, with the same signature as
	// http.Transport.Proxy. It is installed on the client's transport and used
	// by Do() to decide whether the destination needs an explicit check.
	//
	// This matters for CWE-290 (DNS rebinding): with a proxy in the path the
	// socket-level DialControl sees the PROXY address, never the destination,
	// so a name that resolved to an approved IP at gate time can rebind to
	// metadata/private space without the dial hook noticing. When Proxy returns
	// a proxy for a request, Do() resolves the destination itself and runs every
	// answer through DialControl via authz.CheckDialTarget. Nil means no proxy;
	// NewGuard defaults it to http.ProxyFromEnvironment.
	Proxy func(*http.Request) (*url.URL, error)
}

// Defaults. Exported so a caller can build a matching budget report.
const (
	DefaultRPS         = 10
	DefaultMaxRequests = 2000
	DefaultTimeout     = 10 * time.Second

	// defaultMaxRPS bounds the token-bucket refill interval away from zero.
	defaultMaxRPS = 100000

	// maxRateWait bounds how long Do() will wait for a rate token before
	// refusing, so a rate limit can never hang a scan forever.
	maxRateWait = 5 * time.Second

	// taintTTL bounds how long an intrusive refusal taints a target. The
	// defense is against a probe that ignores a Check(..., true) refusal and
	// calls Do() immediately, so a short window catches it while limiting
	// false positives for later passive requests to the same URL.
	taintTTL = 30 * time.Second

	// maxTaintedTargets bounds the taint registry so a long scan full of
	// refused intrusive probes cannot grow it without limit.
	maxTaintedTargets = 4096
)

// GuardStats is a snapshot of Guard's counters.
type GuardStats struct {
	RequestsSent      int64 `json:"requests_sent"`
	RequestsRefused   int64 `json:"requests_refused"`
	RefusedOutOfScope int64 `json:"refused_out_of_scope"`
	RefusedIntrusive  int64 `json:"refused_intrusive"`
	RefusedBudget     int64 `json:"refused_budget"`
	RefusedRate       int64 `json:"refused_rate"`
	RefusedDryRun     int64 `json:"refused_dry_run"`
	DryRunChecked     int64 `json:"dry_run_checked"`
	BytesRead         int64 `json:"bytes_read"`
}

type guardStatsInternal struct {
	requestsSent      atomic.Int64
	requestsRefused   atomic.Int64
	refusedOutOfScope atomic.Int64
	refusedIntrusive  atomic.Int64
	refusedBudget     atomic.Int64
	refusedRate       atomic.Int64
	refusedDryRun     atomic.Int64
	dryRunChecked     atomic.Int64
	bytesRead         atomic.Int64
}

// Guard is the core.Requester every probe uses.
type Guard struct {
	cfg      GuardConfig
	patterns []scopePattern
	limiter  *rateLimiter
	client   *http.Client
	budget   atomic.Int64 // requests reserved so far
	stats    guardStatsInternal

	// intrusiveTaint remembers targets refused by Check(..., true) so a probe
	// that ignores that refusal and calls Do() directly cannot send them.
	// Do() re-checks it as defense in depth. The registry is bounded and each
	// entry expires after taintTTL; see taintTarget.
	taintMu sync.Mutex
	taint   map[string]time.Time
}

// NewGuard validates cfg and builds a Guard. It fails on a non-finite or
// negative RPS, a negative budget/timeout/body-cap/burst, and any malformed
// allowlist pattern — a bad pattern is a configuration error, not something to
// discover mid-scan.
func NewGuard(cfg GuardConfig) (*Guard, error) {
	if math.IsNaN(cfg.RPS) || math.IsInf(cfg.RPS, 0) {
		return nil, fmt.Errorf("scanner: RPS must be a finite number, got %v", cfg.RPS)
	}
	if cfg.RPS < 0 {
		return nil, fmt.Errorf("scanner: RPS must not be negative, got %v", cfg.RPS)
	}
	if cfg.RPS > defaultMaxRPS {
		return nil, fmt.Errorf("scanner: RPS %v is unreasonably high (max %d)", cfg.RPS, defaultMaxRPS)
	}
	if cfg.Burst < 0 {
		return nil, fmt.Errorf("scanner: Burst must not be negative, got %d", cfg.Burst)
	}
	if cfg.MaxRequests < 0 {
		return nil, fmt.Errorf("scanner: MaxRequests must not be negative, got %d", cfg.MaxRequests)
	}
	if cfg.Timeout < 0 {
		return nil, fmt.Errorf("scanner: Timeout must not be negative, got %v", cfg.Timeout)
	}
	if cfg.MaxBodyBytes < 0 {
		return nil, fmt.Errorf("scanner: MaxBodyBytes must not be negative, got %d", cfg.MaxBodyBytes)
	}

	patterns, err := parseScopePatterns(cfg.Allow)
	if err != nil {
		return nil, err
	}

	rps := cfg.RPS
	if rps == 0 {
		rps = DefaultRPS
	}
	burst := cfg.Burst
	if burst == 0 {
		burst = int(math.Ceil(rps))
		if burst < 1 {
			burst = 1
		}
	}
	if cfg.MaxRequests == 0 {
		cfg.MaxRequests = DefaultMaxRequests
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.MaxBodyBytes == 0 {
		cfg.MaxBodyBytes = core.DefaultProbeLimit
	}
	if cfg.Proxy == nil {
		cfg.Proxy = http.ProxyFromEnvironment
	}
	cfg.RPS = rps
	cfg.Burst = burst

	g := &Guard{
		cfg:      cfg,
		patterns: patterns,
		limiter:  newRateLimiter(rps, burst),
	}
	if cfg.Fingerprint != fingerprint.Default {
		g.client = core.NewHTTPClientWithControl(cfg.Fingerprint, cfg.Timeout, cfg.InsecureSkipVerify, cfg.DialControl)
	} else {
		g.client = &http.Client{
			Timeout: cfg.Timeout,
			// Several checks need the raw 3xx and its Location header, so a
			// redirect must never be followed implicitly.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	if cfg.DialControl != nil {
		installDialControl(g.client, cfg.Timeout, cfg.DialControl, cfg.Proxy)
	}
	// Make the transport use the same proxy selector Do() checks, so the
	// authorization decision and the connection that is actually made agree.
	if tr, ok := g.client.Transport.(*http.Transport); ok && tr != nil {
		tr.Proxy = cfg.Proxy
	}
	return g, nil
}

// installDialControl puts control on the client's dialer, creating a transport
// when the client is using the package default. proxy is installed on that
// transport so an operator behind a proxy keeps working and Do() sees the same
// selector the connection uses.
func installDialControl(client *http.Client, timeout time.Duration, control func(network, address string, c syscall.RawConn) error, proxy func(*http.Request) (*url.URL, error)) {
	tr, ok := client.Transport.(*http.Transport)
	if !ok || tr == nil {
		tr = &http.Transport{Proxy: proxy}
		client.Transport = tr
	} else if proxy != nil {
		tr.Proxy = proxy
	}
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second, Control: control}
	tr.DialContext = dialer.DialContext
}

// Config returns the effective configuration (after defaults).
func (g *Guard) Config() GuardConfig { return g.cfg }

// DialControl returns the dial-time check this Guard installed on its HTTP
// client, or nil when none was configured.
//
// A scanner is not only HTTP: port, TLS and WebSocket probes dial sockets of
// their own. Handing them this hook keeps one authorization decision behind
// every connection the scan makes, instead of one for HTTP and a separate,
// unchecked path for the rest.
func (g *Guard) DialControl() func(network, address string, c syscall.RawConn) error {
	return g.cfg.DialControl
}

// Stats returns a snapshot of the counters.
func (g *Guard) Stats() GuardStats {
	return GuardStats{
		RequestsSent:      g.stats.requestsSent.Load(),
		RequestsRefused:   g.stats.requestsRefused.Load(),
		RefusedOutOfScope: g.stats.refusedOutOfScope.Load(),
		RefusedIntrusive:  g.stats.refusedIntrusive.Load(),
		RefusedBudget:     g.stats.refusedBudget.Load(),
		RefusedRate:       g.stats.refusedRate.Load(),
		RefusedDryRun:     g.stats.refusedDryRun.Load(),
		DryRunChecked:     g.stats.dryRunChecked.Load(),
		BytesRead:         g.stats.bytesRead.Load(),
	}
}

// Check applies policy without sending anything. It is advisory and has no
// side effects beyond refusal counters: it never consumes budget or a rate
// token, so a probe may call it freely before building a request.
//
// It returns exactly one of core.ErrOutOfScope, core.ErrIntrusiveDisabled or
// core.ErrBudgetExhausted when policy forbids the probe, and nil otherwise. In
// DryRun it returns nil (the request is within policy) and records the check in
// DryRunChecked; the refusal is applied by Do.
func (g *Guard) Check(ctx context.Context, method, rawURL string, intrusive bool) error {
	_ = ctx
	_ = method
	if g == nil {
		return core.ErrOutOfScope
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return g.refuse(fmt.Errorf("%w: unparseable url %q: %v", core.ErrOutOfScope, rawURL, err), nil)
	}
	if err := g.checkScope(u); err != nil {
		return g.refuse(err, nil)
	}
	if intrusive && !g.cfg.Intrusive {
		// Defense in depth: remember the target so a probe that ignores this
		// refusal and calls Do() directly still cannot send it.
		g.taintTarget(u)
		return g.refuse(core.ErrIntrusiveDisabled, nil)
	}
	if !g.cfg.DryRun && g.budget.Load() >= g.cfg.MaxRequests {
		return g.refuse(core.ErrBudgetExhausted, nil)
	}
	if g.cfg.DryRun {
		g.stats.dryRunChecked.Add(1)
	}
	return nil
}

// Do sends req through the rate limiter, budget, timeout, body cap and
// User-Agent policy. It re-checks scope first (defense in depth: a caller that
// skipped Check still cannot escape the allowlist). Redirects are never
// followed.
func (g *Guard) Do(req *http.Request) (*http.Response, error) {
	if g == nil {
		return nil, core.ErrOutOfScope
	}
	if req == nil || req.URL == nil {
		return nil, g.refuse(fmt.Errorf("%w: nil request", core.ErrOutOfScope), nil)
	}
	if g.cfg.DryRun {
		g.stats.refusedDryRun.Add(1)
		return nil, core.ErrDryRun
	}
	if err := g.checkScope(req.URL); err != nil {
		return nil, g.refuse(err, nil)
	}
	if g.isTainted(req.URL) {
		return nil, g.refuse(core.ErrIntrusiveDisabled, nil)
	}
	if err := g.checkProxyTarget(req); err != nil {
		return nil, g.refuse(err, nil)
	}
	if !g.reserveBudget() {
		return nil, g.refuse(core.ErrBudgetExhausted, nil)
	}
	if err := g.acquireRate(req.Context(), strings.ToLower(req.URL.Host)); err != nil {
		return nil, g.refuse(err, nil)
	}
	if g.cfg.Fingerprint != fingerprint.Default {
		core.ApplyHeaders(req, g.cfg.Fingerprint)
	} else if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", core.ScannerUserAgent)
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	g.stats.requestsSent.Add(1)
	// Cap the body at the Guard level too, so a caller that ignores core.ReadBody's
	// limit still cannot be made to read an unbounded response.
	resp.Body = &cappedBody{rc: resp.Body, remaining: g.cfg.MaxBodyBytes, g: g}
	return resp, nil
}

// refuse records a refusal and returns it.
func (g *Guard) refuse(err error, _ *string) error {
	g.stats.requestsRefused.Add(1)
	switch {
	case errors.Is(err, core.ErrOutOfScope):
		g.stats.refusedOutOfScope.Add(1)
	case errors.Is(err, core.ErrIntrusiveDisabled):
		g.stats.refusedIntrusive.Add(1)
	case errors.Is(err, core.ErrBudgetExhausted):
		g.stats.refusedBudget.Add(1)
	case errors.Is(err, core.ErrRateLimited):
		g.stats.refusedRate.Add(1)
	case errors.Is(err, core.ErrDryRun):
		g.stats.refusedDryRun.Add(1)
	}
	return err
}

// reserveBudget increments the budget counter only if it stays within the cap.
func (g *Guard) reserveBudget() bool {
	for {
		cur := g.budget.Load()
		if cur >= g.cfg.MaxRequests {
			return false
		}
		if g.budget.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

// acquireRate waits (bounded) for a token for key, or refuses.
func (g *Guard) acquireRate(ctx context.Context, key string) error {
	deadline := time.Now().Add(maxRateWait)
	for {
		if g.limiter.tryTake(key, time.Now()) {
			return nil
		}
		if !time.Now().Before(deadline) {
			return core.ErrRateLimited
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(g.limiter.tick()):
		}
	}
}

// checkScope enforces structural validity plus the allowlist.
func (g *Guard) checkScope(u *url.URL) error {
	if u == nil {
		return fmt.Errorf("%w: nil url", core.ErrOutOfScope)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("%w: scheme %q is not http(s)", core.ErrOutOfScope, u.Scheme)
	}
	if u.User != nil {
		return fmt.Errorf("%w: url carries userinfo", core.ErrOutOfScope)
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return fmt.Errorf("%w: url has no host", core.ErrOutOfScope)
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("%w: invalid port %q", core.ErrOutOfScope, p)
		}
	}
	if g.cfg.AllowAll {
		return nil
	}
	if len(g.patterns) == 0 {
		return fmt.Errorf("%w: the allowlist is empty (fail-closed)", core.ErrOutOfScope)
	}
	effPort := effectivePort(u)
	escPath := u.EscapedPath()
	if escPath == "" {
		escPath = "/"
	}
	for _, p := range g.patterns {
		if p.matches(host, effPort, escPath) {
			return nil
		}
	}
	return fmt.Errorf("%w: %s is not covered by any allowed pattern", core.ErrOutOfScope, host)
}

func effectivePort(u *url.URL) int {
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			return n
		}
	}
	if strings.EqualFold(u.Scheme, "https") {
		return 443
	}
	return 80
}

// ── intrusive taint ─────────────────────────────────────────────────────────

// taintTarget records u as a target whose intrusive use was refused. It is
// bounded and TTL'd: expired entries are swept first, then an arbitrary entry
// is evicted if the registry is still full. Dropping a taint only weakens the
// defense-in-depth layer; the primary gate is Check itself.
func (g *Guard) taintTarget(u *url.URL) {
	if u == nil {
		return
	}
	key := taintKey(u)
	now := time.Now()

	g.taintMu.Lock()
	defer g.taintMu.Unlock()
	if g.taint == nil {
		g.taint = make(map[string]time.Time)
	}
	for k, exp := range g.taint {
		if !now.Before(exp) {
			delete(g.taint, k)
		}
	}
	for len(g.taint) >= maxTaintedTargets {
		for k := range g.taint {
			delete(g.taint, k)
			break
		}
	}
	g.taint[key] = now.Add(taintTTL)
}

// isTainted reports whether u was refused as intrusive recently. An expired
// entry is removed and treated as absent, so the registry cannot grow forever
// for a target that is only checked once.
func (g *Guard) isTainted(u *url.URL) bool {
	if u == nil {
		return false
	}
	key := taintKey(u)
	now := time.Now()

	g.taintMu.Lock()
	defer g.taintMu.Unlock()
	exp, ok := g.taint[key]
	if !ok {
		return false
	}
	if !now.Before(exp) {
		delete(g.taint, key)
		return false
	}
	return true
}

// taintKey canonicalises a URL for the taint registry. scheme and host are
// case-insensitive; the escaped path and raw query identify the specific
// target. Query is included so refusing an intrusive payload on /api?q=...
// does not also block a passive request to the clean /api.
func taintKey(u *url.URL) string {
	key := strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + u.EscapedPath()
	if u.RawQuery != "" {
		key += "?" + u.RawQuery
	}
	return key
}

// checkProxyTarget re-applies the authorization decision to the destination
// when the request is going through a proxy. The socket-level DialControl sees
// the proxy address in that case, so without this check a destination that
// resolves to an approved IP at gate time could rebind to metadata or private
// space unnoticed (CWE-290). It is a no-op when no DialControl or Proxy is set.
func (g *Guard) checkProxyTarget(req *http.Request) error {
	if g.cfg.DialControl == nil || g.cfg.Proxy == nil {
		return nil
	}
	proxyURL, err := g.cfg.Proxy(req)
	if err != nil || proxyURL == nil {
		return nil // no proxy applies; the dial hook sees the real target
	}
	host := req.URL.Hostname()
	if host == "" {
		return fmt.Errorf("%w: proxy dial target has no host", core.ErrOutOfScope)
	}
	port := req.URL.Port()
	if port == "" {
		port = strconv.Itoa(effectivePort(req.URL))
	}
	if err := authz.CheckDialTarget(req.Context(), host, port, g.cfg.DialControl); err != nil {
		return fmt.Errorf("%w: %v", core.ErrOutOfScope, err)
	}
	return nil
}

// ── scope patterns ──────────────────────────────────────────────────────────

type patternKind int

const (
	patExact patternKind = iota
	patWildcard
	patIP
	patCIDR
)

type scopePattern struct {
	raw        string
	kind       patternKind
	host       string // exact/wildcard base, lowercased
	ip         net.IP
	ipnet      *net.IPNet
	port       int
	portSet    bool
	pathPrefix string
}

func parseScopePatterns(entries []string) ([]scopePattern, error) {
	out := make([]scopePattern, 0, len(entries))
	for _, entry := range entries {
		p, err := parseScopePattern(entry)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func parseScopePattern(entry string) (scopePattern, error) {
	fields := strings.Fields(strings.TrimSpace(entry))
	if len(fields) == 0 {
		return scopePattern{}, fmt.Errorf("scanner: empty scope pattern")
	}
	if len(fields) > 2 {
		return scopePattern{}, fmt.Errorf("scanner: scope pattern %q has too many fields", entry)
	}
	netloc := fields[0]
	pathPrefix := ""
	if len(fields) == 2 {
		if !strings.HasPrefix(fields[1], "/") {
			return scopePattern{}, fmt.Errorf("scanner: scope pattern %q: path prefix must start with /", entry)
		}
		pathPrefix = strings.TrimSuffix(fields[1], "/")
		if pathPrefix == "" {
			pathPrefix = "/"
		}
	}

	p := scopePattern{raw: entry, pathPrefix: pathPrefix}

	// CIDR first: it is the only case where "/" is a mask, not a path.
	if _, ipnet, err := net.ParseCIDR(netloc); err == nil {
		p.kind = patCIDR
		p.ipnet = ipnet
		return p, nil
	}

	host, port, portSet, err := splitHostPort(netloc)
	if err != nil {
		return scopePattern{}, fmt.Errorf("scanner: scope pattern %q: %v", entry, err)
	}
	if strings.Contains(host, "/") {
		return scopePattern{}, fmt.Errorf("scanner: scope pattern %q: put a space before a path prefix", entry)
	}
	if host == "" {
		return scopePattern{}, fmt.Errorf("scanner: scope pattern %q: empty host", entry)
	}
	p.port, p.portSet = port, portSet
	host = strings.ToLower(host)

	if ip := net.ParseIP(host); ip != nil {
		p.kind = patIP
		p.ip = ip
		return p, nil
	}
	if strings.HasPrefix(host, "*.") {
		base := host[2:]
		if base == "" || strings.Contains(base, "*") {
			return scopePattern{}, fmt.Errorf("scanner: scope pattern %q: malformed wildcard", entry)
		}
		p.kind = patWildcard
		p.host = base
		return p, nil
	}
	if strings.Contains(host, "*") {
		return scopePattern{}, fmt.Errorf("scanner: scope pattern %q: '*' is only valid as a leading '*'", entry)
	}
	p.kind = patExact
	p.host = host
	return p, nil
}

// splitHostPort splits a netloc into host and optional port, understanding
// bracketed IPv6 and bare (unbracketed, portless) IPv6.
func splitHostPort(s string) (host string, port int, portSet bool, err error) {
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 {
			return "", 0, false, fmt.Errorf("unclosed '[' in %q", s)
		}
		host = s[1:end]
		rest := s[end+1:]
		if rest == "" {
			return host, 0, false, nil
		}
		if !strings.HasPrefix(rest, ":") {
			return "", 0, false, fmt.Errorf("unexpected %q after ']'", rest)
		}
		p, e := strconv.Atoi(rest[1:])
		if e != nil || p < 1 || p > 65535 {
			return "", 0, false, fmt.Errorf("invalid port %q", rest[1:])
		}
		return host, p, true, nil
	}
	if strings.Count(s, ":") > 1 {
		// Bare IPv6 literal; a port would need brackets.
		return s, 0, false, nil
	}
	if i := strings.LastIndex(s, ":"); i >= 0 {
		ps := s[i+1:]
		p, e := strconv.Atoi(ps)
		if e != nil || p < 1 || p > 65535 {
			return "", 0, false, fmt.Errorf("invalid port %q", ps)
		}
		return s[:i], p, true, nil
	}
	return s, 0, false, nil
}

func (p scopePattern) matches(host string, effPort int, escPath string) bool {
	if p.portSet && p.port != effPort {
		return false
	}
	if !p.matchPath(escPath) {
		return false
	}
	switch p.kind {
	case patExact:
		return host == p.host
	case patWildcard:
		// Subdomains only: the apex (host == base) is deliberately excluded.
		return host != p.host && strings.HasSuffix(host, "."+p.host)
	case patIP:
		ip := net.ParseIP(host)
		return ip != nil && p.ip.Equal(ip)
	case patCIDR:
		ip := net.ParseIP(host)
		return ip != nil && p.ipnet.Contains(ip)
	}
	return false
}

// matchPath is segment-aware: "/api" matches "/api" and "/api/users" but never
// "/apix".
func (p scopePattern) matchPath(escPath string) bool {
	if p.pathPrefix == "" {
		return true
	}
	if p.pathPrefix == "/" {
		return true
	}
	return escPath == p.pathPrefix || strings.HasPrefix(escPath, p.pathPrefix+"/")
}

// ── rate limiter ────────────────────────────────────────────────────────────

type rateLimiter struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(rate float64, burst int) *rateLimiter {
	return &rateLimiter{rate: rate, burst: float64(burst), buckets: map[string]*bucket{}}
}

// tick returns the interval between tokens, clamped to a sane minimum.
func (rl *rateLimiter) tick() time.Duration {
	if rl.rate <= 0 {
		return time.Millisecond
	}
	d := time.Duration(float64(time.Second) / rl.rate)
	if d < time.Millisecond {
		d = time.Millisecond
	}
	return d
}

func (rl *rateLimiter) tryTake(key string, now time.Time) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	b := rl.buckets[key]
	if b == nil {
		b = &bucket{tokens: rl.burst, last: now}
		rl.buckets[key] = b
	} else if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = math.Min(rl.burst, b.tokens+elapsed*rl.rate)
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// ── capped body ─────────────────────────────────────────────────────────────

// cappedBody enforces MaxBodyBytes regardless of how the caller reads.
type cappedBody struct {
	rc        io.ReadCloser
	remaining int64
	g         *Guard
}

func (c *cappedBody) Read(p []byte) (int, error) {
	if c.remaining <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.rc.Read(p)
	if n > 0 {
		c.remaining -= int64(n)
		c.g.stats.bytesRead.Add(int64(n))
	}
	return n, err
}

func (c *cappedBody) Close() error { return c.rc.Close() }
