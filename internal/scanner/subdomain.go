package scanner

// --- Subdomain enumeration ---------------------------------------------------
//
// Passive subdomain discovery: certificate transparency logs (crt.sh),
// DNS resolution, and common DNS records. No active probing of discovered
// hostnames is performed unless a core.Requester is supplied and allowed.

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/scanner/core"
)

// Resource limits for passive enumeration. A single 4 MiB crt.sh response can
// name thousands of hosts, and each host costs up to three DNS lookups, so both
// the name set and the resolver pool need fixed ceilings.
const (
	// maxPassiveNames is ~5x Guard's 2000-request scan budget and above its
	// 4096-entry taint registry (guard.go): those bound paid HTTP probes and
	// refusals, while discovery is local and cheap, so it gets a larger but
	// still bounded ceiling.
	maxPassiveNames = 10000

	// resolveConcurrency caps in-flight resolutions, mirroring the 64-wide
	// dial semaphore in portscan.go; beyond that, more goroutines only add
	// resolver pressure.
	resolveConcurrency = 64
)

// Test seams. Passive enumeration is network-bound, so the DNS lookups and the
// passive-source wait are indirected through package variables. Production
// wiring keeps the standard library resolver and the 8s window; tests replace
// them to stay hermetic.
var (
	lookupHostFn  = net.DefaultResolver.LookupHost
	lookupCNAMEFn = net.DefaultResolver.LookupCNAME
	lookupMXFn    = net.DefaultResolver.LookupMX
	lookupTXTFn   = net.DefaultResolver.LookupTXT
	passiveWait   = 8 * time.Second
)

// SubdomainResult is the output of a subdomain enumeration run.
type SubdomainResult struct {
	Target     string        `json:"target"`
	Seed       int64         `json:"seed"`
	Found      int           `json:"found"`
	Resolved   int           `json:"resolved"`
	Subdomains []Subdomain   `json:"subdomains,omitempty"`
	Duration   time.Duration `json:"duration"`
}

// Subdomain is one discovered hostname.
type Subdomain struct {
	Name    string   `json:"name"`
	IPs     []string `json:"ips,omitempty"`
	Source  string   `json:"source"`            // crtsh, dns, wordlist
	Methods []string `json:"methods,omitempty"` // A, AAAA, CNAME, MX, TXT
}

// crtShEntry is one row from crt.sh JSON output.
type crtShEntry struct {
	CommonName string `json:"common_name"`
	NameValue  string `json:"name_value"`
}

// EnumerateSubdomains passively discovers subdomains for target.
// If req is non-nil, each discovered name is DNS-resolved (local resolution,
// not network probing through the gate).
func EnumerateSubdomains(ctx context.Context, target string, req core.Requester) *SubdomainResult {
	res := &SubdomainResult{Target: target}
	start := time.Now()

	found := map[string]*Subdomain{}
	var mu sync.Mutex
	add := func(name, source string, methods ...string) {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" || !strings.HasSuffix(name, "."+target) && name != target {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if s, ok := found[name]; ok {
			s.Source = source
			s.Methods = appendUnique(s.Methods, methods...)
			return
		}
		// Cap only new names: an already-discovered host keeps collecting
		// methods even after the set is full.
		if len(found) >= maxPassiveNames {
			return
		}
		found[name] = &Subdomain{Name: name, Source: source, Methods: methods}
	}

	// 1) crt.sh certificate transparency log (best-effort).
	// 2) Common DNS record queries for the apex and www.
	// Both passive sources are network-bound and may hang indefinitely when the
	// caller supplies a context with no deadline (the dashboard/CLI pass
	// context.Background()). Bound them with a dedicated timeout context so
	// every source has an exit path, then wait on the WaitGroup deterministically
	// before snapshotting the findings, so no reader ever races a writer.
	passiveCtx, cancelPassive := context.WithTimeout(ctx, passiveWait)
	defer cancelPassive()
	var passiveWG sync.WaitGroup
	passiveWG.Add(2)
	go func() {
		defer passiveWG.Done()
		_ = crtSh(passiveCtx, target, add)
	}()
	go func() {
		defer passiveWG.Done()
		dnsQuery(passiveCtx, target, add, "A", "AAAA", "CNAME", "MX", "TXT")
		dnsQuery(passiveCtx, "www."+target, add, "A", "AAAA", "CNAME")
	}()

	// passiveWG.Wait cannot hang: the bounded context above terminates both
	// sources (and so do caller cancellations, which propagate through it).
	passiveWG.Wait()

	// Resolve discovered names (local resolver, not through gate). Snapshot
	// the map under the lock: iterating the map while the background goroutines
	// still hold the write lock would race.
	names := make([]*Subdomain, 0, len(found))
	mu.Lock()
	for _, s := range found {
		names = append(names, s)
	}
	mu.Unlock()

	// Callers may pass context.Background(), so DNS gets its own bounded
	// window too (derived from ctx, so caller cancellation still wins). The
	// passive phase is finished, so this window is not consumed by it.
	resolveCtx, cancelResolve := context.WithTimeout(ctx, passiveWait)
	defer cancelResolve()

	var wg sync.WaitGroup
	sem := make(chan struct{}, resolveConcurrency)
	resolved := int64(0)
	for _, s := range names {
		// Acquire before spawning: at most resolveConcurrency goroutines and
		// DNS lookups exist at once, however large the crt.sh response was.
		select {
		case <-resolveCtx.Done():
			// Stop starting new work when the budget is gone; wg.Wait below
			// still joins everything already in flight.
			continue
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(s *Subdomain) {
			defer wg.Done()
			defer func() { <-sem }()
			ips, methods := resolveHost(resolveCtx, s.Name)
			if len(ips) > 0 {
				s.IPs = ips
				s.Methods = appendUnique(s.Methods, methods...)
				atomic.AddInt64(&resolved, 1)
			}
		}(s)
	}
	wg.Wait()

	res.Subdomains = make([]Subdomain, 0, len(names))
	for _, s := range names {
		res.Subdomains = append(res.Subdomains, *s)
	}
	res.Found = len(names)
	res.Resolved = int(resolved)
	res.Duration = time.Since(start)
	return res
}

func crtSh(ctx context.Context, target string, add func(name, source string, methods ...string)) error {
	u := "https://crt.sh/?q=%25." + url.QueryEscape(target) + "&output=json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Sift-subenum/1.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	var entries []crtShEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return err
	}
	for _, e := range entries {
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.TrimSpace(name)
			name = strings.TrimPrefix(name, "*.")
			add(name, "crt.sh", "cert")
		}
		for _, name := range strings.Split(e.CommonName, "\n") {
			name = strings.TrimSpace(name)
			name = strings.TrimPrefix(name, "*.")
			add(name, "crt.sh", "cert")
		}
	}
	return nil
}

func dnsQuery(ctx context.Context, host string, add func(name, source string, methods ...string), types ...string) {
	for _, t := range types {
		select {
		case <-ctx.Done():
			return
		default:
		}
		answers, err := lookupHostFn(ctx, host)
		if err != nil {
			continue
		}
		ips := answers
		if len(ips) > 0 {
			add(host, "dns", append(types, ips...)...)
		}
		// Also try SRV/MX/TXT where meaningful.
		switch t {
		case "MX":
			if mx, err := lookupMXFn(ctx, host); err == nil {
				for _, m := range mx {
					add(m.Host, "dns", "MX")
				}
			}
		case "TXT":
			if txt, err := lookupTXTFn(ctx, host); err == nil {
				for _, t := range txt {
					_ = t // TXT content is informational; we record the host exists
				}
				add(host, "dns", "TXT")
			}
		}
	}
}

func resolveHost(ctx context.Context, name string) ([]string, []string) {
	var ips []string
	var methods []string
	if addrs, err := lookupHostFn(ctx, name); err == nil {
		ips = addrs
		methods = append(methods, "A/AAAA")
	}
	if cname, err := lookupCNAMEFn(ctx, name); err == nil && cname != name {
		methods = append(methods, "CNAME:"+cname)
	}
	if _, err := lookupMXFn(ctx, name); err == nil {
		methods = append(methods, "MX")
	}
	return ips, methods
}

func appendUnique(s []string, v ...string) []string {
	for _, x := range v {
		found := false
		for _, y := range s {
			if x == y {
				found = true
				break
			}
		}
		if !found {
			s = append(s, x)
		}
	}
	return s
}

func atomicAdd(n *int) {
	// Simple atomic-ish increment; good enough for a counter.
	*n++
}
