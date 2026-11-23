package replay

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// --- Core Types -------------------------------------------------------------

// Capture is a parsed traffic capture with its packets, TLS material, and time bounds.
type Capture struct {
	Source    string
	Format    CaptureFormat
	Packets   []*Packet
	Sessions  map[string]*TLSSession
	TLSKeys   []*TLSKey
	StartTime time.Time
	EndTime   time.Time
	Metadata  map[string]string
	mu        sync.RWMutex
}

// CaptureFormat identifies the container format a Capture was read from.
type CaptureFormat string

const (
	// FormatPCAP marks a capture read from a PCAP file.
	FormatPCAP CaptureFormat = "pcap"
	// FormatHAR marks a capture read from a HAR file.
	FormatHAR CaptureFormat = "har"
)

// TLSKey pairs an address with the client certificate used for its traffic.
type TLSKey struct {
	IP   string
	Port int
	Key  *tls.Certificate
}

// TLSSession holds the key material negotiated for one TLS connection.
type TLSSession struct {
	ClientRandom []byte
	ServerRandom []byte
	MasterSecret []byte
	CipherSuite  uint16
	Key          *TLSKey
}

// Packet is one replayable HTTP request extracted from a capture.
type Packet struct {
	Timestamp time.Time
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   int
	DstPort   int
	Protocol  string
	Method    string
	URL       string
	Headers   http.Header
	Body      []byte
	Response  *Response
	StreamID  uint32
	IsRequest bool
}

// Response is the recorded HTTP response associated with a Packet.
type Response struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
	Timestamp  time.Time
	Duration   time.Duration
}

// ReplayPacing selects how a replay spaces captured requests over time.
type ReplayPacing string //nolint:revive // reason: renaming exported identifier would break the public API

const (
	// PacingTiming replays packets at their captured inter-request gaps,
	// scaled by RateMultiplier (rate=1 is real-time).
	PacingTiming ReplayPacing = "timing"
	// PacingRPS paces requests at a constant rate defined by RPS.
	PacingRPS ReplayPacing = "rps"
	// PacingLegacy keeps the original fixed 1s/RateMultiplier behavior.
	PacingLegacy ReplayPacing = "legacy"
)

// ReplayConfig controls rate, concurrency, filtering, and validation for a replay run.
type ReplayConfig struct { //nolint:revive // reason: renaming exported identifier would break the public API
	RateMultiplier float64
	MaxConcurrency int
	Duration       time.Duration
	Pacing         ReplayPacing
	RPS            float64
	BaseURL        string
	// AllowOriginalDestinations permits requests to the hosts recorded in the
	// capture. It is off by default: a HAR/PCAP may contain internal or
	// cloud-metadata URLs together with captured auth headers, so replaying it
	// unmodified would turn the operator's host into an SSRF/exfiltration proxy.
	// Set BaseURL or this flag explicitly to override the safety check.
	AllowOriginalDestinations bool
	SkipTLSVerify             bool
	TLSKeys                   []*TLSKey
	FollowRedirects           bool
	ValidateResponse          bool
	Assertions                []Assertion
	OutputReport              bool
	ReportDir                 string
	Filter                    *PacketFilter
	// DialControl is an optional socket-level authorization hook. It runs
	// after DNS resolution on every dial, so a name approved at gate time
	// cannot rebind to a private or metadata address before connect. Nil keeps
	// replay's historical direct behavior for dev and tests. Runtime-only.
	DialControl func(network, address string, c syscall.RawConn) error `json:"-"`
}

// PacketFilter selects packets by method, URL, status, latency, protocol, and host.
type PacketFilter struct {
	Methods     []string
	URLPatterns []string
	StatusCodes []int
	MinLatency  time.Duration
	MaxLatency  time.Duration
	Protocols   []string
	Hosts       []string
}

// Assertion is one response check identified by type and expected value.
type Assertion struct {
	Type  string
	Value string
}

// ReplayResult aggregates counters and latency percentiles for a completed replay run.
type ReplayResult struct { //nolint:revive // reason: renaming exported identifier would break the public API
	Capture      *Capture        `json:"-"`
	Config       *ReplayConfig   `json:"-"`
	StartTime    time.Time       `json:"start_time"`
	EndTime      time.Time       `json:"end_time"`
	TotalPackets int             `json:"total_packets"`
	Replayed     int             `json:"replayed"`
	Succeeded    int             `json:"succeeded"`
	Failed       int             `json:"failed"`
	Errors       map[string]int  `json:"errors"`
	Latencies    []time.Duration `json:"-"`
	AvgLatency   time.Duration   `json:"avg_latency_ms"`
	P50Latency   time.Duration   `json:"p50_latency_ms"`
	P95Latency   time.Duration   `json:"p95_latency_ms"`
	P99Latency   time.Duration   `json:"p99_latency_ms"`
}

// --- Capture Methods --------------------------------------------------------

// AddPacket appends a packet and extends the capture time bounds under the capture lock.
func (c *Capture) AddPacket(p *Packet) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Sessions == nil {
		c.Sessions = make(map[string]*TLSSession)
	}
	if c.Metadata == nil {
		c.Metadata = make(map[string]string)
	}
	c.Packets = append(c.Packets, p)
	if c.StartTime.IsZero() || p.Timestamp.Before(c.StartTime) {
		c.StartTime = p.Timestamp
	}
	if p.Timestamp.After(c.EndTime) {
		c.EndTime = p.Timestamp
	}
}

// Filter returns packets matching f, or all packets when f is nil.
func (c *Capture) Filter(f *PacketFilter) []*Packet {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var out []*Packet
	for _, p := range c.Packets {
		if matchesFilter(p, f) {
			out = append(out, p)
		}
	}
	return out
}

// ExportJSON writes the capture as indented JSON to w.
func (c *Capture) ExportJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(c)
}

// --- TLS Helpers ------------------------------------------------------------

// TLSConfigFromKeys builds a TLS config from keys with a minimum version of TLS 1.2.
func TLSConfigFromKeys(keys []*TLSKey, skipVerify bool) *tls.Config {
	cfg := &tls.Config{
		InsecureSkipVerify: skipVerify, // #nosec G402 -- replay intentionally supports operator-controlled skip-verify for capturing/replaying targets with non-public TLS setups.
		MinVersion:         tls.VersionTLS12,
	}
	if len(keys) > 0 {
		certs := make([]tls.Certificate, 0, len(keys))
		for _, k := range keys {
			if k.Key != nil {
				certs = append(certs, *k.Key)
			}
		}
		cfg.Certificates = certs
	}
	return cfg
}

// --- Filtering Helpers ------------------------------------------------------

func matchesFilter(p *Packet, f *PacketFilter) bool {
	if f == nil {
		return true
	}
	if len(f.Methods) > 0 && !contains(f.Methods, p.Method) {
		return false
	}
	if len(f.Protocols) > 0 && !contains(f.Protocols, p.Protocol) {
		return false
	}
	if len(f.Hosts) > 0 {
		u, _ := url.Parse(p.URL)
		if u != nil && !contains(f.Hosts, u.Host) {
			return false
		}
	}
	if len(f.URLPatterns) > 0 {
		found := false
		for _, pat := range f.URLPatterns {
			if pat == "*" || strings.Contains(p.URL, pat) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if p.Response != nil {
		if len(f.StatusCodes) > 0 && !containsInt(f.StatusCodes, p.Response.StatusCode) {
			return false
		}
		if f.MinLatency > 0 && p.Response.Duration < f.MinLatency {
			return false
		}
		if f.MaxLatency > 0 && p.Response.Duration > f.MaxLatency {
			return false
		}
	}
	return true
}

func contains[T comparable](slice []T, val T) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}

func containsInt(slice []int, val int) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}

func calcPercentile(sorted []time.Duration, pct float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	idx := int(float64(len(sorted)-1) * pct / 100.0)
	return sorted[idx]
}
