package dashboard

import (
	"time"
)

// --- Types ------------------------------------------------------------------

type LiveSnapshot struct {
	Timestamp   time.Time      `json:"timestamp"`
	RPS         float64        `json:"rps"`
	TotalReq    uint64         `json:"total_requests"`
	TotalErrors uint64         `json:"total_errors"`
	ErrorRate   float64        `json:"error_rate"`
	P50Latency  float64        `json:"p50_latency_ms"`
	P95Latency  float64        `json:"p95_latency_ms"`
	P99Latency  float64        `json:"p99_latency_ms"`
	AvgLatency  float64        `json:"avg_latency_ms"`
	MaxLatency  float64        `json:"max_latency_ms"`
	ActiveUsers int            `json:"active_users"`
	StatusCodes map[int]uint64 `json:"status_codes"`
	Workers     []WorkerStatus `json:"workers,omitempty"`
}

type WorkerStatus struct {
	ID      string  `json:"id"`
	Address string  `json:"address"`
	Status  string  `json:"status"`
	RPS     float64 `json:"rps"`
	Latency float64 `json:"latency_ms"`
	Errors  uint64  `json:"errors"`
}

type RunConfig struct {
	TargetURL       string            `json:"target_url"`
	Users           int               `json:"users"`
	DurationSeconds int               `json:"duration_seconds"`
	RateLimit       int               `json:"rate_limit"`
	Method          string            `json:"method"`
	Headers         map[string]string `json:"headers,omitempty"`
	Body            string            `json:"body,omitempty"`
	Profile         string            `json:"profile,omitempty"`
	TLSFingerprint  string            `json:"tls_fingerprint,omitempty"`
}

type RunState struct {
	Status    string        `json:"status"`
	Config    *RunConfig    `json:"config,omitempty"`
	StartTime time.Time     `json:"start_time,omitempty"`
	EndTime   time.Time     `json:"end_time,omitempty"`
	Elapsed   time.Duration `json:"elapsed"`
	Duration  time.Duration `json:"duration"`
	Progress  float64       `json:"progress"`
	Error     string        `json:"error,omitempty"`
}

type HistoryEntry struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Config    RunConfig `json:"config"`
	Result    RunResult `json:"result"`
	Duration  string    `json:"duration"`
}

type RunResult struct {
	TotalRequests uint64         `json:"total_requests"`
	TotalErrors   uint64         `json:"total_errors"`
	RPS           float64        `json:"rps"`
	P50Latency    float64        `json:"p50_latency"`
	P95Latency    float64        `json:"p95_latency"`
	P99Latency    float64        `json:"p99_latency"`
	AvgLatency    float64        `json:"avg_latency"`
	MaxLatency    float64        `json:"max_latency"`
	StatusCodes   map[int]uint64 `json:"status_codes"`
}

// AttestationInfo holds the latest attestation state produced by a completed run.
type AttestationInfo struct {
	Exists      bool   `json:"exists"`
	RunID       string `json:"runID,omitempty"`
	PubKeyHex   string `json:"pubKeyHex,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`

	// COCorrected reports whether the bundle's percentiles carry the
	// coordinated-omission correction. Dashboard runs never set
	// profile.coordinated_omission, so this is false and the UI must say the
	// percentiles are raw — claiming the correction would be the exact
	// dishonesty this tool exists to expose.
	COCorrected bool `json:"coCorrected"`

	// BundlePath and SamplesPath are absolute, server-local filesystem paths.
	// They are deliberately NOT serialised. The browser fetches the artifacts
	// through /api/attestation/download?type=..., so it never needs to learn
	// where they live on disk — and because the dashboard can be bound beyond
	// loopback, a remote client must not be handed the host's directory layout.
	BundlePath  string `json:"-"`
	SamplesPath string `json:"-"`
}

// AttestationVerifyRequest is the body of POST /api/attestation/verify. It is
// deliberately empty: the endpoint verifies the attestation the dashboard
// itself produced for the latest run.
//
// It must never grow a caller-supplied path field. verify loads and parses a
// file from disk, so honouring a caller-supplied path would turn the local
// control plane into an arbitrary-file-read oracle. Decoding uses
// DisallowUnknownFields, so a body that names a path is rejected (400) rather
// than silently ignored.
type AttestationVerifyRequest struct{}
