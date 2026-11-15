package audit360

import "time"

// Stage identifiers for progress reporting.
const (
	StageScan       = "scan_security"
	StageStress     = "test_load"
	StageResilience = "calculate_resilience"
	StageSeal       = "seal_certificate"
)

// StageStatus values.
const (
	StatusPending   = "pending"
	StatusRunning   = "running"
	StatusCompleted = "completed"
	StatusFailed    = "failed"
	StatusSkipped   = "skipped"
)

// Risk levels for the executive report.
const (
	RiskLow      = "Low Risk"
	RiskModerate = "Moderate Risk"
	RiskCritical = "Critical Risk"
)

// StageProgress describes one pipeline stage for UI/polling.
type StageProgress struct {
	ID        string    `json:"id"`
	Label     string    `json:"label"`
	Status    string    `json:"status"` // pending|running|completed|failed|skipped
	StartedAt time.Time `json:"started_at,omitempty"`
	EndedAt   time.Time `json:"ended_at,omitempty"`
	Detail    string    `json:"detail,omitempty"`
	Error     string    `json:"error,omitempty"`
}

// Finding is a normalized, non-technical-friendly issue entry.
type Finding struct {
	Title         string `json:"title"`
	Severity      string `json:"severity"` // critical|high|medium|low|info
	ImpactSummary string `json:"impact_summary"`
	Remediation   string `json:"remediation"`
	Source        string `json:"source,omitempty"` // security_scan|stress_test|system
}

// Audit360Report is the final signed report.
type Audit360Report struct {
	ResilienceScore    int       `json:"resilience_score"`
	RiskLevel          string    `json:"risk_level"`
	BreakingPointUsers int       `json:"breaking_point_users,omitempty"`
	MaxSafeRPS         float64   `json:"max_safe_rps,omitempty"`
	Findings           []Finding `json:"findings"`
	VPMPSignature      string    `json:"vpmp_signature"`
	CertificateID      string    `json:"certificate_id"`
	Timestamp          string    `json:"timestamp"` // ISO8601
	TargetURL          string    `json:"target_url"`
	DurationMS         int64     `json:"duration_ms"`
	Notes              []string  `json:"notes,omitempty"`

	// Optional transparency fields (additive, not part of strict required schema).
	BreakingPointReached bool    `json:"breaking_point_reached"`
	MaxObservedRPS       float64 `json:"max_observed_rps,omitempty"`
	StressTestAvailable  bool    `json:"stress_test_available"`
	SecurityScanPartial  bool    `json:"security_scan_partial,omitempty"`
}

// JobStatus is returned by polling/SSE status endpoint.
type JobStatus struct {
	JobID        string          `json:"job_id"`
	TargetURL    string          `json:"target_url"`
	State        string          `json:"state"` // queued|running|completed|failed
	StartedAt    time.Time       `json:"started_at,omitempty"`
	UpdatedAt    time.Time       `json:"updated_at,omitempty"`
	FinishedAt   time.Time       `json:"finished_at,omitempty"`
	CurrentStage string          `json:"current_stage,omitempty"`
	Stages       []StageProgress `json:"stages"`
	ProgressPct  int             `json:"progress_pct"`
	Error        string          `json:"error,omitempty"`
	Report       *Audit360Report `json:"report,omitempty"`
}

// StartRequest is POST /api/audit-360 body.
type StartRequest struct {
	TargetURL      string `json:"target_url"`
	Authorized     bool   `json:"authorized"`
	MaxDurationSec int    `json:"max_duration_sec"`
}

// StartResponse is returned by POST /api/audit-360.
type StartResponse struct {
	OK        bool   `json:"ok"`
	JobID     string `json:"job_id,omitempty"`
	StatusURL string `json:"status_url,omitempty"`
	StreamURL string `json:"stream_url,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Event is an SSE/push event payload.
type Event struct {
	Type   string          `json:"type"` // status|stage|completed|failed
	Status *JobStatus      `json:"status,omitempty"`
	Report *Audit360Report `json:"report,omitempty"`
	Error  string          `json:"error,omitempty"`
}
