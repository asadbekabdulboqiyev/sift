package audit360

import (
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/finding"
)

// Stage identifiers for progress reporting.
const (
	StageScan       = "scan_security"
	StageLoad       = "test_load"
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
	Evidence      string `json:"evidence,omitempty"` // measured/observed evidence supporting the finding
	Source        string `json:"source,omitempty"`   // security_scan|load_test|system|evidence_quality
}

// Canonical converts an audit360 finding into the shared model. ImpactSummary
// is the audit360 spelling of the canonical impact field.
func (f Finding) Canonical() finding.Finding {
	return finding.Finding{
		Title:       f.Title,
		Severity:    f.Severity,
		Impact:      f.ImpactSummary,
		Remediation: f.Remediation,
		Evidence:    f.Evidence,
		Source:      f.Source,
	}
}

// ToCanonical is the function form of Finding.Canonical.
func ToCanonical(f Finding) finding.Finding { return f.Canonical() }

// FromCanonical converts a shared finding back into the legacy audit360 shape.
// Canonical-only fields have no audit360 representation and are dropped.
func FromCanonical(f finding.Finding) Finding {
	return Finding{
		Title:         f.Title,
		Severity:      f.Severity,
		ImpactSummary: f.Impact,
		Remediation:   f.Remediation,
		Evidence:      f.Evidence,
		Source:        f.Source,
	}
}

// ScoreBreakdown provides separate assessments (0-100) by category.
// Overall is retained as the canonical aggregate for backward compatibility.
// Coverage reflects how much of the intended assessment scope produced
// measured/observed evidence (higher = stronger evidence basis).
type ScoreBreakdown struct {
	Overall         int `json:"overall"`
	Security        int `json:"security"`
	Resilience      int `json:"resilience"`
	Capacity        int `json:"capacity"`
	EvidenceQuality int `json:"evidence_quality"`
	Coverage        int `json:"coverage,omitempty"`
}

// TestConfiguration records the executed test configuration for integrity/audit.
type TestConfiguration struct {
	Mode                  string `json:"mode"`
	MaxDurationSec        int    `json:"max_duration_sec"`
	RequestedTarget       string `json:"requested_target"`
	LoadMaxUsers          int    `json:"load_max_users,omitempty"`
	LoadDurationSec       int    `json:"load_duration_sec,omitempty"`
	LoadProfile           string `json:"load_profile,omitempty"`
	SecurityScanEnabled   bool   `json:"security_scan_enabled"`
	ActiveLoadEnabled     bool   `json:"active_load_enabled"`
	AuthorizationProvided bool   `json:"authorization_provided,omitempty"`
}

// Audit360Report is the final signed report.
type Audit360Report struct {
	ResilienceScore    int       `json:"resilience_score"` // overall score (backward compatibility)
	RiskLevel          string    `json:"risk_level"`
	BreakingPointUsers int       `json:"breaking_point_users,omitempty"`
	MaxSafeRPS         float64   `json:"max_safe_rps,omitempty"` // sustainable/safe capacity estimate from measured samples (when available)
	Findings           []Finding `json:"findings"`
	VPMPSignature      string    `json:"vpmp_signature"`
	CertificateID      string    `json:"certificate_id"`
	Timestamp          string    `json:"timestamp"` // ISO8601
	TargetURL          string    `json:"target_url"`
	DurationMS         int64     `json:"duration_ms"`
	Notes              []string  `json:"notes,omitempty"`

	// Optional transparency fields (additive, not part of strict required schema).
	BreakingPointReached bool    `json:"breaking_point_reached"`
	MaxObservedRPS       float64 `json:"max_observed_rps,omitempty"` // observed peak throughput (measured), not sustained capacity
	LoadTestAvailable    bool    `json:"load_test_available"`
	SecurityScanPartial  bool    `json:"security_scan_partial,omitempty"`

	// CapacityBlocked is true when the target refused the audit traffic itself
	// (dominant 401/403/407/429), so no capacity number is claimed.
	CapacityBlocked  bool    `json:"capacity_blocked,omitempty"`
	BlockedStatus    int     `json:"blocked_status,omitempty"`
	BlockedSharePct  float64 `json:"blocked_share_pct,omitempty"`
	MaxObservedUsers int     `json:"max_observed_users,omitempty"` // observed concurrent users during test (measured)
	// LoadTestSkipped is true when active load/breaking-point testing was not run
	// intentionally (e.g. passive mode).
	LoadTestSkipped bool `json:"load_test_skipped,omitempty"`

	// Additive integrity/scoring/evidence fields (backward compatible).
	Scores            *ScoreBreakdown    `json:"scores,omitempty"`
	ScoringVersion    string             `json:"scoring_version,omitempty"`
	TestConfiguration *TestConfiguration `json:"test_configuration,omitempty"`
	RawEvidenceHash   string             `json:"raw_evidence_hash,omitempty"`
	RawEvidenceFormat string             `json:"raw_evidence_format,omitempty"`
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

// Audit mode controls safety/authorization behavior.
const (
	ModePassive  = "passive"
	ModeStandard = "standard"
	ModeAdmin    = "admin"
)

// StartRequest is POST /api/audit-360 body.
type StartRequest struct {
	TargetURL      string `json:"target_url"`
	Authorized     bool   `json:"authorized"`
	MaxDurationSec int    `json:"max_duration_sec,omitempty"`
	Mode           string `json:"mode,omitempty"`
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
