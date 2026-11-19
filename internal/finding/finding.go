// Package finding defines the canonical finding model shared by Sift reports,
// certificates and dashboards. Legacy package-specific Finding types stay in
// place; each package converts to and from this model at its own boundary.
package finding

// Finding is the single canonical representation of one assessed defect.
//
// It is a superset of the legacy certificate and audit360 finding shapes, so
// converting either way is explicit and lossless for the fields that legacy
// type actually carries. Every field is optional: a legacy document converted
// into this model leaves the fields it never had at their zero values.
type Finding struct {
	ID          string     `json:"id,omitempty"`
	Severity    string     `json:"severity,omitempty"` // critical, high, medium, low, info
	Title       string     `json:"title,omitempty"`
	Description string     `json:"description,omitempty"`
	Impact      string     `json:"impact,omitempty"`
	Source      string     `json:"source,omitempty"`
	Location    string     `json:"location,omitempty"`
	Remediation string     `json:"remediation,omitempty"`
	Evidence    string     `json:"evidence,omitempty"`
	Confidence  Confidence `json:"confidence,omitempty"`
	CWE         string     `json:"cwe,omitempty"`
	Digests     []string   `json:"digests,omitempty"` // SHA-256 hex digests of supporting artifacts
}
