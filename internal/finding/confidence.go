package finding

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Confidence states how strongly a finding is backed by observed evidence.
type Confidence string

// Confidence values. Unchecked is the conservative default for a finding
// whose evidence basis has not been established.
const (
	ConfidenceVerified  Confidence = "verified"
	ConfidenceHeuristic Confidence = "heuristic"
	ConfidenceUnchecked Confidence = "unchecked"
)

// ParseConfidence normalizes both canonical values and the legacy text values
// already emitted by scanners and dashboards. Unknown and empty inputs land in
// Unchecked rather than being promoted to a stronger claim.
//
// Legacy mapping: confirmed and high -> Verified, heuristic -> Heuristic,
// informational, unknown and everything else -> Unchecked.
func ParseConfidence(raw string) Confidence {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "verified", "confirmed", "high":
		return ConfidenceVerified
	case "heuristic":
		return ConfidenceHeuristic
	default:
		return ConfidenceUnchecked
	}
}

// String returns the canonical spelling of c.
func (c Confidence) String() string {
	return string(ParseConfidence(string(c)))
}

// MarshalJSON always emits the canonical spelling, so a legacy value written
// directly into the enum cannot leak into a signed or published document.
func (c Confidence) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.String())
}

// UnmarshalJSON accepts both canonical and legacy confidence text.
func (c *Confidence) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("finding: confidence must be a string: %w", err)
	}
	*c = ParseConfidence(raw)
	return nil
}
