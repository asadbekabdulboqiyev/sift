package shared

import "strings"

// NormalizeSeverity folds severity spellings onto the canonical five levels:
// critical, high, medium, low, info. "warning" is treated as medium and "fail"
// as high, matching the audit scorer's existing mapping; anything unrecognised
// is info, so an unknown label can never outrank a known finding.
func NormalizeSeverity(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "critical", "high", "medium", "low", "info":
		return s
	case "warning":
		return "medium"
	case "fail":
		return "high"
	default:
		return "info"
	}
}

// SeverityRank orders severities from least (0, info) to most (4, critical)
// severe. It is the shared form of the audit scorer's old local severityRank.
func SeverityRank(s string) int {
	switch NormalizeSeverity(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// FindingSortKey orders findings most-severe-first for a stable ascending sort
// (critical=0, high=1, medium=2, low=3, everything else last). It is the shared
// form of the certificate canonicaliser's severityRank: it deliberately uses
// strings.ToLower without trimming, because that function feeds a signed JSON
// document and its exact ordering is part of the certificate's identity.
func FindingSortKey(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

// AlertSortKey orders host-xray indicators most-severe-first. Host x-ray uses a
// narrower vocabulary than the finding model (critical / warning / everything
// else), so it needs its own key rather than FindingSortKey: mapping "warning"
// to the generic "unknown" bucket would reorder warnings and info indicators.
func AlertSortKey(s string) int {
	switch s {
	case "critical":
		return 0
	case "warning":
		return 1
	default:
		return 2
	}
}
