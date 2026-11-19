package shared

// OWASPStatus applies the coverage-honesty rule to one category verdict.
//
// A category whose probes never reached the server produced no evidence, so it
// is NOT TESTED rather than PASS. Only the checker's own PASS counts as PASS:
// an unrecognised verdict is not evidence of anything and is never upgraded to
// a clean result.
func OWASPStatus(checkerStatus string, coverage int) string {
	if coverage == 0 || checkerStatus == "" || checkerStatus == "NOT TESTED" {
		return "NOT TESTED"
	}
	if checkerStatus == "FAIL" || checkerStatus == "WARNING" {
		return checkerStatus
	}
	if checkerStatus == "PASS" {
		return "PASS"
	}
	return "NOT TESTED"
}

// OWASPStatusRank orders the statuses by severity for worst-wins merges.
// FAIL beats WARNING beats PASS; "" and NOT TESTED carry no severity.
func OWASPStatusRank(s string) int {
	switch s {
	case "FAIL":
		return 3
	case "WARNING":
		return 2
	case "PASS":
		return 1
	default:
		return 0
	}
}

// OWASPWorstStatus merges two verdicts for the same category. A second scanned
// path may only make the picture worse, never better.
func OWASPWorstStatus(a, b string) string {
	if OWASPStatusRank(b) > OWASPStatusRank(a) {
		return b
	}
	return a
}
