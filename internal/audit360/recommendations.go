package audit360

import (
	"fmt"
	"strings"

	"github.com/asadbekabdulboqiyev/sift/internal/shared"
)

func severityRank(sev string) int {
	return shared.SeverityRank(sev)
}

// RecommendedActionNotes returns concise, evidence-based action notes derived
// from the finalized report. It does not fabricate measurements or claims.
func RecommendedActionNotes(r *Audit360Report) []string {
	if r == nil {
		return nil
	}
	notes := make([]string, 0, 4)

	crit, high, med := 0, 0, 0
	for _, f := range r.Findings {
		switch normalizeSeverity(f.Severity) {
		case "critical":
			crit++
		case "high":
			high++
		case "medium":
			med++
		}
	}

	if crit > 0 || high > 0 || med > 0 {
		notes = append(notes, fmt.Sprintf(
			"Recommended action plan (prioritized): address critical/high findings first (%d critical, %d high, %d medium), then retest to confirm risk reduction.",
			crit, high, med,
		))
	} else if len(r.Findings) > 0 {
		notes = append(notes, "Recommended action plan: review reported low/info findings for hardening opportunities and retest if changes are made.")
	} else {
		notes = append(notes, "Recommended action plan: no issues were reported by the executed checks; continue periodic authorized testing and monitoring.")
	}

	// Pick up to two highest-severity concrete findings as immediate actions.
	type pick struct {
		rank  int
		title string
		sev   string
		rem   string
	}
	picks := make([]pick, 0, len(r.Findings))
	for _, f := range r.Findings {
		rk := severityRank(f.Severity)
		if rk <= 0 {
			continue
		}
		picks = append(picks, pick{rank: rk, title: strings.TrimSpace(f.Title), sev: normalizeSeverity(f.Severity), rem: strings.TrimSpace(f.Remediation)})
	}
	// stable sort by rank desc then title
	for i := 0; i < len(picks); i++ {
		for j := i + 1; j < len(picks); j++ {
			if picks[j].rank > picks[i].rank || (picks[j].rank == picks[i].rank && strings.ToLower(picks[j].title) < strings.ToLower(picks[i].title)) {
				picks[i], picks[j] = picks[j], picks[i]
			}
		}
	}
	limit := 2
	if len(picks) < limit {
		limit = len(picks)
	}
	for i := 0; i < limit; i++ {
		p := picks[i]
		action := p.rem
		if action == "" {
			action = "Review and remediate this finding."
		}
		notes = append(notes, fmt.Sprintf("Immediate action %d [%s]: %s — %s", i+1, p.sev, p.title, action))
	}

	switch {
	case r.CapacityBlocked:
		notes = append(notes, "Capacity evidence: target refused load during the test; rerun from an allowed/authorized environment to measure sustainable capacity and breaking point.")
	case r.LoadTestSkipped || !r.StressTestAvailable:
		notes = append(notes, "Capacity evidence: active load/breaking-point metrics were not measured in this run; run an authorized active test when needed to establish safe capacity.")
	}
	if r.SecurityScanPartial {
		notes = append(notes, "Coverage note: security scan coverage was partial; rerun with adequate reachability/time to improve evidence completeness.")
	}

	return notes
}
