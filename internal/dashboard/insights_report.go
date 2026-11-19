package dashboard

import (
	"github.com/asadbekabdulboqiyev/sift/internal/report"
)

// twinFitRequest carries the report evidence used to fit a capacity model.
// Keeping it with the report-evidence validator separates report validation
// from twin endpoint orchestration.
type twinFitRequest struct {
	Report      report.Report `json:"report"`
	TargetP99MS float64       `json:"target_p99_ms,omitempty"`
}

// validateFitReport validates the report-evidence portion of a fit request.
// It returns the exact error text to send to the caller, or "" when valid.
// The checks and their order are unchanged from the original inline block.
func validateFitReport(rep report.Report) string {
	if rep.TotalRequests == 0 {
		return "report has no completed requests; cannot fit a model from zero samples"
	}
	if rep.Duration <= 0 {
		return "report duration must be positive"
	}
	if err := rep.ValidateTimestamps(); err != nil {
		return "report timing is inconsistent: " + err.Error()
	}
	return ""
}
