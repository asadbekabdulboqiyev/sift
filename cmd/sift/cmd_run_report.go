package main

import (
	"fmt"
	"os"

	"github.com/asadbekabdulboqiyev/sift/internal/evidence"
	"github.com/asadbekabdulboqiyev/sift/internal/report"
)

// loadRunBaseline loads the comparison report before any traffic is generated.
// A mistyped --compare path used to surface only after the run, so a typo cost
// a full run and the verdict was announced before the error appeared.
func loadRunBaseline(o *runOptions) *report.Report {
	if o.comparePath == "" {
		return nil
	}
	baseline, err := report.LoadReport(o.comparePath)
	if err != nil {
		fatal(err)
	}
	return baseline
}

// renderRunReport prints and persists a completed run, then applies the gates.
// Reports are written before any gate can exit: a CI job that fails without the
// report that explains the failure is a debugging dead end.
func renderRunReport(o *runOptions, r *report.Report, collector *evidence.Collector, baseline *report.Report) {
	fmt.Fprintln(os.Stderr)
	r.Render(os.Stdout)

	jsonPath, err := r.SaveJSON(o.reportDir)
	if err != nil {
		fatal(err)
	}
	txtPath, err := r.SaveTXT(o.reportDir)
	if err != nil {
		fatal(err)
	}
	fmt.Fprintf(os.Stderr, "\nReports written:\n  %s\n  %s\n", jsonPath, txtPath)

	if o.timelineCSV {
		csvPath, err := r.SaveCSV(o.reportDir)
		if err != nil {
			fatal(err)
		}
		if csvPath != "" {
			fmt.Fprintf(os.Stderr, "  %s\n", csvPath)
		}
	}

	// The evidence is written even when the SLA gate fails: a bundle that
	// proves the target missed its budget is exactly the bundle you want.
	if collector != nil {
		if err := emitEvidenceBundle(o.emitBundle, o.bundleKey, collector, o.scenario, r); err != nil {
			fatal(err)
		}
	}

	if baseline != nil {
		result := report.Compare(r, baseline)
		fmt.Print(result.Render())
		if result.Regression && result.RegressionPct > o.regressPct {
			fmt.Fprintf(os.Stderr, "REGRESSION DETECTED vs %s (threshold %.0f%%, actual %.1f%%)\n",
				o.comparePath, o.regressPct, result.RegressionPct)
			exitProcess(2)
		}
	}

	if len(r.SLA) > 0 && !report.SLAPassed(r.SLA) {
		fmt.Fprintln(os.Stderr, "SLA gate FAILED — exiting with code 2")
		exitProcess(2)
	}

	// Safety net: a run that failed on 100% of requests (e.g. dead port,
	// DNS failure, unreachable host) should not look like a success.
	if r.TotalRequests > 0 && r.TotalErrors == r.TotalRequests {
		fmt.Fprintln(os.Stderr, "FATAL: 100% of requests failed — target unreachable or refusing connections")
		fmt.Fprintln(os.Stderr, "  Check the target URL, network, and that the server is up.")
		exitProcess(1)
	}
}
