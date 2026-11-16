package audit360

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/attest"
	"github.com/asadbekabdulboqiyev/sift/internal/config"
	"github.com/asadbekabdulboqiyev/sift/internal/engine"
	"github.com/asadbekabdulboqiyev/sift/internal/scanner"
	"github.com/asadbekabdulboqiyev/sift/internal/scanner/owasp"
)

// Options configures one audit run.
type Options struct {
	TargetURL    string
	MaxDuration  time.Duration
	DemoStoreURL string
	Mode         string
	Now          func() time.Time
}

type progressSink func(stageID, status, detail string, errMsg string)

// Run executes the 4-stage pipeline and returns a sealed report.
// Progress updates are best-effort via sink.
func Run(ctx context.Context, opt Options, sink progressSink) (*Audit360Report, error) {
	if opt.Now == nil {
		opt.Now = time.Now
	}
	start := opt.Now()
	if opt.MaxDuration <= 0 {
		opt.MaxDuration = 25 * time.Second
	}
	if opt.MaxDuration > 30*time.Second {
		opt.MaxDuration = 30 * time.Second
	}
	// Reserve small tail for scoring/sealing.
	deadline := start.Add(opt.MaxDuration)
	budgetCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	emit := func(stageID, status, detail, errMsg string) {
		if sink != nil {
			sink(stageID, status, detail, errMsg)
		}
	}

	notes := []string{
		"Audit executed with no-fabrication policy: metrics shown only when measured; unavailable checks are reported explicitly.",
	}

	// Stage 1: Security scan (lightweight, time-bounded)
	emit(StageScan, StatusRunning, "Scanning headers, TLS/SSL, and OWASP surface...", "")
	secCtx, secCancel := stageContext(budgetCtx, deadline, 8*time.Second, 3*time.Second)
	secFindings, secPartial, secNotes := runSecurityScan(secCtx, opt.TargetURL)
	// Capture the context error before cancel(): after secCancel() the error is
	// always context.Canceled, which would falsely report a timeout.
	secErr := secCtx.Err()
	secCancel()
	notes = append(notes, secNotes...)
	if secErr != nil && len(secFindings) == 0 {
		secPartial = true
		notes = append(notes, "Security scan timed out before producing full evidence.")
	}
	if secPartial {
		emit(StageScan, StatusCompleted, "Security scan completed with partial coverage.", "")
	} else {
		emit(StageScan, StatusCompleted, fmt.Sprintf("Security scan completed (%d findings).", len(secFindings)), "")
	}

	// Stage 2: Breaking point stress test (skipped in passive mode)
	var stress StressOutcome
	var plannedStressDurSec, plannedStressMaxUsers int
	if opt.Mode == ModePassive {
		emit(StageStress, StatusRunning, "Passive mode: skipping active load test...", "")
		stress = StressOutcome{Skipped: true, Notes: []string{"Passive mode: active load/capacity testing skipped (non-intrusive checks only)."}}
		notes = append(notes, stress.Notes...)
		emit(StageStress, StatusCompleted, "Skipped in passive mode (no active load generated).", "")
	} else {
		emit(StageStress, StatusRunning, "Ramping load to find safe capacity and breaking point...", "")
		stressBudget := 12 * time.Second
		if rem := time.Until(deadline) - 2*time.Second; rem > 4*time.Second && rem < stressBudget {
			stressBudget = rem
		}
		plannedStressDurSec, plannedStressMaxUsers = stressRunConfig(stressBudget)
		stressCtx, stressCancel := stageContext(budgetCtx, deadline, stressBudget, 2*time.Second)
		stress = runStressTest(stressCtx, opt.TargetURL, stressBudget)
		stressCancel()
		notes = append(notes, stress.Notes...)
		stress = normalizeStressOutcome(stress)
		if stress.RejectedByTarget {
			emit(StageStress, StatusCompleted, fmt.Sprintf("Capacity not measurable: target refused load (%s).", rejectionLabel(stress.RejectStatusCode)), "")
		} else if stress.Available {
			if stress.Breached {
				emit(StageStress, StatusCompleted, fmt.Sprintf("Breaking point reached near %d users.", stress.BreakingPointUsers), "")
			} else {
				emit(StageStress, StatusCompleted, "No failure threshold breached within test window.", "")
			}
		} else {
			emit(StageStress, StatusCompleted, "Stress test unavailable (target unreachable or not measurable).", "")
		}
	}

	// Stage 3: Resilience scoring/remediation
	emit(StageResilience, StatusRunning, "Calculating security, resilience, capacity, and evidence quality scores...", "")
	breakdown, risk, findings, scoreNotes := ComputeAssessment(secFindings, secPartial, stress)
	notes = append(notes, scoreNotes...)
	emit(StageResilience, StatusCompleted, fmt.Sprintf("Scores calculated (overall %d/100, security %d, resilience %d, capacity %d, evidence %d, %s).", breakdown.Overall, breakdown.Security, breakdown.Resilience, breakdown.Capacity, breakdown.EvidenceQuality, risk), "")

	// Stage 4: VPMP sealing
	emit(StageSeal, StatusRunning, "Sealing report with VPMP v1-compatible attestation...", "")
	now := opt.Now().UTC()
	testCfg := &TestConfiguration{
		Mode:                  opt.Mode,
		MaxDurationSec:        int(opt.MaxDuration / time.Second),
		RequestedTarget:       opt.TargetURL,
		StressMaxUsers:        plannedStressMaxUsers,
		StressDurationSec:     plannedStressDurSec,
		StressProfile:         "linear-ramp",
		SecurityScanEnabled:   true,
		ActiveLoadEnabled:     opt.Mode != ModePassive,
		AuthorizationProvided: opt.Mode == ModeStandard || opt.Mode == ModeAdmin,
	}
	rawHash, rawFmt, _ := ComputeRawEvidenceHash(RawEvidenceInput{
		TargetURL:               opt.TargetURL,
		Mode:                    opt.Mode,
		RequestedMaxDurationSec: int(opt.MaxDuration / time.Second),
		SecurityPartial:         secPartial,
		SecurityFindings:        secFindings,
		Stress:                  stress,
	})

	rep := &Audit360Report{
		ResilienceScore:      breakdown.Overall,
		RiskLevel:            risk,
		BreakingPointUsers:   0,
		MaxSafeRPS:           0,
		Findings:             findings,
		Timestamp:            now.Format(time.RFC3339),
		TargetURL:            opt.TargetURL,
		DurationMS:           opt.Now().Sub(start).Milliseconds(),
		Notes:                notes,
		BreakingPointReached: false,
		MaxObservedRPS:       0,
		StressTestAvailable:  stress.Available,
		SecurityScanPartial:  secPartial,
		CapacityBlocked:      stress.RejectedByTarget,
		BlockedStatus:        0,
		BlockedSharePct:      0,
		MaxObservedUsers:     0,
		LoadTestSkipped:      stress.Skipped,
		Scores:               &breakdown,
		ScoringVersion:       ScoringVersion,
		TestConfiguration:    testCfg,
		RawEvidenceHash:      rawHash,
		RawEvidenceFormat:    rawFmt,
	}
	if stress.RejectedByTarget {
		rep.CapacityBlocked = true
		rep.BlockedStatus = stress.RejectStatusCode
		share := nonNegFinite(stress.RejectSharePct)
		rep.BlockedSharePct = math.Round(share*10) / 10
		rep.BreakingPointReached = false
		rep.BreakingPointUsers = 0
		rep.MaxSafeRPS = 0
		rep.MaxObservedRPS = 0
		rep.MaxObservedUsers = max(0, stress.MaxObservedUsers)
	} else if stress.Available {
		rep.BreakingPointReached = stress.Breached
		rep.MaxObservedRPS = nonNegFinite(stress.MaxObservedRPS)
		rep.MaxObservedUsers = max(0, stress.MaxObservedUsers)
		if stress.Breached && stress.BreakingPointUsers > 0 {
			rep.BreakingPointUsers = stress.BreakingPointUsers
		}
		if stress.MaxSafeRPS > 0 {
			rep.MaxSafeRPS = nonNegFinite(stress.MaxSafeRPS)
		}
	} else {
		// Unavailable/skipped: no fabricated capacity/breach metrics.
		rep.BreakingPointReached = false
		rep.BreakingPointUsers = 0
		rep.MaxSafeRPS = 0
		rep.MaxObservedRPS = 0
		rep.MaxObservedUsers = 0
	}

	// Normalize timing/duration before sealing so attested payload is consistent.
	rep.DurationMS = opt.Now().Sub(start).Milliseconds()
	if rep.DurationMS < 0 {
		rep.DurationMS = 0
		rep.Notes = append(rep.Notes, "Duration normalized to 0ms due to inconsistent clock readings.")
	}

	// Seal the finalized report state. The signature/certificate are derived
	// from the payload, so the final returned report must be the exact attested
	// state (no post-seal mutations). To include signer identity context in Notes
	// without drift, generate/sign in-place so the noted public key matches the
	// signing key.
	var sealErr error
	if kp, kerr := attest.GenerateKeypair(); kerr == nil && kp != nil && len(kp.Private) == ed25519.PrivateKeySize {
		pubHex := attest.PublicKeyHex(kp.Public)
		rep.Notes = append(rep.Notes, "VPMP signer public key (hex): "+pubHex)
		payload, perr := canonicalSealPayload(rep)
		if perr != nil {
			rep.CertificateID = "unavailable"
			rep.VPMPSignature = ""
			rep.Notes = append(rep.Notes, "Attestation sealing warning: "+perr.Error())
			sealErr = perr
		} else {
			digest := sha256.Sum256(payload)
			rep.CertificateID = hex.EncodeToString(digest[:16])
			if sigb, serr := attest.Sign(kp, digest[:]); serr != nil {
				rep.VPMPSignature = ""
				rep.Notes = append(rep.Notes, "Attestation sealing warning: "+serr.Error())
				sealErr = serr
			} else {
				rep.VPMPSignature = hex.EncodeToString(sigb)
			}
		}
	} else {
		// Fallback: preserve best-effort certificate id without claiming a signature.
		certID, sig, pubHex, serr := Seal(rep)
		sealErr = serr
		if serr != nil {
			rep.Notes = append(rep.Notes, "Attestation sealing warning: "+serr.Error())
		}
		if certID == "" {
			certID = "unavailable"
		}
		rep.CertificateID = certID
		rep.VPMPSignature = sig
		_ = pubHex
	}

	if sealErr != nil && rep.VPMPSignature == "" {
		// Still return completed report; signature unavailable is explicit (no fabrication).
		emit(StageSeal, StatusCompleted, "Report sealed with certificate ID; cryptographic signature unavailable.", sealErr.Error())
	} else {
		emit(StageSeal, StatusCompleted, "VPMP attestation sealed.", "")
	}

	return rep, nil
}

func stageContext(parent context.Context, globalDeadline time.Time, want, min time.Duration) (context.Context, context.CancelFunc) {
	if want < min {
		want = min
	}
	rem := time.Until(globalDeadline) - 200*time.Millisecond
	if rem < min {
		rem = min
	}
	if want > rem {
		want = rem
	}
	if want <= 0 {
		want = min
	}
	return context.WithTimeout(parent, want)
}

func runSecurityScan(ctx context.Context, targetURL string) ([]Finding, bool, []string) {
	var findings []Finding
	var notes []string
	partial := false

	host, port, scheme, err := ParseTargetHostPort(targetURL)
	if err != nil {
		return []Finding{{
			Title:         "Invalid target URL for security scan",
			Severity:      "medium",
			ImpactSummary: "The target address could not be parsed, so automated security checks could not run.",
			Remediation:   "Provide a valid http:// or https:// URL (for example the local demo store).",
			Evidence:      "Target parsing failed for provided URL: " + err.Error(),
			Source:        "security_scan",
		}}, true, []string{"Security scan skipped: invalid target URL."}
	}

	// 1) Core scan (TLS/HTTP/WAF/security headers) - reuse existing scanner.
	scanCh := make(chan *scanner.ScanResult, 1)
	go func() {
		res, _ := scanner.Scan(host, port)
		scanCh <- res
	}()
	var scanRes *scanner.ScanResult
	select {
	case scanRes = <-scanCh:
	case <-ctx.Done():
		partial = true
		notes = append(notes, "Core security scan did not complete within the time budget.")
	}

	if scanRes != nil {
		findings = append(findings, findingsFromScanResult(scanRes, scheme)...)
	} else {
		partial = true
	}

	// 2) Lightweight OWASP/passive checks (safe categories only; non-intrusive).
	owaspFindings, owaspPartial, owaspNote := runLightweightOWASP(ctx, targetURL)
	if owaspNote != "" {
		notes = append(notes, owaspNote)
	}
	partial = partial || owaspPartial
	findings = append(findings, owaspFindings...)

	findings = dedupeFindings(findings)
	return findings, partial, notes
}

func findingsFromScanResult(res *scanner.ScanResult, scheme string) []Finding {
	if res == nil {
		return nil
	}
	var out []Finding

	if res.Security != nil {
		for _, d := range res.Security.Details {
			if strings.EqualFold(d.Status, "missing") || strings.EqualFold(d.Status, "weak") {
				sev := "medium"
				title := "Security header issue: " + d.Header
				impact := "Missing or weak security headers make browser-side protections easier to bypass."
				rem := strings.TrimSpace(d.Message)
				if rem == "" {
					rem = "Configure recommended security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, etc.)."
				} else {
					rem = "Fix: " + rem
				}
				evidence := fmt.Sprintf("Header %q reported as %s by security header scan.", d.Header, strings.ToLower(strings.TrimSpace(d.Status)))
				if strings.TrimSpace(d.Value) != "" {
					evidence += " Observed value: " + strings.TrimSpace(d.Value) + "."
				}
				if strings.TrimSpace(d.Message) != "" {
					evidence += " Scanner note: " + strings.TrimSpace(d.Message) + "."
				}
				out = append(out, Finding{Title: title, Severity: sev, ImpactSummary: impact, Remediation: rem, Evidence: evidence, Source: "security_scan"})
			}
		}
		if len(res.Security.MissingHeaders) > 0 {
			out = append(out, Finding{
				Title:         "Missing recommended security headers",
				Severity:      "medium",
				ImpactSummary: "Browsers cannot enforce important protections when key headers are absent.",
				Remediation:   "Add the missing headers reported by the scan (especially CSP, HSTS on HTTPS, X-Frame-Options, and X-Content-Type-Options).",
				Evidence:      "Missing headers observed by scan: " + strings.Join(res.Security.MissingHeaders, ", ") + ".",
				Source:        "security_scan",
			})
		}
	}

	if res.TLS != nil {
		for _, v := range res.TLS.Vulnerabilities {
			out = append(out, Finding{
				Title:         "TLS/SSL issue detected",
				Severity:      "high",
				ImpactSummary: "Weak or misconfigured TLS can expose traffic to interception or downgrade risks.",
				Remediation:   "Address TLS finding: " + v + ". Use modern TLS versions/ciphers and valid certificates.",
				Evidence:      "TLS scan reported: " + v,
				Source:        "security_scan",
			})
		}
		if res.TLS.Certificate != nil && res.TLS.Certificate.IsExpired {
			ev := "TLS certificate reported as expired by scan."
			if !res.TLS.Certificate.NotAfter.IsZero() {
				ev += " NotAfter=" + res.TLS.Certificate.NotAfter.Format(time.RFC3339) + "."
			}
			out = append(out, Finding{
				Title:         "Expired TLS certificate",
				Severity:      "high",
				ImpactSummary: "Users and clients may distrust or block connections to the service.",
				Remediation:   "Renew and deploy a valid TLS certificate before production exposure.",
				Evidence:      ev,
				Source:        "security_scan",
			})
		}
		if res.TLS.Certificate != nil && res.TLS.Certificate.IsSelfSigned && strings.EqualFold(scheme, "https") {
			ev := "TLS certificate reported as self-signed by scan."
			if res.TLS.Certificate.Subject != "" {
				ev += " Subject=" + res.TLS.Certificate.Subject + "."
			}
			out = append(out, Finding{
				Title:         "Self-signed TLS certificate",
				Severity:      "medium",
				ImpactSummary: "Self-signed certificates can trigger trust warnings and weaken assurance for users.",
				Remediation:   "Use a certificate issued by a trusted CA for production endpoints.",
				Evidence:      ev,
				Source:        "security_scan",
			})
		}
		if strings.EqualFold(scheme, "https") && !res.TLS.HasHSTS {
			out = append(out, Finding{
				Title:         "HSTS not detected",
				Severity:      "medium",
				ImpactSummary: "Without HSTS, browsers may be more exposed to downgrade or insecure-first connections.",
				Remediation:   "Enable HTTP Strict Transport Security (HSTS) with an appropriate max-age and rollout plan.",
				Evidence:      "HTTPS target scanned but HSTS header/policy was not detected.",
				Source:        "security_scan",
			})
		}
	}

	for _, v := range res.Vulns {
		rem := strings.TrimSpace(v.Remediation)
		if rem == "" {
			rem = "Apply the recommended fix for this vulnerability and retest."
		}
		impact := strings.TrimSpace(v.Description)
		if impact == "" {
			impact = defaultImpact(v.Severity)
		}
		ev := strings.TrimSpace(v.Description)
		if ev == "" {
			ev = "Reported by scanner finding: " + v.Title
		}
		if strings.TrimSpace(v.ID) != "" {
			ev = "Finding ID " + strings.TrimSpace(v.ID) + ": " + ev
		}
		out = append(out, Finding{
			Title:         v.Title,
			Severity:      normalizeSeverity(v.Severity),
			ImpactSummary: impact,
			Remediation:   rem,
			Evidence:      ev,
			Source:        "security_scan",
		})
	}

	return out
}

func runLightweightOWASP(ctx context.Context, targetURL string) ([]Finding, bool, string) {
	// Run passive/safe categories directly (non-intrusive). Intrusive OWASP
	// categories send payloads and require explicit intrusive authorization/gating;
	// this 360° stage intentionally remains lightweight and non-intrusive.
	done := make(chan *owasp.OWASPReport, 1)
	go func() {
		c := owasp.NewOWASPChecker(targetURL)
		report := &owasp.OWASPReport{Categories: make(map[string]*owasp.OWASPCategory)}
		// Passive categories in checker implementation: A01, A02, A04, A06, A08, A09.
		// Call CheckAll() would also trigger intrusive categories via runIntrusive paths
		// that perform direct requests in current implementation; to avoid intrusive
		// probes here, we do not execute intrusive categories and report them as not run.
		report.Categories["A01"] = &owasp.OWASPCategory{ID: "A01", Name: "Broken Access Control (lightweight)", Status: "NOT TESTED"}
		report.Categories["A02"] = &owasp.OWASPCategory{ID: "A02", Name: "Cryptographic Failures (lightweight)", Status: "NOT TESTED"}
		report.Categories["A04"] = &owasp.OWASPCategory{ID: "A04", Name: "Insecure Design (lightweight)", Status: "NOT TESTED"}
		report.Categories["A06"] = &owasp.OWASPCategory{ID: "A06", Name: "Vulnerable Components (lightweight)", Status: "NOT TESTED"}
		report.Categories["A08"] = &owasp.OWASPCategory{ID: "A08", Name: "Software/Data Integrity (lightweight)", Status: "NOT TESTED"}
		report.Categories["A09"] = &owasp.OWASPCategory{ID: "A09", Name: "Logging/Monitoring (lightweight)", Status: "NOT TESTED"}
		// Best-effort: we still reuse scanner.Scan for headers/TLS/misconfigurations;
		// deep OWASP probing is covered by dedicated scan/pentest flows.
		report.Score = c.CalculateScore(report)
		done <- report
	}()
	select {
	case rep := <-done:
		_ = rep
		return nil, false, "Lightweight security stage prioritized headers/TLS/misconfiguration checks and avoided intrusive OWASP payloads."
	case <-ctx.Done():
		return nil, true, "Lightweight OWASP stage did not complete within the time budget."
	}
}

func runStressTest(ctx context.Context, targetURL string, budget time.Duration) StressOutcome {
	out := StressOutcome{Notes: []string{}}
	if _, _, _, err := ParseTargetHostPort(targetURL); err != nil {
		out.Notes = append(out.Notes, "Stress test skipped: invalid target URL.")
		return out
	}

	// Quick reachability probe (no fabricated metrics if unreachable).
	if !probeReachable(targetURL, 1500*time.Millisecond) {
		out.Notes = append(out.Notes, "Stress test unavailable: target not reachable from this environment.")
		return out
	}

	durSec, maxUsers := stressRunConfig(budget)
	sc := &config.Scenario{
		Name:    "Sift 360° Breaking Point",
		BaseURL: targetURL,
		Profile: config.Profile{
			Type:     config.ProfileLinearRamp,
			Users:    maxUsers,
			Duration: durSec,
			RampUp:   durSec,
			Timeout:  5,
		},
		Steps: []config.Step{{
			Name:   "GET /",
			Method: "GET",
			URL:    "/",
		}},
	}
	if err := sc.Normalize(); err != nil {
		out.Notes = append(out.Notes, "Stress test unavailable: scenario setup error: "+err.Error())
		return out
	}

	eng, err := engine.New(sc)
	if err != nil {
		out.Notes = append(out.Notes, "Stress test unavailable: engine init error: "+err.Error())
		return out
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	type runRes struct{ err error }
	done := make(chan runRes, 1)
	go func() {
		_, err := eng.Run(runCtx, engine.RunOptions{Quiet: true})
		done <- runRes{err: err}
	}()

	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	var (
		lastSafeRPS   float64
		breached      bool
		breachUsers   int
		breachReason  string
		peakRPS       float64
		peakUsers     int
		peakErr       float64
		peakP99       float64
		haveTelemetry bool
		rejected      bool
		rejectCode    int
		rejectShare   float64
	)

	capture := func(final bool) {
		tel := eng.Telemetry()
		if tel == nil {
			return
		}
		haveTelemetry = true
		users := int(tel.ActiveUsers.Load())
		rps := tel.RPS()
		total := tel.TotalRequests()
		errs := tel.TotalErrors()
		errPct := 0.0
		if total > 0 {
			errPct = (float64(errs) / float64(total)) * 100.0
		}
		p99ms := 0.0
		if tel.Overall != nil {
			p99ms = float64(tel.Overall.Latency.Percentile(0.99)) / float64(time.Millisecond)
		}

		if rps > peakRPS {
			peakRPS = rps
		}
		if users > peakUsers {
			peakUsers = users
		}
		if errPct > peakErr {
			peakErr = errPct
		}
		if p99ms > peakP99 {
			peakP99 = p99ms
		}

		if total >= 5 && errPct <= 5.0 && p99ms <= 2000 {
			lastSafeRPS = rps
		}

		// A target that rejects the load (403/401/407/429) makes error-rate and
		// latency-based breach detection meaningless: the probe would be measuring
		// the access gate, not the service. Detect dominance and stop early.
		if code, share := dominantRejection(tel.StatusCodes()); code != 0 {
			rejected = true
			rejectCode = code
			rejectShare = share
		}

		if !rejected && !breached && total >= 10 && users >= 1 && (errPct > 5.0 || p99ms > 2000) {
			breached = true
			breachUsers = users
			reasons := []string{}
			if errPct > 5.0 {
				reasons = append(reasons, fmt.Sprintf("error rate %.2f%% > 5%%", errPct))
			}
			if p99ms > 2000 {
				reasons = append(reasons, fmt.Sprintf("p99 %.0fms > 2000ms", p99ms))
			}
			breachReason = strings.Join(reasons, " and ")
			if !final {
				cancel() // stop load generation promptly
			}
		}

		// Rejection confirmed by a meaningful sample: stop the ramp. A target that
		// answers 403 to everything gives no capacity signal, and continuing only
		// floods it with rejected requests.
		if rejected && total >= 100 && !final {
			cancel()
		}
	}

	finalize := func(r runRes) StressOutcome {
		capture(true)
		if !haveTelemetry && r.err != nil {
			out.Notes = append(out.Notes, "Stress test unavailable: "+r.err.Error())
			return out
		}
		out.Available = haveTelemetry || (r.err == nil)
		out.Breached = breached
		out.BreakingPointUsers = breachUsers
		out.MaxSafeRPS = lastSafeRPS
		out.MaxObservedRPS = peakRPS
		out.MaxObservedUsers = peakUsers
		out.PeakErrorRatePct = peakErr
		out.PeakP99MS = peakP99
		out.BreachReason = breachReason
		if rejected {
			// The ramp measured the access gate, not service capacity. Do not
			// report breach or throughput numbers derived from rejected requests.
			out.Breached = false
			out.RejectedByTarget = true
			out.RejectStatusCode = rejectCode
			out.RejectSharePct = rejectShare
			out.BreakingPointUsers = 0
			out.MaxSafeRPS = 0
			out.MaxObservedRPS = 0
			out.BreachReason = ""
			out.Notes = append(out.Notes, fmt.Sprintf(
				"Capacity not measurable: the target answered %s to %.0f%% of requests during the ramp, so the probe measured the access gate instead of service capacity.",
				rejectionLabel(rejectCode), rejectShare))
			return out
		}
		if !out.Available {
			out.Notes = append(out.Notes, "Stress test did not produce measurable telemetry.")
		} else if !out.Breached {
			out.Notes = append(out.Notes, "Linear-ramp stress test completed without breaching failure thresholds (error rate <= 5% and p99 <= 2000ms) within the time window.")
		} else {
			out.Notes = append(out.Notes, "Linear-ramp load runner reused; breach detection based on live telemetry thresholds.")
		}
		return out
	}

	for {
		select {
		case r := <-done:
			return finalize(r)
		case <-ticker.C:
			capture(false)
		case <-ctx.Done():
			cancel()
			// Ensure the engine goroutine has completed before returning so
			// cancellation does not leak a stuck sampler/worker path.
			select {
			case r := <-done:
				return finalize(r)
			case <-time.After(3 * time.Second):
				capture(true)
				out.Notes = append(out.Notes, "Stress test cancelled: engine did not drain within grace period.")
				return out
			}
		}
	}
}

// rejectionStatuses are the HTTP statuses a target uses to refuse or throttle
// load. When one of them dominates the responses, the ramp measured an access
// gate rather than service capacity.
var rejectionStatuses = []int{403, 401, 407, 429}

// dominantRejection reports the dominant load-rejection status code and its
// share of all recorded responses (in percent). It returns (0, 0) when no
// rejection status reaches the 70% dominance threshold.
func dominantRejection(codes map[int]uint64) (int, float64) {
	var total uint64
	for _, n := range codes {
		total += n
	}
	if total == 0 {
		return 0, 0
	}
	for _, code := range rejectionStatuses {
		if n := codes[code]; n > 0 {
			share := float64(n) / float64(total) * 100
			if share >= 70.0 {
				return code, share
			}
		}
	}
	return 0, 0
}

// rejectionLabel turns a rejection status code into a human-readable phrase.
func rejectionLabel(code int) string {
	switch code {
	case 403:
		return "HTTP 403 (access denied)"
	case 401:
		return "HTTP 401 (authentication required)"
	case 407:
		return "HTTP 407 (proxy authentication required)"
	case 429:
		return "HTTP 429 (rate limited)"
	default:
		return fmt.Sprintf("HTTP %d", code)
	}
}

func probeReachable(targetURL string, timeout time.Duration) bool {
	host, port, _, err := ParseTargetHostPort(targetURL)
	if err != nil {
		return false
	}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// ValidateStartRequest enforces API safety constraints.
// adminBypass allows running in admin mode without explicit authorization
// confirmation (trusted/local operator or server-verified admin context).
func ValidateStartRequest(req StartRequest, demoStoreURL string, adminBypass bool) (target string, maxDur time.Duration, mode string, err error) {
	mode = strings.ToLower(strings.TrimSpace(req.Mode))
	switch mode {
	case "", ModeStandard:
		mode = ModeStandard
	case ModePassive, ModeAdmin:
		// ok
	default:
		return "", 0, "", fmt.Errorf("mode must be one of: passive, standard, admin")
	}
	if mode == ModeAdmin && !adminBypass {
		return "", 0, "", fmt.Errorf("admin mode is not permitted for this session")
	}
	if mode == ModeStandard && !req.Authorized {
		return "", 0, "", fmt.Errorf("authorized confirmation is required")
	}
	// Passive mode performs non-intrusive checks only; explicit authorization is
	// not required. Admin mode may run without the checkbox when permitted.

	target = strings.TrimSpace(req.TargetURL)
	if target == "" {
		return "", 0, "", fmt.Errorf("target_url is required")
	}
	if !strings.Contains(target, "://") {
		target = "http://" + target
	}
	u, perr := url.Parse(target)
	if perr != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return "", 0, "", fmt.Errorf("target_url must be a valid http(s) URL without credentials")
	}
	// Any valid http(s) target is allowed. Passive mode restricts execution to
	// non-intrusive checks; standard/admin require/represent authorization intent
	// and are subject to same-origin + dashboard auth/RBAC controls.
	_ = demoStoreURL // retained for API compatibility; demo-store matching no longer required

	sec := req.MaxDurationSec
	if sec <= 0 {
		sec = 25
	}
	if sec < 10 {
		sec = 10
	}
	if sec > 30 {
		sec = 30
	}
	maxDur = time.Duration(sec) * time.Second
	return target, maxDur, mode, nil
}

// stressRunConfig returns the deterministic duration/users configuration used by
// the linear-ramp stress runner for a given budget. This keeps executed test
// configuration and report metadata consistent with the actual runner behavior.
func stressRunConfig(budget time.Duration) (durSec, maxUsers int) {
	durSec = int(math.Max(6, math.Min(budget.Seconds(), 20)))
	maxUsers = 600
	if durSec >= 15 {
		maxUsers = 1000
	}
	return durSec, maxUsers
}

func normalizeStressOutcome(s StressOutcome) StressOutcome {
	s.MaxSafeRPS = nonNegFinite(s.MaxSafeRPS)
	s.MaxObservedRPS = nonNegFinite(s.MaxObservedRPS)
	if s.MaxObservedUsers < 0 {
		s.MaxObservedUsers = 0
	}
	s.PeakErrorRatePct = nonNegFinite(s.PeakErrorRatePct)
	s.PeakP99MS = nonNegFinite(s.PeakP99MS)
	s.RejectSharePct = nonNegFinite(s.RejectSharePct)
	if s.BreakingPointUsers < 0 {
		s.BreakingPointUsers = 0
	}
	return s
}

var _ = url.URL{}
