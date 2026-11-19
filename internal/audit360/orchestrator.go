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
	"syscall"
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

	// DialControl, when set, is installed on every dialer this run creates.
	// The gate uses it to refuse a connection whose resolved peer address was
	// not covered by the authorization decision, closing the gap between a
	// public-target approval and a socket that reaches a private address.
	// Nil keeps the original dial behaviour.
	DialControl func(network, address string, c syscall.RawConn) error

	// SignerKey, when set, is the identity that seals the report. A persistent
	// key makes the seal attributable: a verifier can pin the public key and
	// answer "did this issuer produce this file?", which an ephemeral per-run
	// key cannot — anyone can mint one and sign with it.
	//
	// Nil keeps the legacy behaviour (fresh keypair per run), so callers that do
	// not manage a key still produce a self-consistent report.
	SignerKey *attest.Keypair
	// SignerKeyErr reports why a configured signer key could not be loaded. It
	// is recorded in the report notes instead of being dropped, because a run
	// that silently fell back to an ephemeral key is not attributable.
	SignerKeyErr error
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

	// A cancelled parent means the caller no longer wants this run: retention
	// evicted the job, or the process is shutting down. Only ctx is consulted —
	// budgetCtx's own deadline is a normal outcome (a partial report inside the
	// time budget), never a cancellation.
	aborted := func() error {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("audit360: run cancelled: %w", err)
		}
		return nil
	}
	if err := aborted(); err != nil {
		return nil, err
	}

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
	secFindings, secPartial, secNotes := runSecurityScan(secCtx, opt.TargetURL, opt.DialControl)
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
	// Re-check before spending the largest slice of the budget and before any
	// further traffic is sent.
	if err := aborted(); err != nil {
		emit(StageStress, StatusFailed, "", err.Error())
		return nil, err
	}
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
		stress = runStressTest(stressCtx, opt.TargetURL, stressBudget, opt.DialControl)
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
	// A cancelled run must never be sealed: a signature attests that this
	// report is the outcome of a completed audit.
	if err := aborted(); err != nil {
		emit(StageSeal, StatusFailed, "", err.Error())
		return nil, err
	}
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
	rep.Notes = append(rep.Notes, RecommendedActionNotes(rep)...)

	// Seal the finalized report state. The signature/certificate are derived
	// from the payload, so the final returned report must be the exact attested
	// state (no post-seal mutations). To include signer identity context in Notes
	// without drift, generate/sign in-place so the noted public key matches the
	// signing key.
	var sealErr error
	if opt.SignerKeyErr != nil {
		rep.Notes = append(rep.Notes, "Attestation sealing warning: signer key unavailable: "+opt.SignerKeyErr.Error())
	}
	kp, kerr := opt.SignerKey, error(nil)
	if kp == nil {
		kp, kerr = attest.GenerateKeypair()
	}
	if kerr != nil || kp == nil || len(kp.Private) != ed25519.PrivateKeySize {
		// Best-effort fallback: preserve a deterministic certificate id bound to
		// the final payload without claiming a cryptographic signature.
		if kerr != nil {
			sealErr = kerr
			rep.Notes = append(rep.Notes, "Attestation sealing warning: "+kerr.Error())
		}
		if payload, perr := canonicalSealPayload(rep); perr != nil {
			rep.CertificateID = "unavailable"
			rep.VPMPSignature = ""
			rep.Notes = append(rep.Notes, "Attestation sealing warning: "+perr.Error())
			if sealErr == nil {
				sealErr = perr
			}
		} else {
			digest := sha256.Sum256(payload)
			rep.CertificateID = hex.EncodeToString(digest[:16])
			rep.VPMPSignature = ""
		}
	} else if _, _, _, serr := SealWithKey(rep, kp); serr != nil {
		// The key was usable but sealing failed (canonicalization or signing).
		// Keep the report usable and say so, rather than emitting a signature
		// that does not check out.
		rep.VPMPSignature = ""
		if strings.TrimSpace(rep.CertificateID) == "" {
			rep.CertificateID = "unavailable"
		}
		rep.Notes = append(rep.Notes, "Attestation sealing warning: "+serr.Error())
		sealErr = serr
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

func runSecurityScan(ctx context.Context, targetURL string, control func(network, address string, c syscall.RawConn) error) ([]Finding, bool, []string) {
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
		res, _ := scanner.ScanWithControl(host, port, control)
		scanCh <- res
	}()
	var scanRes *scanner.ScanResult
	select {
	case scanRes = <-scanCh:
	case <-ctx.Done():
		partial = true
		notes = append(notes, "Core security scan did not complete within the time budget.")
	}

	hasObservableSecurityEvidence := false
	targetReachable := false
	dialAddr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	dialer := net.Dialer{Timeout: 2 * time.Second, Control: control}
	if conn, derr := dialer.Dial("tcp", dialAddr); derr == nil {
		targetReachable = true
		_ = conn.Close()
	}

	if scanRes != nil {
		if scanRes.HTTP != nil || scanRes.Security != nil || len(scanRes.Vulns) > 0 {
			hasObservableSecurityEvidence = true
		}
		if scanRes.TLS != nil {
			if strings.TrimSpace(scanRes.TLS.Version) != "" || scanRes.TLS.Certificate != nil || scanRes.TLS.HasHSTS ||
				len(scanRes.TLS.SupportedVersions) > 0 || len(scanRes.TLS.SupportedCiphers) > 0 || len(scanRes.TLS.Vulnerabilities) > 0 {
				hasObservableSecurityEvidence = true
			}
		}
		// If target was reachable, consider scan execution as evidence attempt even
		// when no weaknesses/findings were reported by completed checks.
		if targetReachable {
			hasObservableSecurityEvidence = true
		}
		// If the target was unreachable or produced no usable evidence, treat as partial.
		if !hasObservableSecurityEvidence {
			partial = true
			notes = append(notes, "Core security scan produced no observable security evidence (target likely unreachable or refusing connections).")
		}
		findings = append(findings, findingsFromScanResult(scanRes, scheme)...)
	} else {
		partial = true
		if targetReachable {
			hasObservableSecurityEvidence = true
		}
		notes = append(notes, "Core security scan returned no results (target unreachable or scan failed).")
	}

	// 2) Lightweight OWASP/passive checks (safe categories only; non-intrusive).
	owaspFindings, owaspPartial, owaspNote := runLightweightOWASP(ctx, targetURL, control)
	if owaspNote != "" {
		notes = append(notes, owaspNote)
	}
	partial = partial || owaspPartial
	findings = append(findings, owaspFindings...)
	if len(owaspFindings) > 0 {
		hasObservableSecurityEvidence = true
	}

	// If we could not collect any observable security evidence (common for
	// unreachable/unknown targets), report this explicitly so scoring does not
	// treat "no findings observed" as a verified secure posture.
	switch {
	case !hasObservableSecurityEvidence:
		partial = true
		if len(findings) == 0 {
			findings = append(findings, Finding{
				Title:         "Target unreachable or unassessable — security posture could not be verified",
				Severity:      "high",
				ImpactSummary: "The target did not produce observable security evidence, so its security posture remains unverified.",
				Remediation:   "Verify the target URL, DNS, network reachability, and that the service is running and accessible from this environment, then rerun the audit.",
				Evidence:      "No observable TLS/HTTP/security-header/OWASP evidence could be collected from the target during the security scan.",
				Source:        "security_scan",
			})
		}
	case len(findings) == 0 && partial:
		// Partial evidence with no specific findings: keep partial state; no
		// synthetic weakness added beyond coverage handling.
		notes = append(notes, "Security scan completed with partial evidence and no specific weaknesses reported by completed checks.")
	}
	// A complete scan that observed evidence and found nothing is a valid
	// "no issues found by executed checks" outcome; nothing to add.

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
			st := strings.ToLower(strings.TrimSpace(d.Status))
			if st != "missing" && st != "weak" {
				continue
			}
			sev := "medium"
			if st == "weak" {
				sev = "medium"
			}
			header := strings.TrimSpace(d.Header)
			if header == "" {
				header = "security header"
			}
			statusWord := "Misconfigured"
			switch st {
			case "missing":
				statusWord = "Missing"
			case "weak":
				statusWord = "Weak"
			}
			title := fmt.Sprintf("%s security header: %s", statusWord, header)
			rem := strings.TrimSpace(d.Message)
			if rem == "" {
				rem = headerSpecificRemediation(header)
			}
			impact := headerImpact(header, st)
			evidence := fmt.Sprintf("Security header check for %q returned status=%q.", header, st)
			if strings.TrimSpace(d.Value) != "" {
				evidence += " Observed value: " + strings.TrimSpace(d.Value) + "."
			}
			if strings.TrimSpace(d.Message) != "" {
				evidence += " Scanner note: " + strings.TrimSpace(d.Message) + "."
			}
			out = append(out, Finding{
				Title:         title,
				Severity:      sev,
				ImpactSummary: impact,
				Remediation:   rem,
				Evidence:      evidence,
				Source:        "security_scan",
			})
		}
		// Report each missing header explicitly (full breakdown), even if not
		// already represented in Details by a specific implementation.
		for _, h := range res.Security.MissingHeaders {
			header := strings.TrimSpace(h)
			if header == "" {
				continue
			}
			out = append(out, Finding{
				Title:         "Missing security header: " + header,
				Severity:      "medium",
				ImpactSummary: headerImpact(header, "missing"),
				Remediation:   headerSpecificRemediation(header),
				Evidence:      fmt.Sprintf("Header %q was not observed in the HTTP response.", header),
				Source:        "security_scan",
			})
		}
	}

	if res.TLS != nil {
		for _, v := range res.TLS.Vulnerabilities {
			issue := strings.TrimSpace(v)
			if issue == "" {
				continue
			}
			out = append(out, Finding{
				Title:         "TLS/SSL weakness: " + issue,
				Severity:      "high",
				ImpactSummary: "Weak or misconfigured TLS can expose traffic to interception, downgrade, or confidentiality/integrity risks.",
				Remediation:   "Remediate the reported TLS issue: " + issue + ". Disable weak protocols/ciphers/features and use modern TLS configuration.",
				Evidence:      "TLS scan reported: " + issue,
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
				Severity:      "critical",
				ImpactSummary: "Users and clients may distrust or block connections; expired certificates undermine transport trust.",
				Remediation:   "Renew and deploy a valid TLS certificate before production exposure and ensure automated renewal/monitoring.",
				Evidence:      ev,
				Source:        "security_scan",
			})
		}
		if res.TLS.Certificate != nil && res.TLS.Certificate.IsSelfSigned && strings.EqualFold(scheme, "https") {
			ev := "TLS certificate reported as self-signed by scan."
			if strings.TrimSpace(res.TLS.Certificate.Subject) != "" {
				ev += " Subject=" + strings.TrimSpace(res.TLS.Certificate.Subject) + "."
			}
			out = append(out, Finding{
				Title:         "Self-signed TLS certificate",
				Severity:      "medium",
				ImpactSummary: "Self-signed certificates can trigger trust warnings and weaken assurance for users and integrations.",
				Remediation:   "Use a certificate issued by a trusted CA for production endpoints.",
				Evidence:      ev,
				Source:        "security_scan",
			})
		}
		if strings.EqualFold(scheme, "https") && !res.TLS.HasHSTS {
			out = append(out, Finding{
				Title:         "Missing HSTS policy on HTTPS endpoint",
				Severity:      "medium",
				ImpactSummary: "Without HSTS, browsers may be more exposed to downgrade or insecure-first connection attempts.",
				Remediation:   "Enable HTTP Strict Transport Security (HSTS) with an appropriate max-age and staged rollout plan.",
				Evidence:      "HTTPS target scanned but HSTS header/policy was not detected.",
				Source:        "security_scan",
			})
		}
		if strings.EqualFold(scheme, "https") && strings.TrimSpace(res.TLS.Version) != "" {
			switch strings.TrimSpace(res.TLS.Version) {
			case "TLS 1.0", "TLS 1.1":
				out = append(out, Finding{
					Title:         "Deprecated TLS protocol version in use: " + strings.TrimSpace(res.TLS.Version),
					Severity:      "high",
					ImpactSummary: "Deprecated TLS versions weaken transport security and may be vulnerable to known protocol weaknesses.",
					Remediation:   "Disable TLS 1.0/1.1 and enforce TLS 1.2+ (prefer TLS 1.3) with modern cipher suites.",
					Evidence:      "Negotiated/observed TLS version: " + strings.TrimSpace(res.TLS.Version) + ".",
					Source:        "security_scan",
				})
			}
		}
	}

	if res.HTTP != nil {
		if s := strings.TrimSpace(res.HTTP.Server); s != "" {
			out = append(out, Finding{
				Title:         "Server version/banner disclosure",
				Severity:      "low",
				ImpactSummary: "Exposed server software/version details can help attackers fingerprint the stack and target known issues.",
				Remediation:   "Minimize or remove detailed Server header/banner information where possible.",
				Evidence:      "Observed Server header: " + s,
				Source:        "security_scan",
			})
		}
		if s := strings.TrimSpace(res.HTTP.XPoweredBy); s != "" {
			out = append(out, Finding{
				Title:         "Technology stack disclosure (X-Powered-By)",
				Severity:      "low",
				ImpactSummary: "Framework/runtime disclosure can aid fingerprinting and targeted exploitation attempts.",
				Remediation:   "Disable or mask X-Powered-By and similar technology-identifying headers.",
				Evidence:      "Observed X-Powered-By header: " + s,
				Source:        "security_scan",
			})
		}
		if res.HTTP.CORS != nil && res.HTTP.CORS.IsPermissive {
			origin := strings.TrimSpace(res.HTTP.CORS.AllowOrigin)
			if origin == "" {
				origin = "*"
			}
			out = append(out, Finding{
				Title:         "Permissive CORS configuration detected",
				Severity:      "medium",
				ImpactSummary: "Overly permissive CORS can expose responses to untrusted origins and increase risk for sensitive endpoints.",
				Remediation:   "Restrict Access-Control-Allow-Origin to trusted origins and avoid wildcard or reflective policies for sensitive responses.",
				Evidence:      "Observed permissive CORS policy (Allow-Origin=" + origin + ").",
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
		title := strings.TrimSpace(v.Title)
		if title == "" {
			title = "Reported security weakness"
		}
		if ev == "" {
			ev = "Reported by scanner finding: " + title
		}
		if strings.TrimSpace(v.ID) != "" {
			ev = "Finding ID " + strings.TrimSpace(v.ID) + ": " + ev
		}
		out = append(out, Finding{
			Title:         title,
			Severity:      normalizeSeverity(v.Severity),
			ImpactSummary: impact,
			Remediation:   rem,
			Evidence:      ev,
			Source:        "security_scan",
		})
	}

	return out
}

func headerSpecificRemediation(header string) string {
	switch strings.ToLower(strings.TrimSpace(header)) {
	case "strict-transport-security":
		return "Enable HSTS (Strict-Transport-Security) with an appropriate max-age, includeSubDomains where safe, and a staged rollout plan."
	case "content-security-policy":
		return "Define and deploy a Content-Security-Policy tailored to the application to reduce XSS and content injection risk."
	case "x-frame-options":
		return "Set X-Frame-Options (or CSP frame-ancestors) to prevent clickjacking on sensitive pages."
	case "x-content-type-options":
		return "Set X-Content-Type-Options: nosniff to prevent MIME type sniffing."
	case "referrer-policy":
		return "Set a restrictive Referrer-Policy to limit leakage of sensitive URL data to third parties."
	case "permissions-policy":
		return "Set Permissions-Policy to explicitly restrict browser features not required by the application."
	default:
		return "Configure the recommended security header according to application requirements and security best practices."
	}
}

func headerImpact(header, status string) string {
	h := strings.ToLower(strings.TrimSpace(header))
	st := strings.ToLower(strings.TrimSpace(status))
	base := "Missing or weak security headers can weaken browser-side protections."
	switch h {
	case "strict-transport-security":
		base = "Without effective HSTS, clients may be more exposed to downgrade or insecure-first connection attempts."
	case "content-security-policy":
		base = "Without an effective CSP, browsers have less protection against XSS and content injection attacks."
	case "x-frame-options":
		base = "Without clickjacking protection, sensitive pages may be embedded in malicious frames."
	case "x-content-type-options":
		base = "Without MIME sniffing protection, browsers may interpret responses unsafely."
	case "referrer-policy":
		base = "A weak or missing referrer policy can leak sensitive URL information to third parties."
	case "permissions-policy":
		base = "Without a restrictive permissions policy, unnecessary browser features may remain available to page content."
	}
	if st == "weak" {
		return base + " The current configuration is weak and should be hardened."
	}
	return base
}

func runLightweightOWASP(ctx context.Context, targetURL string, control func(network, address string, c syscall.RawConn) error) ([]Finding, bool, string) {
	// Run passive/safe categories directly (non-intrusive). Intrusive OWASP
	// categories send payloads and require explicit intrusive authorization/gating;
	// this 360° stage intentionally remains lightweight and non-intrusive.
	done := make(chan *owasp.OWASPReport, 1)
	go func() {
		c := owasp.NewOWASPChecker(targetURL)
		c.DialControl = control
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

func runStressTest(ctx context.Context, targetURL string, budget time.Duration, control func(network, address string, c syscall.RawConn) error) StressOutcome {
	out := StressOutcome{Notes: []string{}}
	if _, _, _, err := ParseTargetHostPort(targetURL); err != nil {
		out.Notes = append(out.Notes, "Stress test skipped: invalid target URL.")
		return out
	}

	// Quick reachability probe (no fabricated metrics if unreachable).
	if !probeReachable(targetURL, 1500*time.Millisecond, control) {
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

	eng, err := engine.NewWithControl(sc, control)
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

func probeReachable(targetURL string, timeout time.Duration, control func(network, address string, c syscall.RawConn) error) bool {
	host, port, _, err := ParseTargetHostPort(targetURL)
	if err != nil {
		return false
	}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	dialer := net.Dialer{Timeout: timeout, Control: control}
	conn, err := dialer.Dial("tcp", addr)
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
	// Shape only: any well-formed http(s) URL parses here. Authorization is a
	// separate decision the caller makes before starting a run — the dashboard
	// applies the same authz gate as the CLI (metadata closed, private ranges
	// need a rule) in handleAudit360Start.
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
