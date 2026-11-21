package audit360

import (
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestValidateStartRequest_RequiresAuthorization(t *testing.T) {
	_, _, _, err := ValidateStartRequest(StartRequest{TargetURL: "http://127.0.0.1:8090", Authorized: false, Mode: ModeStandard}, "http://127.0.0.1:8090", false)
	if err == nil || !strings.Contains(err.Error(), "authorized") {
		t.Fatalf("expected authorization error, got: %v", err)
	}
}

func TestValidateStartRequest_PassiveAllowsAnyTargetWithoutAuth(t *testing.T) {
	target, dur, mode, err := ValidateStartRequest(StartRequest{TargetURL: "https://example.com/path", Authorized: false, Mode: ModePassive, MaxDurationSec: 25}, "http://127.0.0.1:8090", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mode != ModePassive {
		t.Fatalf("mode = %q, want passive", mode)
	}
	if target != "https://example.com/path" {
		t.Fatalf("unexpected target: %q", target)
	}
	if dur != 25*time.Second {
		t.Fatalf("duration = %v, want 25s", dur)
	}
}

func TestValidateStartRequest_StandardAllowsAnyTargetWithAuth(t *testing.T) {
	target, _, mode, err := ValidateStartRequest(StartRequest{TargetURL: "https://example.com", Authorized: true, Mode: ModeStandard, MaxDurationSec: 25}, "http://127.0.0.1:8090", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mode != ModeStandard || target != "https://example.com" {
		t.Fatalf("unexpected result: mode=%q target=%q", mode, target)
	}
}

func TestValidateStartRequest_AdminRequiresBypass(t *testing.T) {
	_, _, _, err := ValidateStartRequest(StartRequest{TargetURL: "https://example.com", Authorized: false, Mode: ModeAdmin}, "http://127.0.0.1:8090", false)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "admin") {
		t.Fatalf("expected admin permission error, got: %v", err)
	}
	target, _, mode, err := ValidateStartRequest(StartRequest{TargetURL: "https://example.com", Authorized: false, Mode: ModeAdmin}, "http://127.0.0.1:8090", true)
	if err != nil {
		t.Fatalf("unexpected error with bypass: %v", err)
	}
	if mode != ModeAdmin || target != "https://example.com" {
		t.Fatalf("unexpected result: mode=%q target=%q", mode, target)
	}
}

func TestValidateStartRequest_AcceptsDemoStoreTarget(t *testing.T) {
	target, dur, mode, err := ValidateStartRequest(StartRequest{TargetURL: "http://127.0.0.1:8090/health", Authorized: true, MaxDurationSec: 25}, "http://127.0.0.1:8090", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mode != ModeStandard {
		t.Fatalf("mode = %q, want standard", mode)
	}
	if !strings.HasPrefix(target, "http://127.0.0.1:8090") {
		t.Fatalf("unexpected normalized target: %q", target)
	}
	if dur != 25*time.Second {
		t.Fatalf("duration = %v, want 25s", dur)
	}
}

func TestIsDemoStoreTarget_LocalhostEquivalence(t *testing.T) {
	if !IsDemoStoreTarget("http://localhost:8090/", "http://127.0.0.1:8090") {
		t.Fatal("expected localhost and 127.0.0.1 demo-store targets to match")
	}
	if IsDemoStoreTarget("http://127.0.0.1:8080/", "http://127.0.0.1:8090") {
		t.Fatal("different ports must not match")
	}
}

func TestComputeResilience_NoFabricationWhenLoadUnavailable(t *testing.T) {
	score, risk, findings, notes := ComputeResilience(nil, false, LoadOutcome{Available: false})
	if score >= 90 {
		t.Fatalf("score should be penalized when load unavailable, got %d", score)
	}
	if risk == "" {
		t.Fatal("risk level must be set")
	}
	found := false
	for _, f := range findings {
		title := strings.ToLower(f.Title)
		if strings.Contains(title, "capacity test unavailable") {
			found = true
		}
		if found && strings.TrimSpace(f.Evidence) == "" {
			t.Fatalf("expected evidence on capacity-unavailable finding: %+v", f)
		}
		if found && strings.TrimSpace(f.Remediation) == "" {
			t.Fatalf("expected remediation on capacity-unavailable finding: %+v", f)
		}
	}
	if !found {
		t.Fatalf("expected capacity-unavailable finding, got %+v", findings)
	}
	joined := strings.Join(notes, " ")
	if !strings.Contains(strings.ToLower(joined), "unavailable") {
		t.Fatalf("expected unavailable note, got %v", notes)
	}
}

func TestComputeResilience_BreachLowersScore(t *testing.T) {
	scoreNoBreach, _, _, _ := ComputeResilience(nil, false, LoadOutcome{Available: true, Breached: false, MaxObservedUsers: 300, PeakP99MS: 200})
	scoreBreach, _, findings, _ := ComputeResilience(nil, false, LoadOutcome{Available: true, Breached: true, BreakingPointUsers: 120, BreachReason: "error rate 6% > 5%", PeakErrorRatePct: 6})
	if scoreBreach >= scoreNoBreach {
		t.Fatalf("breach score (%d) should be lower than no-breach score (%d)", scoreBreach, scoreNoBreach)
	}
	ok := false
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Title), "capacity limit reached") {
			ok = true
			if strings.TrimSpace(f.Evidence) == "" || strings.TrimSpace(f.Remediation) == "" {
				t.Fatalf("expected evidence and remediation on breaking-point finding: %+v", f)
			}
		}
	}
	if !ok {
		t.Fatalf("expected breaking-point finding, got %+v", findings)
	}
}

func TestComputeResilience_BlockedTargetDoesNotClaimCapacityLimit(t *testing.T) {
	// A target answering 403 to every request looks like a 100% error rate, but it
	// is refusing load, not failing under it. The report must say so.
	score, risk, findings, _ := ComputeResilience(nil, false, LoadOutcome{
		Available:        true,
		RejectedByTarget: true,
		RejectStatusCode: http.StatusForbidden,
		RejectSharePct:   100,
		PeakErrorRatePct: 100,
		PeakP99MS:        2,
	})
	for _, f := range findings {
		title := strings.ToLower(f.Title)
		if strings.Contains(title, "capacity limit reached") {
			t.Fatalf("blocked target must not be reported as a capacity limit: %+v", findings)
		}
		if strings.Contains(title, "capacity test unavailable") {
			t.Fatalf("blocked target must not be reported as unavailable: %+v", findings)
		}
	}
	var blocked *Finding
	for i := range findings {
		if strings.Contains(strings.ToLower(findings[i].Title), "refused load") {
			blocked = &findings[i]
		}
	}
	if blocked == nil {
		t.Fatalf("expected a 'refused load' finding, got %+v", findings)
	}
	if blocked.Severity != "medium" {
		t.Fatalf("blocked-target finding severity = %q, want medium", blocked.Severity)
	}
	if !strings.Contains(blocked.ImpactSummary, "403") {
		t.Fatalf("blocked-target finding must name the rejection status, got %q", blocked.ImpactSummary)
	}
	if strings.TrimSpace(blocked.Evidence) == "" || !strings.Contains(blocked.Evidence, "403") {
		t.Fatalf("blocked-target finding must include measured evidence naming rejection, got %q", blocked.Evidence)
	}
	if strings.TrimSpace(blocked.Remediation) == "" {
		t.Fatalf("blocked-target finding must include remediation")
	}
	if score >= 100 || score <= 0 {
		t.Fatalf("score = %d, want penalized but valid score for unmeasurable blocked capacity", score)
	}
	if risk != RiskLow && risk != RiskModerate {
		t.Fatalf("risk = %q, want low or moderate (blocked/refused load is not a confirmed capacity breach)", risk)
	}
}

func TestDominantRejection(t *testing.T) {
	cases := []struct {
		name  string
		codes map[int]uint64
		want  int
	}{
		{"all 403", map[int]uint64{403: 100}, 403},
		{"all 429", map[int]uint64{429: 50}, 429},
		{"403 majority", map[int]uint64{403: 80, 200: 20}, 403},
		{"mixed 200", map[int]uint64{200: 60, 403: 40}, 0},
		{"server errors are not rejection", map[int]uint64{500: 100}, 0},
		{"empty", map[int]uint64{}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _ := dominantRejection(tc.codes)
			if code != tc.want {
				t.Fatalf("dominantRejection(%v) = %d, want %d", tc.codes, code, tc.want)
			}
		})
	}
}

func TestRunLoadTest_DetectsTargetRejection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("Access Temporarily Blocked"))
	}))
	defer srv.Close()

	out := runLoadTest(context.Background(), srv.URL, 6*time.Second, nil)

	if !out.RejectedByTarget {
		t.Fatalf("expected RejectedByTarget, notes: %v", out.Notes)
	}
	if out.RejectStatusCode != http.StatusForbidden {
		t.Fatalf("RejectStatusCode = %d, want 403", out.RejectStatusCode)
	}
	if out.Breached {
		t.Fatal("a rejecting target must not be flagged as a capacity breach")
	}
	if out.MaxObservedRPS != 0 || out.MaxSafeRPS != 0 {
		t.Fatalf("capacity figures must be suppressed, got rps=%v safe=%v", out.MaxObservedRPS, out.MaxSafeRPS)
	}
	if len(out.Notes) == 0 || !strings.Contains(out.Notes[0], "403") {
		t.Fatalf("expected a note naming HTTP 403, got %v", out.Notes)
	}
}

func TestSealAndVerify(t *testing.T) {
	rep := &Audit360Report{
		ResilienceScore:      72,
		RiskLevel:            RiskModerate,
		TargetURL:            "http://127.0.0.1:8090",
		Timestamp:            time.Now().UTC().Format(time.RFC3339),
		LoadTestAvailable:    true,
		BreakingPointReached: false,
		Findings:             []Finding{{Title: "Missing header", Severity: "medium", ImpactSummary: "impact", Remediation: "fix", Evidence: "Header X-Test missing in response", Source: "security_scan"}},
		Notes:                []string{"note"},
		DurationMS:           1234,
		ScoringVersion:       ScoringVersion,
		Scores:               &ScoreBreakdown{Overall: 72, Security: 80, Resilience: 70, Capacity: 75, EvidenceQuality: 60},
		TestConfiguration:    &TestConfiguration{Mode: ModeStandard, MaxDurationSec: 25, RequestedTarget: "http://127.0.0.1:8090", SecurityScanEnabled: true, ActiveLoadEnabled: true},
		RawEvidenceHash:      "abc123",
		RawEvidenceFormat:    "sha256(json:sift.audit360.raw-evidence/v1)",
	}
	certID, sig, pub, err := Seal(rep)
	if err != nil {
		// sealing may warn but should still produce cert id; signature may be empty only on key failure
		t.Logf("seal warning: %v", err)
	}
	if certID == "" {
		t.Fatal("certificate id must not be empty")
	}
	// Seal returns the seal; the caller stores it on the report, exactly as the
	// orchestrator does through SealWithKey. Verification then recomputes the
	// certificate id from the payload and requires it to match.
	rep.CertificateID = certID
	rep.VPMPSignature = sig
	if sig != "" {
		ok, reason := VerifySeal(rep, sig, pub)
		if !ok {
			t.Fatalf("signature verification failed: %s", reason)
		}
		// tamper overall score
		tampered := *rep
		tampered.ResilienceScore = 99
		ok, _ = VerifySeal(&tampered, sig, pub)
		if ok {
			t.Fatal("tampered report must not verify")
		}
		// tamper integrity-bound metadata
		tampered2 := *rep
		tampered2.RawEvidenceHash = "deadbeef"
		ok, _ = VerifySeal(&tampered2, sig, pub)
		if ok {
			t.Fatal("tampered raw evidence hash must not verify")
		}
		// tamper capacity-blocked evidence fields (must be seal-bound)
		tampered3 := *rep
		tampered3.CapacityBlocked = true
		tampered3.BlockedStatus = 403
		tampered3.BlockedSharePct = 100
		ok, _ = VerifySeal(&tampered3, sig, pub)
		if ok {
			t.Fatal("tampered capacity-blocked fields must not verify")
		}
	}
}

func TestRunIntegrationAgainstLocalServer(t *testing.T) {
	// Local test server acts as authorized demo-store target.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	var sawStage bool
	rep, err := Run(ctx, Options{
		TargetURL:    srv.URL,
		MaxDuration:  8 * time.Second, // short but exercises pipeline
		DemoStoreURL: srv.URL,
	}, func(stageID, status, detail, errMsg string) {
		_ = detail
		_ = errMsg
		if stageID != "" && status != "" {
			sawStage = true
		}
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if rep == nil {
		t.Fatal("expected report")
	}
	if !sawStage {
		t.Fatal("expected progress callbacks")
	}
	if rep.Timestamp == "" || rep.RiskLevel == "" {
		t.Fatalf("report missing required fields: %+v", rep)
	}
	if rep.CertificateID == "" {
		t.Fatal("certificate_id must be set")
	}
	if rep.ResilienceScore < 0 || rep.ResilienceScore > 100 {
		t.Fatalf("invalid resilience score: %d", rep.ResilienceScore)
	}
	// No fabrication: load may be available or not depending on environment timing; fields must be consistent.
	if !rep.LoadTestAvailable {
		if rep.BreakingPointReached || rep.BreakingPointUsers != 0 {
			t.Fatalf("load unavailable but breaking point reported: %+v", rep)
		}
	}
}

func TestComputeResilience_CriticalFindingCannotYieldLowRiskOrHighOverall(t *testing.T) {
	score, risk, findings, _ := ComputeResilience([]Finding{{
		Title:         "Critical security exposure",
		Severity:      "critical",
		ImpactSummary: "critical",
		Remediation:   "fix",
		Evidence:      "measured",
		Source:        "security_scan",
	}}, false, LoadOutcome{Available: true, Breached: false, MaxObservedUsers: 500, MaxObservedRPS: 200, MaxSafeRPS: 180, PeakP99MS: 100})
	if risk != RiskCritical {
		t.Fatalf("risk = %q, want %q when critical finding exists", risk, RiskCritical)
	}
	if score > 54 {
		t.Fatalf("overall score = %d, want <=54 when critical finding exists (findings=%+v)", score, findings)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings")
	}
}

func TestComputeResilience_HighFindingCannotYieldLowRisk(t *testing.T) {
	score, risk, _, _ := ComputeResilience([]Finding{{
		Title: "High severity issue", Severity: "high", ImpactSummary: "impact", Remediation: "fix", Evidence: "ev", Source: "security_scan",
	}}, false, LoadOutcome{Available: true, Breached: false, MaxObservedUsers: 500, MaxObservedRPS: 200, MaxSafeRPS: 180, PeakP99MS: 100})
	if risk == RiskLow {
		t.Fatalf("risk must not be Low when high-severity finding exists (score=%d)", score)
	}
	if score > 79 {
		t.Fatalf("overall score = %d, want <=79 when high-severity finding exists", score)
	}
}

func TestComputeResilience_SkippedPassiveNoFabricatedCapacityBreach(t *testing.T) {
	score, _, findings, notes := ComputeResilience(nil, false, LoadOutcome{Skipped: true})
	if score < 0 || score > 100 {
		t.Fatalf("score out of range: %d", score)
	}
	for _, f := range findings {
		lt := strings.ToLower(f.Title)
		if strings.Contains(lt, "capacity limit reached") || strings.Contains(lt, "capacity test unavailable") {
			t.Fatalf("skipped passive run must not claim breach/unavailable capacity failure: %+v", findings)
		}
	}
	joined := strings.ToLower(strings.Join(notes, " "))
	if !strings.Contains(joined, "skipped") && !strings.Contains(joined, "passive") {
		t.Fatalf("expected passive/skipped note, got %v", notes)
	}
}

func TestComputeResilience_ZeroSampleOutcomeNoInvalidState(t *testing.T) {
	// Zero/timeout-like edge: no samples, all zero metrics, unavailable/unmeasurable.
	score, risk, findings, _ := ComputeResilience(nil, false, LoadOutcome{})
	if score < 0 || score > 100 {
		t.Fatalf("score out of range for zero-sample outcome: %d", score)
	}
	if risk == "" {
		t.Fatal("risk must be set")
	}
	foundUnavailable := false
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Title), "capacity test unavailable") {
			foundUnavailable = true
		}
	}
	if !foundUnavailable {
		t.Fatalf("expected unavailable finding for zero-sample outcome, got %+v", findings)
	}
}

func TestSealVerify_TamperedCertificateIDFails(t *testing.T) {
	rep := &Audit360Report{
		ResilienceScore: 80, RiskLevel: RiskLow, TargetURL: "http://127.0.0.1:8090",
		Timestamp: time.Now().UTC().Format(time.RFC3339), LoadTestAvailable: true,
		Findings: []Finding{}, Notes: []string{"n"}, DurationMS: 10,
		ScoringVersion: ScoringVersion, RawEvidenceHash: "h", RawEvidenceFormat: "f",
		Scores: &ScoreBreakdown{Overall: 80, Security: 80, Resilience: 80, Capacity: 80, EvidenceQuality: 80},
	}
	certID, sig, pub, err := Seal(rep)
	if err != nil {
		t.Logf("seal warning: %v", err)
	}
	if sig == "" {
		t.Skip("signature unavailable in environment")
	}
	rep.CertificateID = certID
	rep.VPMPSignature = sig
	ok, _ := VerifySeal(rep, sig, pub)
	if !ok {
		t.Fatal("expected untampered report to verify")
	}
	tampered := *rep
	// single-byte style change in sealed identity field
	if tampered.CertificateID != "" {
		b := []byte(tampered.CertificateID)
		b[len(b)-1] ^= 1
		tampered.CertificateID = string(b)
	}
	ok, reason := VerifySeal(&tampered, sig, pub)
	if ok || !strings.Contains(strings.ToLower(reason), "certificate") {
		t.Fatalf("tampered certificate id must fail verification, ok=%v reason=%q", ok, reason)
	}
}

func TestRunReportConsistency_LoadUnavailableNoFabricatedMetrics(t *testing.T) {
	// Unreachable target should yield no fabricated breach/capacity metrics and consistent state.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	rep, err := Run(ctx, Options{
		TargetURL:   "http://127.0.0.1:1", // almost certainly unreachable
		MaxDuration: 8 * time.Second,
		Mode:        ModeStandard,
	}, nil)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if rep == nil {
		t.Fatal("expected report")
	}
	if rep.Scores == nil {
		t.Fatal("expected scores")
	}
	if rep.ResilienceScore != rep.Scores.Overall {
		t.Fatalf("overall/resilience_score drift: report=%d scores=%d", rep.ResilienceScore, rep.Scores.Overall)
	}
	if rep.DurationMS < 0 {
		t.Fatalf("duration must be non-negative: %d", rep.DurationMS)
	}
	if rep.CapacityBlocked {
		t.Fatal("unreachable/unavailable run must not be marked as capacity-blocked rejection")
	}
	if rep.BreakingPointReached || rep.BreakingPointUsers != 0 || rep.MaxSafeRPS != 0 || rep.MaxObservedRPS != 0 {
		t.Fatalf("unavailable load must not fabricate capacity metrics: %+v", rep)
	}
	if rep.RiskLevel == "" {
		t.Fatal("risk level must be set")
	}
	// Returned sealed report must be self-consistent: signature/certificate must verify
	// against the final report payload (no post-seal mutation drift).
	if rep.VPMPSignature != "" {
		if rep.RawEvidenceHash == "" || rep.CertificateID == "" || rep.CertificateID == "unavailable" {
			t.Fatalf("sealed report missing integrity identifiers: cert=%q hash=%q", rep.CertificateID, rep.RawEvidenceHash)
		}
		// Public key is recorded in notes for attestation context; extract for verification.
		pub := ""
		for _, n := range rep.Notes {
			const pfx = "VPMP signer public key (hex): "
			if strings.HasPrefix(n, pfx) {
				pub = strings.TrimSpace(strings.TrimPrefix(n, pfx))
			}
		}
		if pub == "" {
			t.Fatal("sealed report missing signer public key note required for verification context")
		}
		ok, reason := VerifySeal(rep, rep.VPMPSignature, pub)
		if !ok {
			t.Fatalf("returned report signature must verify against final payload: %s", reason)
		}
	}
}

func TestComputeAssessment_SanitizesNonFiniteLoadMetrics(t *testing.T) {
	nan := math.NaN()
	inf := math.Inf(1)
	breakdown, risk, findings, notes := ComputeAssessment(nil, false, LoadOutcome{
		Available:        true,
		Breached:         false,
		MaxObservedRPS:   inf,
		MaxSafeRPS:       nan,
		MaxObservedUsers: 10,
		PeakErrorRatePct: nan,
		PeakP99MS:        inf,
	})
	if breakdown.Overall < 0 || breakdown.Overall > 100 || breakdown.Security < 0 || breakdown.Capacity < 0 || breakdown.Resilience < 0 || breakdown.EvidenceQuality < 0 {
		t.Fatalf("scores must remain bounded finite ints: %+v", breakdown)
	}
	if risk == "" {
		t.Fatal("risk must be set")
	}
	joined := strings.Join(notes, " ")
	if strings.Contains(joined, "NaN") || strings.Contains(joined, "Inf") {
		t.Fatalf("notes must not contain NaN/Inf: %v", notes)
	}
	for _, f := range findings {
		if strings.Contains(f.Evidence, "NaN") || strings.Contains(f.Evidence, "Inf") || strings.Contains(f.ImpactSummary, "NaN") {
			t.Fatalf("findings must not contain NaN/Inf: %+v", f)
		}
	}
}

func TestComputeAssessment_ZeroSamplesUnavailableConsistent(t *testing.T) {
	breakdown, risk, findings, _ := ComputeAssessment(nil, false, LoadOutcome{Available: false})
	if breakdown.Overall == 100 {
		t.Fatal("unavailable load with no measured capacity should not claim perfect overall assessment")
	}
	if risk == "" {
		t.Fatal("risk must be set")
	}
	found := false
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Title), "capacity test unavailable") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected unavailable-capacity finding, got %+v", findings)
	}
}

func TestComputeAssessment_PartialTimeoutAndZeroSamples(t *testing.T) {
	// Partial security scan + unavailable load (e.g. timeout/0 samples) must be explicit and bounded.
	breakdown, _, findings, notes := ComputeAssessment([]Finding{
		{Title: "Missing header", Severity: "medium", Source: "security_scan", Evidence: "X-Test missing"},
	}, true, LoadOutcome{Available: false, MaxObservedUsers: 0, MaxObservedRPS: 0})
	if breakdown.Security >= 100 || breakdown.EvidenceQuality >= 100 {
		t.Fatalf("partial/unavailable evidence must reduce relevant scores: %+v", breakdown)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings for partial/unavailable evidence")
	}
	if strings.Join(notes, " ") == "" {
		t.Fatal("expected explanatory notes")
	}
}
