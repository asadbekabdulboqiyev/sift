package audit360

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestValidateStartRequest_RequiresAuthorization(t *testing.T) {
	_, _, err := ValidateStartRequest(StartRequest{TargetURL: "http://127.0.0.1:8090", Authorized: false}, "http://127.0.0.1:8090")
	if err == nil || !strings.Contains(err.Error(), "authorized") {
		t.Fatalf("expected authorization error, got: %v", err)
	}
}

func TestValidateStartRequest_RejectsNonDemoTarget(t *testing.T) {
	_, _, err := ValidateStartRequest(StartRequest{TargetURL: "https://example.com", Authorized: true, MaxDurationSec: 25}, "http://127.0.0.1:8090")
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "allowlist") {
		t.Fatalf("expected allowlist/demo-store error, got: %v", err)
	}
}

func TestValidateStartRequest_AcceptsDemoStoreTarget(t *testing.T) {
	target, dur, err := ValidateStartRequest(StartRequest{TargetURL: "http://127.0.0.1:8090/health", Authorized: true, MaxDurationSec: 25}, "http://127.0.0.1:8090")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
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

func TestComputeResilience_NoFabricationWhenStressUnavailable(t *testing.T) {
	score, risk, findings, notes := ComputeResilience(nil, false, StressOutcome{Available: false})
	if score >= 90 {
		t.Fatalf("score should be penalized when stress unavailable, got %d", score)
	}
	if risk == "" {
		t.Fatal("risk level must be set")
	}
	found := false
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Title), "capacity test unavailable") {
			found = true
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
	scoreNoBreach, _, _, _ := ComputeResilience(nil, false, StressOutcome{Available: true, Breached: false, MaxObservedUsers: 300, PeakP99MS: 200})
	scoreBreach, _, findings, _ := ComputeResilience(nil, false, StressOutcome{Available: true, Breached: true, BreakingPointUsers: 120, BreachReason: "error rate 6% > 5%", PeakErrorRatePct: 6})
	if scoreBreach >= scoreNoBreach {
		t.Fatalf("breach score (%d) should be lower than no-breach score (%d)", scoreBreach, scoreNoBreach)
	}
	ok := false
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Title), "capacity limit reached") {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("expected breaking-point finding, got %+v", findings)
	}
}

func TestSealAndVerify(t *testing.T) {
	rep := &Audit360Report{
		ResilienceScore:      72,
		RiskLevel:            RiskModerate,
		TargetURL:            "http://127.0.0.1:8090",
		Timestamp:            time.Now().UTC().Format(time.RFC3339),
		StressTestAvailable:  true,
		BreakingPointReached: false,
		Findings:             []Finding{{Title: "Missing header", Severity: "medium", ImpactSummary: "impact", Remediation: "fix"}},
		Notes:                []string{"note"},
		DurationMS:           1234,
	}
	certID, sig, pub, err := Seal(rep)
	if err != nil {
		// sealing may warn but should still produce cert id; signature may be empty only on key failure
		t.Logf("seal warning: %v", err)
	}
	if certID == "" {
		t.Fatal("certificate id must not be empty")
	}
	if sig != "" {
		ok, reason := VerifySeal(rep, sig, pub)
		if !ok {
			t.Fatalf("signature verification failed: %s", reason)
		}
		// tamper
		tampered := *rep
		tampered.ResilienceScore = 99
		ok, _ = VerifySeal(&tampered, sig, pub)
		if ok {
			t.Fatal("tampered report must not verify")
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
	// No fabrication: stress may be available or not depending on environment timing; fields must be consistent.
	if !rep.StressTestAvailable {
		if rep.BreakingPointReached || rep.BreakingPointUsers != 0 {
			t.Fatalf("stress unavailable but breaking point reported: %+v", rep)
		}
	}
}
