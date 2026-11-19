package engine

import (
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/sift/internal/config"
)

func TestConstantRPSProfile(t *testing.T) {
	p := newConstantRPSProfile(500, 10, 30*time.Second)

	if p.targetRPS != 500 {
		t.Errorf("targetRPS = %d, want 500", p.targetRPS)
	}
	if p.Duration() != 30*time.Second {
		t.Errorf("duration = %s, want 30s", p.Duration())
	}
	if p.MaxConcurrency() != 500 {
		t.Errorf("MaxConcurrency = %d, want 500", p.MaxConcurrency())
	}
	if p.ConcurrencyAt(0) != 500 {
		t.Errorf("ConcurrencyAt(0) = %d, want 500 (fixed workers)", p.ConcurrencyAt(0))
	}
	if !p.IsConstantRPS() {
		t.Error("IsConstantRPS should be true")
	}
}

func TestConstantRPSRampUp(t *testing.T) {
	p := newConstantRPSProfile(1000, 10, 30*time.Second)

	if got := p.TargetRPSAt(0); got != 1 {
		t.Errorf("TargetRPSAt(0) = %d, want 1", got)
	}
	if got := p.TargetRPSAt(5 * time.Second); got < 490 || got > 510 {
		t.Errorf("TargetRPSAt(5s) = %d, want ~500", got)
	}
	if got := p.TargetRPSAt(10 * time.Second); got != 1000 {
		t.Errorf("TargetRPSAt(10s) = %d, want 1000", got)
	}
	if got := p.TargetRPSAt(20 * time.Second); got != 1000 {
		t.Errorf("TargetRPSAt(20s) = %d, want 1000 (post-ramp)", got)
	}
}

func TestConstantRPSZeroRampUp(t *testing.T) {
	p := newConstantRPSProfile(200, 0, 30*time.Second)

	// rampUp=0 defaults to dur/2 = 15s, so at t=0 RPS is 1.
	if got := p.TargetRPSAt(0); got != 1 {
		t.Errorf("TargetRPSAt(0) = %d, want 1 (ramp starts at 0)", got)
	}
	if p.RampDuration() != 15*time.Second {
		t.Errorf("RampDuration = %s, want 15s (default = dur/2)", p.RampDuration())
	}
	// At t=15s, should reach full target.
	if got := p.TargetRPSAt(15 * time.Second); got != 200 {
		t.Errorf("TargetRPSAt(15s) = %d, want 200", got)
	}
}

func TestBuildProfileConstantRPS(t *testing.T) {
	p, err := buildProfile(config.Profile{
		Type:      config.ProfileConstantRPS,
		TargetRPS: 500,
		Duration:  30,
		RampUp:    5,
	})
	if err != nil {
		t.Fatal(err)
	}
	crps, ok := p.(*constantRPSProfile)
	if !ok {
		t.Fatalf("expected *constantRPSProfile, got %T", p)
	}
	if crps.targetRPS != 500 {
		t.Errorf("targetRPS = %d, want 500", crps.targetRPS)
	}
}

func TestConstantRPSConfigNormalize(t *testing.T) {
	// Missing target_rps should fail.
	sc := &config.Scenario{
		Profile: config.Profile{Type: config.ProfileConstantRPS},
		Steps:   []config.Step{{URL: "/x"}},
	}
	if err := sc.Normalize(); err == nil {
		t.Error("expected error for constant-rps without target_rps")
	}

	// Valid constant-rps.
	sc = &config.Scenario{
		Profile: config.Profile{Type: config.ProfileConstantRPS, TargetRPS: 100, Duration: 30},
		Steps:   []config.Step{{URL: "/x"}},
	}
	if err := sc.Normalize(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sc.Profile.RampUp != 15 {
		t.Errorf("default ramp_up = %d, want 15 (duration/2)", sc.Profile.RampUp)
	}
}
