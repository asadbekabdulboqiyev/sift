package evidence

import (
	"testing"

	"github.com/asadbekabdulboqiyev/sift/internal/attest"
	"github.com/asadbekabdulboqiyev/sift/internal/config"
)

// A rate is a number with a unit, and the bundle's unit is thousandths of a
// request per second. Getting the factor of 1000 wrong produces a bundle that
// still verifies, which is why the exact rendered decimal is asserted here.
func TestPlannedRPSMilliKeepsItsUnit(t *testing.T) {
	for _, tc := range []struct {
		name    string
		profile config.Profile
		want    int64
		wantDec string
	}{
		{"constant rps paces at target_rps", config.Profile{Type: config.ProfileConstantRPS, TargetRPS: 300}, 300_000, "300.000"},
		{"one request per second", config.Profile{TargetRPS: 1}, 1_000, "1.000"},
		{"global cap", config.Profile{Type: config.ProfileSteady, RPS: 250}, 250_000, "250.000"},
		{"direct pace wins over the cap", config.Profile{Type: config.ProfileConstantRPS, TargetRPS: 40, RPS: 900}, 40_000, "40.000"},
		{"unpaced run has no schedule", config.Profile{Type: config.ProfileSteady}, 0, "0.000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sc := &config.Scenario{Name: "unit", Profile: tc.profile}
			got := PlannedRPSMilli(sc)
			if got != tc.want {
				t.Errorf("PlannedRPSMilli = %d, want %d", got, tc.want)
			}
			dec, err := attest.DecimalFromMilli(got)
			if err != nil {
				t.Fatalf("DecimalFromMilli(%d): %v", got, err)
			}
			if dec.String() != tc.wantDec {
				t.Errorf("planned_rps renders as %q, want %q", dec.String(), tc.wantDec)
			}
		})
	}
}

func TestPlannedRPSMilliHandlesNilScenario(t *testing.T) {
	if got := PlannedRPSMilli(nil); got != 0 {
		t.Errorf("PlannedRPSMilli(nil) = %d, want 0", got)
	}
}

func mustMilli(t *testing.T, rps int64) attest.Decimal {
	t.Helper()
	d, err := attest.DecimalFromMilli(rps * 1000)
	if err != nil {
		t.Fatalf("DecimalFromMilli: %v", err)
	}
	return d
}
