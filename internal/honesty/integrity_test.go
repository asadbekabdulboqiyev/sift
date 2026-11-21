package honesty

// integrity_test.go — pacing bookkeeping and the coordinated-omission correction.

import (
	"math"
	"testing"
)

func TestPPMScaleConstant(t *testing.T) {
	if PPMScale != 1_000_000 {
		t.Fatalf("PPMScale = %d, want 1000000", PPMScale)
	}
}

func TestMulDivHelpers(t *testing.T) {
	if got, err := mulDivFloor(6, 7, 2); err != nil || got != 21 {
		t.Fatalf("mulDivFloor(6,7,2) = (%d,%v)", got, err)
	}
	if got, err := mulDivRound(1, 1, 2); err != nil || got != 1 {
		t.Fatalf("mulDivRound(1,1,2) = (%d,%v)", got, err)
	}
	if _, err := mulDivFloor(1, 1, 0); err == nil {
		t.Fatal("floor division by zero accepted")
	}
	if _, err := mulDivRound(1, 1, 0); err == nil {
		t.Fatal("round division by zero accepted")
	}
	// mulDivRoundU never panics: it returns 0 on overflow.
	if got := mulDivRoundU(1<<63, 2, 1); got != 0 {
		t.Fatalf("mulDivRoundU overflow = %d, want 0", got)
	}
}

func TestAchievedRPSMilli(t *testing.T) {
	cases := []struct {
		count    uint64
		duration int64
		want     int64
	}{
		{1000, 1_000_000_000, 1_000_000},
		{65, 10_000_000_000, 6_500},
		{0, 1_000_000_000, 0},
		{1, 1_000_000_000, 1_000},
	}
	for _, tc := range cases {
		got, err := AchievedRPSMilli(tc.count, tc.duration)
		if err != nil {
			t.Fatalf("AchievedRPSMilli(%d,%d): %v", tc.count, tc.duration, err)
		}
		if got != tc.want {
			t.Fatalf("AchievedRPSMilli(%d,%d) = %d, want %d", tc.count, tc.duration, got, tc.want)
		}
	}
	if _, err := AchievedRPSMilli(1, 0); err == nil {
		t.Fatal("zero duration accepted")
	}
	if _, err := AchievedRPSMilli(1, -1); err == nil {
		t.Fatal("negative duration accepted")
	}
}

func TestPlannedSlotsAndDropped(t *testing.T) {
	slots, err := PlannedSlots(1_000_000, 1_000_000_000)
	if err != nil || slots != 1000 {
		t.Fatalf("PlannedSlots(1e6,1e9) = (%d,%v), want 1000", slots, err)
	}
	if slots, _ := PlannedSlots(1000, 1_000_000_000); slots != 1 {
		t.Fatalf("1 rps over 1s = %d slots, want 1", slots)
	}
	if slots, _ := PlannedSlots(0, 1_000_000_000); slots != 0 {
		t.Fatalf("0 rps = %d slots", slots)
	}
	if _, err := PlannedSlots(-1, 1_000_000_000); err == nil {
		t.Fatal("negative planned rate accepted")
	}
	if _, err := PlannedSlots(1000, 0); err == nil {
		t.Fatal("zero duration accepted")
	}

	dropped, err := DroppedSamples(1_000_000, 1_000_000_000, 999)
	if err != nil || dropped != 1 {
		t.Fatalf("DroppedSamples = (%d,%v), want 1", dropped, err)
	}
	// More samples than slots never yields a negative drop count.
	if dropped, _ := DroppedSamples(1_000_000, 1_000_000_000, 5000); dropped != 0 {
		t.Fatalf("overcount drop = %d, want 0", dropped)
	}
}

func TestScheduleAccuracyPPM(t *testing.T) {
	cases := []struct {
		planned, achieved int64
		want              int64
	}{
		{1000, 1000, 1_000_000},
		{1000, 500, 500_000},  // 50% low
		{1000, 1500, 500_000}, // 50% high
		{1000, 2000, 0},       // 100% off
		{1000, 0, 0},          // nothing achieved
		{0, 0, 1_000_000},     // nothing planned, nothing achieved
		{0, 5, 0},             // nothing planned but something achieved
		{-5, 5, 0},            // non-positive planned rate
	}
	for _, tc := range cases {
		if got := ScheduleAccuracyPPM(tc.planned, tc.achieved); got != tc.want {
			t.Fatalf("ScheduleAccuracyPPM(%d,%d) = %d, want %d", tc.planned, tc.achieved, got, tc.want)
		}
	}
}

func TestIntendedStartNS(t *testing.T) {
	// Slot 1 (seq 1) begins at the window start.
	if got, err := IntendedStartNS(1000, 1, 1000); err != nil || got != 1000 {
		t.Fatalf("IntendedStartNS(1000,1,1000) = (%d,%v)", got, err)
	}
	// seq 0 is "before the first slot" and returns the window start.
	if got, err := IntendedStartNS(500, 0, 1000); err != nil || got != 500 {
		t.Fatalf("IntendedStartNS seq 0 = (%d,%v)", got, err)
	}
	// Slot 1000 at 1000 rps is 999 ms after the window start.
	if got, err := IntendedStartNS(0, 1000, 1_000_000); err != nil || got != 999_000_000 {
		t.Fatalf("IntendedStartNS(0,1000,1e6) = (%d,%v), want 999000000", got, err)
	}
	if _, err := IntendedStartNS(0, 1, 0); err == nil {
		t.Fatal("zero rate accepted")
	}
	if _, err := IntendedStartNS(-1, 1, 1000); err == nil {
		t.Fatal("negative window start accepted")
	}
}

func TestCorrectedLatencyNS(t *testing.T) {
	// On schedule: the raw latency is returned unchanged.
	if got, err := CorrectedLatencyNS(0, 5, 0, 1, 1000); err != nil || got != 5 {
		t.Fatalf("on-time correction = (%d,%v), want 5", got, err)
	}
	// Slot 2 is scheduled 1 s in; starting at 2 s adds 1 s of waiting.
	if got, err := CorrectedLatencyNS(2_000_000_000, 5, 0, 2, 1000); err != nil || got != 1_000_000_005 {
		t.Fatalf("late correction = (%d,%v), want 1000000005", got, err)
	}
	if _, err := CorrectedLatencyNS(0, -1, 0, 1, 1000); err == nil {
		t.Fatal("negative latency accepted")
	}
}

func TestSubsampleDeterministic(t *testing.T) {
	in := []int64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	got := subsample(in, 4)
	if len(got) != 4 {
		t.Fatalf("subsample length = %d, want 4", len(got))
	}
	want := []int64{0, 2, 5, 7}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("subsample[%d] = %d, want %d", i, got[i], want[i])
		}
	}
	if full := subsample(in, 100); len(full) != len(in) {
		t.Fatalf("subsample larger than input returned %d values", len(full))
	}
}

func TestCeilScaleAndClamp(t *testing.T) {
	if got := ceilScale(0, 1000); got != 0 {
		t.Fatalf("ceilScale(0,1000) = %d", got)
	}
	if got := ceilScale(1, 1000); got != 1 {
		t.Fatalf("ceilScale(1,1000) = %d, want 1", got)
	}
	if got := ceilScale(1000, 1000); got != 1 {
		t.Fatalf("ceilScale(1000,1000) = %d, want 1", got)
	}
	if got := ceilScale(1001, 1000); got != 2 {
		t.Fatalf("ceilScale(1001,1000) = %d, want 2", got)
	}
	if got := ceilScale(-5, 1000); got != 0 {
		t.Fatalf("ceilScale(-5,1000) = %d, want 0", got)
	}
	if got := clamp(5, 1, 3); got != 3 {
		t.Fatalf("clamp(5,1,3) = %d", got)
	}
	if got := clamp(0, 1, 3); got != 1 {
		t.Fatalf("clamp(0,1,3) = %d", got)
	}
	if got := clamp(2, 1, 3); got != 2 {
		t.Fatalf("clamp(2,1,3) = %d", got)
	}
}

// assertIntegrityBoundaryError checks the exact error text so a silent change
// in the guard order or message is caught, not just the presence of an error.
func assertIntegrityBoundaryError(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want %q", want)
	}
	if got := err.Error(); got != want {
		t.Fatalf("error = %q, want %q", got, want)
	}
}

func TestMulDivFloorBoundaries(t *testing.T) {
	cases := []struct {
		name    string
		a, b, d uint64
		want    uint64
		wantErr string
	}{
		{
			name:    "max uint64 times two over one overflows",
			a:       math.MaxUint64,
			b:       2,
			d:       1,
			wantErr: "honesty: 18446744073709551615*2/1 overflows 64 bits",
		},
		{
			name:    "max uint64 squared over one overflows",
			a:       math.MaxUint64,
			b:       math.MaxUint64,
			d:       1,
			wantErr: "honesty: 18446744073709551615*18446744073709551615/1 overflows 64 bits",
		},
		{
			// (2^64-1)^2 / (2^64-1) = 2^64-1 exactly; hi == d-1 must not error.
			name: "max uint64 squared over max uint64 is max uint64",
			a:    math.MaxUint64,
			b:    math.MaxUint64,
			d:    math.MaxUint64,
			want: math.MaxUint64,
		},
		{
			name: "half max times two over half max",
			a:    1 << 63,
			b:    2,
			d:    1 << 63,
			want: 2,
		},
		{
			name: "max uint64 times two over max uint64",
			a:    math.MaxUint64,
			b:    2,
			d:    math.MaxUint64,
			want: 2,
		},
		{
			name:    "zero divisor",
			a:       1,
			b:       1,
			d:       0,
			wantErr: "honesty: division by zero",
		},
		{
			// The divisor guard runs before the overflow guard.
			name:    "zero divisor takes precedence over overflowing product",
			a:       math.MaxUint64,
			b:       math.MaxUint64,
			d:       0,
			wantErr: "honesty: division by zero",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := mulDivFloor(tc.a, tc.b, tc.d)
			if tc.wantErr != "" {
				assertIntegrityBoundaryError(t, err, tc.wantErr)
				if got != 0 {
					t.Fatalf("result = %d, want 0 on error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("result = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestMulDivRoundBoundaries(t *testing.T) {
	cases := []struct {
		name    string
		a, b, d uint64
		want    uint64
		wantErr string
	}{
		{
			name:    "max uint64 times two over one overflows",
			a:       math.MaxUint64,
			b:       2,
			d:       1,
			wantErr: "honesty: 18446744073709551615*2/1 overflows 64 bits",
		},
		{
			name:    "half max times two over one overflows",
			a:       1 << 63,
			b:       2,
			d:       1,
			wantErr: "honesty: 9223372036854775808*2/1 overflows 64 bits",
		},
		{
			name:    "max uint64 squared over one overflows",
			a:       math.MaxUint64,
			b:       math.MaxUint64,
			d:       1,
			wantErr: "honesty: 18446744073709551615*18446744073709551615/1 overflows 64 bits",
		},
		{
			name: "max uint64 squared over max uint64 is max uint64",
			a:    math.MaxUint64,
			b:    math.MaxUint64,
			d:    math.MaxUint64,
			want: math.MaxUint64,
		},
		{
			// (2^64-1)/2 = 2^63-0.5; half-away-from-zero gives 2^63.
			name: "rounding half up at the int64 boundary",
			a:    math.MaxUint64,
			b:    1,
			d:    2,
			want: 1 << 63,
		},
		{
			name:    "zero divisor",
			a:       1,
			b:       1,
			d:       0,
			wantErr: "honesty: division by zero",
		},
		{
			name:    "zero divisor takes precedence over overflowing product",
			a:       math.MaxUint64,
			b:       math.MaxUint64,
			d:       0,
			wantErr: "honesty: division by zero",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := mulDivRound(tc.a, tc.b, tc.d)
			if tc.wantErr != "" {
				assertIntegrityBoundaryError(t, err, tc.wantErr)
				if got != 0 {
					t.Fatalf("result = %d, want 0 on error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("result = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestMulDivRoundUBoundaries(t *testing.T) {
	cases := []struct {
		name    string
		a, b, d uint64
		want    uint64
	}{
		{
			name: "overflow at divisor one",
			a:    math.MaxUint64,
			b:    2,
			d:    1,
			want: 0,
		},
		{
			name: "overflow at half max",
			a:    1 << 63,
			b:    2,
			d:    1,
			want: 0,
		},
		{
			name: "overflow with max operands",
			a:    math.MaxUint64,
			b:    math.MaxUint64,
			d:    1,
			want: 0,
		},
		{
			name: "zero divisor",
			a:    1,
			b:    1,
			d:    0,
			want: 0,
		},
		{
			name: "zero divisor with overflowing product",
			a:    math.MaxUint64,
			b:    math.MaxUint64,
			d:    0,
			want: 0,
		},
		{
			name: "rounding half up is preserved when there is no error",
			a:    math.MaxUint64,
			b:    1,
			d:    2,
			want: 1 << 63,
		},
		{
			name: "max operands over max divisor",
			a:    math.MaxUint64,
			b:    math.MaxUint64,
			d:    math.MaxUint64,
			want: math.MaxUint64,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := mulDivRoundU(tc.a, tc.b, tc.d); got != tc.want {
				t.Fatalf("mulDivRoundU(%d,%d,%d) = %d, want %d", tc.a, tc.b, tc.d, got, tc.want)
			}
		})
	}
}

func TestAchievedRPSMilliBoundaries(t *testing.T) {
	cases := []struct {
		name       string
		count      uint64
		durationNS int64
		want       int64
		wantErr    string
	}{
		{
			name:       "huge count overflows the 128-bit intermediate",
			count:      math.MaxUint64,
			durationNS: 1,
			wantErr:    "honesty: 18446744073709551615*1000000000000/1 overflows 64 bits",
		},
		{
			// count*1e12/duration = 2^64-1, which does not fit in int64.
			name:       "max uint64 count over 1000 seconds exceeds int64",
			count:      math.MaxUint64,
			durationNS: 1_000_000_000_000,
			wantErr:    "honesty: achieved rate overflows int64",
		},
		{
			name:       "max int64 count over 1000 seconds fits exactly",
			count:      math.MaxInt64,
			durationNS: 1_000_000_000_000,
			want:       math.MaxInt64,
		},
		{
			name:       "min int64 duration is rejected",
			count:      1,
			durationNS: math.MinInt64,
			wantErr:    "honesty: duration_ns -9223372036854775808 must be positive",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := AchievedRPSMilli(tc.count, tc.durationNS)
			if tc.wantErr != "" {
				assertIntegrityBoundaryError(t, err, tc.wantErr)
				if got != 0 {
					t.Fatalf("result = %d, want 0 on error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("result = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestPlannedSlotsBoundaries(t *testing.T) {
	cases := []struct {
		name                     string
		plannedMilli, durationNS int64
		want                     uint64
		wantErr                  string
	}{
		{
			name:         "max rate and max duration overflow the product",
			plannedMilli: math.MaxInt64,
			durationNS:   math.MaxInt64,
			wantErr:      "honesty: 9223372036854775807*9223372036854775807/1000000000000 overflows 64 bits",
		},
		{
			name:         "max rate over 1000 seconds is max int64 slots",
			plannedMilli: math.MaxInt64,
			durationNS:   1_000_000_000_000,
			want:         math.MaxInt64,
		},
		{
			// round((2^63-1+5e11)/1e12) = 9223372.
			name:         "tiny rate over max duration",
			plannedMilli: 1,
			durationNS:   math.MaxInt64,
			want:         9_223_372,
		},
		{
			name:         "min int64 duration is rejected",
			plannedMilli: 1,
			durationNS:   math.MinInt64,
			wantErr:      "honesty: duration_ns -9223372036854775808 must be positive",
		},
		{
			name:         "min int64 rate is rejected",
			plannedMilli: math.MinInt64,
			durationNS:   1,
			wantErr:      "honesty: planned rate -9223372036854775808 is negative",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := PlannedSlots(tc.plannedMilli, tc.durationNS)
			if tc.wantErr != "" {
				assertIntegrityBoundaryError(t, err, tc.wantErr)
				if got != 0 {
					t.Fatalf("result = %d, want 0 on error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("result = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestScheduleAccuracyPPMBoundaries(t *testing.T) {
	cases := []struct {
		name              string
		planned, achieved int64
		want              int64
	}{
		{
			// The exact 2^64-1 deviation rounds to 2e6 ppm, so the miss is
			// reported as minimum accuracy instead of wrapping to a perfect hit.
			name:     "opposite int64 extremes report zero accuracy",
			planned:  math.MaxInt64,
			achieved: math.MinInt64,
			want:     0,
		},
		{
			name:     "max int64 rate exactly met",
			planned:  math.MaxInt64,
			achieved: math.MaxInt64,
			want:     1_000_000,
		},
		{
			name:     "one milli below max int64 rounds to perfect",
			planned:  math.MaxInt64,
			achieved: math.MaxInt64 - 1,
			want:     1_000_000,
		},
		{
			name:     "deviation of exactly one million ppm is a full miss",
			planned:  math.MaxInt64,
			achieved: 0,
			want:     0,
		},
		{
			name:     "deviation overflow reports zero accuracy",
			planned:  1,
			achieved: math.MaxInt64,
			want:     0,
		},
		{
			name:     "opposite half-range extremes report zero accuracy",
			planned:  1 << 62,
			achieved: -(1 << 62),
			want:     0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ScheduleAccuracyPPM(tc.planned, tc.achieved); got != tc.want {
				t.Fatalf("ScheduleAccuracyPPM(%d,%d) = %d, want %d", tc.planned, tc.achieved, got, tc.want)
			}
		})
	}
}
