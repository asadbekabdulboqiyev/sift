package twin

// simulate.go — deterministic Monte Carlo over the fitted service curve.
//
// # The latency model
//
// The fit stores a reference utilisation rhoRef (the utilisation the measured
// run operated at) and the baseline percentile it measured. Above rhoRef the
// twin amplifies latency with the M/M/1 tail ratio
//
//	amp(rho) = (1 - rhoRef) / (1 - rho)      for rho > rhoRef
//	amp(rho) = 1                             for rho <= rhoRef
//
// so amp(rhoRef) = 1 exactly: at the fitted load the prediction reproduces the
// measurement, and from there it grows towards the pole at rho = 1. The ratio
// is algebraically the same as L0/(1-rho) normalised by its value at rhoRef,
// so it stays consistent with the capacity derivation in model.go. Below
// rhoRef the twin has no evidence of degradation and does not invent any.
//
// At or beyond rho = 0.999 the ratio is capped at maxAmplification (20x) so a
// single scenario cannot produce infinite latency or a division by zero. That
// cap is itself a statement: once the model is inside the last 0.1% of
// capacity, the number is a lower bound on the pain.
//
// # The error model
//
// Errors are not predicted from first principles. The twin carries the
// measured error rate forward, scales it with run-to-run noise, and adds a
// linear overload penalty above 90% utilisation (up to +30 percentage points
// at 100%). This is an assumption of monotonic degradation, documented in the
// output, not a queueing result.
//
// # The random stream
//
// All randomness comes from one math/rand/v2 PCG stream seeded from the
// scenario seed. Iterations draw, in a fixed order, a capacity perturbation, a
// latency noise factor and an error noise factor. The same seed therefore
// produces byte-identical results on every platform, which is what makes the
// output auditable and the tests meaningful.

import (
	"fmt"
	"math"
	"math/rand/v2"
	"slices"
	"strings"
)

// Simulation guard rails. They bound worst-case runtime and reject inputs that
// are almost certainly mistakes rather than intent.
const (
	// MaxIterations caps a single simulation. 10k iterations at the default
	// iteration cost is well under a second and gives tail probabilities to
	// roughly 0.01% resolution.
	MaxIterations = 10_000
	// MaxDurationSeconds caps scenario length at 24 hours. The twin is a
	// steady-state model; day-long scenarios add no information.
	MaxDurationSeconds = 24 * 60 * 60
	// MaxRPS and MaxUsers cap open- and closed-loop load. They are far above
	// any load a single Sift fit can meaningfully extrapolate to.
	MaxRPS   = 1_000_000.0
	MaxUsers = 1_000_000.0

	// maxAmplification caps the M/M/1 ratio near the pole.
	maxAmplification = 20.0
	// maxUtilization keeps 1-rho away from zero in every division.
	maxUtilization = 0.999
	// overloadUtilization is where the error penalty starts.
	overloadUtilization = 0.90
	// overloadErrorCeilingPct is the additional error rate at rho = 1.
	overloadErrorCeilingPct = 30.0
	// capacityJitterFraction sets how much of the model's capacity
	// uncertainty is re-drawn per iteration: drawing the full uncertainty
	// would double-count it, half keeps it visible without swamping the trend.
	capacityJitterFraction = 0.5
	// latencyJitterSigma and errorJitterSigma are multiplicative run-to-run
	// noise on the measured baseline. 5% and 15% are deliberately small: the
	// dominant uncertainty is capacity, not per-run latency noise.
	latencyJitterSigma = 0.05
	errorJitterSigma   = 0.15
	// closedLoopMaxSteps and closedLoopDamping control the Little's-law fixed
	// point for closed-loop scenarios.
	closedLoopMaxSteps = 64
	closedLoopDamping  = 0.5
)

// LoopMode selects how the scenario applies load.
type LoopMode string

const (
	// LoopOpen applies a fixed arrival rate: requests arrive regardless of how
	// fast the service answers.
	LoopOpen LoopMode = "open"
	// LoopClosed applies a fixed number of users, each waiting for its own
	// response before issuing the next request.
	LoopClosed LoopMode = "closed"
)

// Risk levels derived from the estimated SLA breach probability.
const (
	// RiskLow means the estimated breach probability is below 5%.
	RiskLow = "low"
	// RiskElevated means it is between 5% and 50%.
	RiskElevated = "elevated"
	// RiskHigh means it is 50% or more.
	RiskHigh = "high"
)

// SLAThresholds configures breach evaluation (P1). Zero/unset means NOT_CONFIGURED.
type SLAThresholds struct {
	P95MS         float64 `json:"p95_ms,omitempty"`
	P99MS         float64 `json:"p99_ms,omitempty"`
	MaxErrorRate  float64 `json:"max_error_rate_pct,omitempty"`
	MinThroughput float64 `json:"min_throughput_rps,omitempty"`
}

// BreachAssessment reports probability with confidence interval and status.
type BreachAssessment struct {
	Status      string   `json:"status"` // OK/NOT_CONFIGURED
	Threshold   float64  `json:"threshold,omitempty"`
	Probability float64  `json:"probability,omitempty"`
	CI          Interval `json:"confidence_interval,omitempty"`
	Breaches    int      `json:"breaches,omitempty"`
	Trials      int      `json:"trials,omitempty"`
	Note        string   `json:"note,omitempty"`
}

// Scenario is one what-if question. Exactly one of TargetRPS (open loop) or
// TargetUsers (closed loop) is used, selected by Mode.
type Scenario struct {
	Name string `json:"name"`
	// Mode is "open" for a fixed arrival rate or "closed" for a fixed user
	// count. The zero value is invalid; callers must be explicit.
	Mode LoopMode `json:"mode"`
	// TargetRPS is the arrival rate for open-loop scenarios.
	TargetRPS float64 `json:"target_rps,omitempty"`
	// TargetUsers is the concurrency for closed-loop scenarios.
	TargetUsers float64 `json:"target_users,omitempty"`
	// DurationSeconds is the scenario length. The twin is steady-state, so
	// this affects reporting and the ramp, not the steady-state prediction.
	DurationSeconds float64 `json:"duration_seconds"`
	// RampSeconds is the time taken to reach the target load. Zero means an
	// immediate step; saturation time is only predicted when it is positive.
	RampSeconds float64 `json:"ramp_seconds"`
	// SLAP99MS is the p99 latency objective in milliseconds. Zero disables the
	// latency breach check (legacy; prefer Thresholds).
	SLAP99MS float64 `json:"sla_p99_ms"`
	// SLAP95MS is the p95 latency objective in milliseconds (P1).
	SLAP95MS float64 `json:"sla_p95_ms,omitempty"`
	// MaxErrorRatePct is the error-rate objective in percent. Zero disables the
	// error breach check.
	MaxErrorRatePct float64 `json:"max_error_rate_pct"`
	// MinThroughputRPS is the minimum throughput objective (P1).
	MinThroughputRPS float64 `json:"min_throughput_rps,omitempty"`
	Iterations       int     `json:"iterations"`
	Seed             int64   `json:"seed"`
	// Optional P2 scenario classification/resource hints.
	ScenarioType string            `json:"scenario_type,omitempty"`
	ResourceHint map[string]string `json:"resource_hints,omitempty"`
}

// Iteration is one Monte Carlo draw. Latency values are the predicted
// distribution for the whole scenario, not a single request.
type Iteration struct {
	Index                 int      `json:"index"`
	AchievedRPS           float64  `json:"achieved_rps"`
	CapacityRPS           float64  `json:"capacity_rps"`
	Utilization           float64  `json:"utilization"`
	P50MS                 float64  `json:"p50_ms"`
	P95MS                 float64  `json:"p95_ms"`
	P99MS                 float64  `json:"p99_ms"`
	ErrorRatePct          float64  `json:"error_rate_pct"`
	P99Breach             bool     `json:"p99_breach"`
	ErrorBreach           bool     `json:"error_breach"`
	SLABreach             bool     `json:"sla_breach"`
	SaturationTimeSeconds *float64 `json:"saturation_time_seconds,omitempty"`
}

// Band summarises a value across iterations: the median (P50), the 95th
// percentile (P95) and the observed extremes. "P95 of p99" is the number to
// read when asking how bad a bad run gets.
type Band struct {
	P50 float64 `json:"p50"`
	P95 float64 `json:"p95"`
	Min float64 `json:"min"`
	Max float64 `json:"max"`
}

// Summary is the aggregate answer for a scenario.
type Summary struct {
	Iterations             int     `json:"iterations"`
	AchievedRPS            Band    `json:"achieved_rps"`
	Utilization            Band    `json:"utilization"`
	P50MS                  Band    `json:"p50_ms"`
	P95MS                  Band    `json:"p95_ms"`
	P99MS                  Band    `json:"p99_ms"`
	ErrorRatePct           Band    `json:"error_rate_pct"`
	P99BreachProbability   float64 `json:"p99_breach_probability"`
	ErrorBreachProbability float64 `json:"error_breach_probability"`
	SLAProbabilityBreach   float64 `json:"sla_breach_probability"`
	// PredictedSaturationSeconds is the median time at which the ramp crosses
	// the latency objective. Nil when no draw crossed it.
	PredictedSaturationSeconds *float64 `json:"predicted_saturation_seconds,omitempty"`
	SaturationProbability      float64  `json:"saturation_probability"`
	RiskLevel                  string   `json:"risk_level"`
	// P1: statistically meaningful per-threshold breach assessments.
	BreachP95            BreachAssessment `json:"breach_p95,omitempty"`
	BreachP99            BreachAssessment `json:"breach_p99,omitempty"`
	BreachErrorRate      BreachAssessment `json:"breach_error_rate,omitempty"`
	BreachThroughput     BreachAssessment `json:"breach_throughput,omitempty"`
	ThresholdsConfigured bool             `json:"thresholds_configured"`
	OverallBreachCI      Interval         `json:"overall_breach_confidence_interval,omitempty"`
}

// Result is the full simulation output: the scenario that was run, the
// aggregate, every draw, and human-readable caveats.
type Result struct {
	SchemaVersion string      `json:"schema_version"`
	Scenario      Scenario    `json:"scenario"`
	Summary       Summary     `json:"summary"`
	Iterations    []Iteration `json:"iterations"`
	Notes         []string    `json:"notes"`
	// Reproducibility/labeling metadata.
	SimulationSeed int64  `json:"simulation_seed,omitempty"`
	Simulated      bool   `json:"simulated"`
	EstimateType   string `json:"estimate_type,omitempty"` // MODEL_ESTIMATE
}

// PresetNames lists the legacy built-in scenarios in display order (kept for
// backward compatibility with existing CLI compare behavior).
func PresetNames() []string {
	return []string{"best", "likely", "worst"}
}

// RequiredScenarioPresetNames lists P2-required scenario types.
func RequiredScenarioPresetNames() []string {
	return []string{"normal", "peak", "burst", "sustained", "high-concurrency", "resource-degradation"}
}

// Preset builds a built-in scenario from a fitted model.
// Supports legacy presets and P2-required scenario types.
func Preset(name string, m Model) (Scenario, error) {
	if err := m.Validate(); err != nil {
		return Scenario{}, fmt.Errorf("twin: model is not usable: %w", err)
	}
	sla := m.Calibration.TargetP99MS
	if sla <= 0 {
		sla = m.Curve.Baseline.P99MS * 1.25
	}
	base := Scenario{
		Name:            name,
		Mode:            LoopOpen,
		DurationSeconds: 60,
		RampSeconds:     10,
		SLAP99MS:        sla,
		SLAP95MS:        m.Curve.Baseline.P95MS * 1.5,
		MaxErrorRatePct: math.Max(m.Workload.ErrorRatePct*2, 1),
		Iterations:      200,
		Seed:            42,
		ScenarioType:    name,
	}
	cap := m.Curve.CapacityRPS
	low := m.Curve.CapacityLowRPS
	high := m.Curve.CapacityHighRPS
	obs := m.Workload.RPS
	switch name {
	case "best":
		base.TargetRPS = math.Max(low*0.5, 0.1)
	case "likely", "normal":
		base.Name = name
		base.TargetRPS = math.Max(cap*0.75, obs*0.9)
		if name == "normal" {
			base.DurationSeconds = 120
			base.RampSeconds = 15
		}
	case "worst":
		base.TargetRPS = high * 1.10
	case "peak":
		base.TargetRPS = math.Max(cap*0.95, obs*1.2)
		base.DurationSeconds = 90
		base.RampSeconds = 20
	case "burst":
		base.TargetRPS = math.Max(high*1.05, obs*1.5)
		base.DurationSeconds = 45
		base.RampSeconds = 2
	case "sustained":
		base.TargetRPS = math.Max(cap*0.85, obs)
		base.DurationSeconds = 300
		base.RampSeconds = 30
	case "high-concurrency":
		base.Mode = LoopClosed
		base.TargetUsers = math.Max(m.Workload.Concurrency*2, 10)
		base.DurationSeconds = 120
		base.RampSeconds = 20
	case "resource-degradation":
		// Model as constrained effective capacity (resource pressure proxy).
		base.TargetRPS = math.Max(cap*0.8, obs)
		base.DurationSeconds = 120
		base.RampSeconds = 20
		base.ResourceHint = map[string]string{
			"cpu": "degraded", "memory": "degraded", "network_latency": "elevated",
			"assumption": "simulated as reduced headroom / higher effective utilization; collect resource metrics for stronger evidence",
		}
	default:
		return Scenario{}, fmt.Errorf("twin: unknown scenario preset %q (supported: %s, %s)", name, strings.Join(PresetNames(), ", "), strings.Join(RequiredScenarioPresetNames(), ", "))
	}
	if base.TargetRPS <= 0 && base.Mode == LoopOpen {
		base.TargetRPS = 0.1
	}
	return base, nil
}

// SensitivityPoint quantifies impact of one parameter change.
type SensitivityPoint struct {
	Parameter string  `json:"parameter"`
	Value     float64 `json:"value"`
	Delta     float64 `json:"delta"`
	P99MS     float64 `json:"p99_ms_p50"`
	Breach    float64 `json:"breach_probability"`
	Risk      string  `json:"risk_level"`
	Note      string  `json:"note,omitempty"`
}

// SensitivityReport quantifies impact of concurrency/complexity/resources/limits.
type SensitivityReport struct {
	Baseline  Scenario           `json:"baseline"`
	Points    []SensitivityPoint `json:"points"`
	Notes     []string           `json:"notes"`
	Simulated bool               `json:"simulated"`
	Seed      int64              `json:"seed"`
}

// AnalyzeSensitivity runs deterministic scenario sweeps to quantify impact.
func AnalyzeSensitivity(m Model, base Scenario, seed int64) (SensitivityReport, error) {
	if err := m.Validate(); err != nil {
		return SensitivityReport{}, err
	}
	if err := base.validate(); err != nil {
		// try preset baseline
		p, perr := Preset("normal", m)
		if perr != nil {
			return SensitivityReport{}, err
		}
		base = p
	}
	base.Seed = seed
	report := SensitivityReport{Baseline: base, Simulated: true, Seed: seed}
	eval := func(label string, sc Scenario, note string) {
		res, err := Simulate(m, sc, seed)
		if err != nil {
			report.Notes = append(report.Notes, fmt.Sprintf("%s: simulation failed: %v", label, err))
			return
		}
		val := sc.TargetRPS
		if sc.Mode == LoopClosed {
			val = sc.TargetUsers
		}
		report.Points = append(report.Points, SensitivityPoint{
			Parameter: label, Value: val, P99MS: res.Summary.P99MS.P50, Breach: res.Summary.SLAProbabilityBreach, Risk: res.Summary.RiskLevel, Note: note,
		})
	}
	// Concurrency/load sensitivity
	if base.Mode == LoopOpen {
		for _, mult := range []float64{0.5, 0.75, 1.0, 1.25, 1.5} {
			sc := base
			sc.Name = fmt.Sprintf("concurrency-x%.2f", mult)
			sc.TargetRPS = base.TargetRPS * mult
			eval("concurrency_rps", sc, "load multiplier on arrival rate")
		}
	} else {
		for _, mult := range []float64{0.5, 1.0, 1.5, 2.0} {
			sc := base
			sc.Name = fmt.Sprintf("users-x%.2f", mult)
			sc.TargetUsers = base.TargetUsers * mult
			eval("concurrency_users", sc, "virtual user multiplier")
		}
	}
	// Request complexity proxy: increase baseline latency pressure via tighter SLA + higher effective load proxy by scenario naming/notes
	for _, mult := range []float64{1.0, 1.25, 1.5} {
		sc := base
		sc.Name = fmt.Sprintf("complexity-x%.2f", mult)
		sc.SLAP99MS = base.SLAP99MS / mult
		if sc.SLAP99MS <= 0 {
			sc.SLAP99MS = base.SLAP99MS
		}
		eval("request_complexity_sla_pressure", sc, "proxy: stricter latency budget representing higher request complexity")
	}
	// CPU/memory/network/connection limits proxies (model-level): run degradation/pressure scenarios
	deg, err := Preset("resource-degradation", m)
	if err == nil {
		deg.SLAP99MS = base.SLAP99MS
		deg.SLAP95MS = base.SLAP95MS
		deg.MaxErrorRatePct = base.MaxErrorRatePct
		eval("resource_degradation", deg, "proxy for CPU/memory/network/connection pressure (collect resource metrics for stronger evidence)")
	}
	hc, err := Preset("high-concurrency", m)
	if err == nil {
		hc.SLAP99MS = base.SLAP99MS
		hc.MaxErrorRatePct = base.MaxErrorRatePct
		eval("connection_high_concurrency", hc, "proxy for connection/concurrency limits")
	}
	report.Notes = append(report.Notes,
		"Sensitivity analysis is model-based and uses proxies where direct resource metrics are unavailable.",
		"CPU, memory, network latency, and connection-limit impacts should be validated with collected resource monitoring when available.",
		"All results are deterministic for the same seed.",
	)
	return report, nil
}

// Simulate runs a seeded Monte Carlo over the fitted model.
func Simulate(m Model, sc Scenario, seed int64) (Result, error) {
	if err := m.Validate(); err != nil {
		return Result{}, fmt.Errorf("twin: model is not usable: %w", err)
	}
	if err := sc.validate(); err != nil {
		return Result{}, err
	}
	sc.Seed = seed

	base := m.Curve.Baseline
	ref := m.Curve.ReferenceUtilization
	capacitySigma := math.Max(minCapacityUncertainty, m.Curve.CapacityRelativeUncertainty*capacityJitterFraction)

	// #nosec G404 G115 -- deterministic Monte Carlo for capacity planning, not a security-sensitive random source.
	rng := rand.New(rand.NewPCG(uint64(seed), 0x9E3779B97F4A7C15))

	iterations := make([]Iteration, 0, sc.Iterations)
	p50s := make([]float64, 0, sc.Iterations)
	p95s := make([]float64, 0, sc.Iterations)
	p99s := make([]float64, 0, sc.Iterations)
	errs := make([]float64, 0, sc.Iterations)
	achieved := make([]float64, 0, sc.Iterations)
	utilizations := make([]float64, 0, sc.Iterations)
	saturationTimes := make([]float64, 0, sc.Iterations)

	var p99Breaches, p95Breaches, errBreaches, thrBreaches, slaBreaches int
	hasP95 := sc.SLAP95MS > 0
	hasP99 := sc.SLAP99MS > 0
	hasErr := sc.MaxErrorRatePct > 0
	hasThr := sc.MinThroughputRPS > 0

	for i := 0; i < sc.Iterations; i++ {
		capacityFactor := 1 + truncNormal(rng, capacitySigma)
		capacity := m.Curve.CapacityRPS * capacityFactor
		latencyNoise := math.Exp(rng.NormFloat64() * latencyJitterSigma)
		errorNoise := math.Exp(rng.NormFloat64() * errorJitterSigma)

		achievedRPS := sc.TargetRPS
		if sc.Mode == LoopClosed {
			achievedRPS = closedLoopRPS(sc.TargetUsers, capacity, base, ref, latencyNoise)
		}
		rho := 0.0
		if capacity > 0 {
			rho = achievedRPS / capacity
		}
		amp := amplification(rho, ref) * latencyNoise

		p50 := base.P50MS * amp
		p95 := base.P95MS * amp
		p99 := base.P99MS * amp

		errorRate := m.Workload.ErrorRatePct * errorNoise
		if rho > overloadUtilization {
			errorRate += overloadErrorCeilingPct * (rho - overloadUtilization) / (1 - overloadUtilization)
		}
		errorRate = clamp(errorRate, 0, 100)

		saturation := saturationTime(sc, capacity, ref, base.P99MS)
		p95Breach := hasP95 && p95 > sc.SLAP95MS
		p99Breach := hasP99 && p99 > sc.SLAP99MS
		errorBreach := hasErr && errorRate > sc.MaxErrorRatePct
		thrBreach := hasThr && achievedRPS < sc.MinThroughputRPS
		slaBreach := (hasP95 && p95Breach) || (hasP99 && p99Breach) || (hasErr && errorBreach) || (hasThr && thrBreach)

		if p95Breach {
			p95Breaches++
		}
		if p99Breach {
			p99Breaches++
		}
		if errorBreach {
			errBreaches++
		}
		if thrBreach {
			thrBreaches++
		}
		if slaBreach {
			slaBreaches++
		}

		iterations = append(iterations, Iteration{
			Index:                 i,
			AchievedRPS:           achievedRPS,
			CapacityRPS:           capacity,
			Utilization:           rho,
			P50MS:                 p50,
			P95MS:                 p95,
			P99MS:                 p99,
			ErrorRatePct:          errorRate,
			P99Breach:             p99Breach,
			ErrorBreach:           errorBreach,
			SLABreach:             slaBreach,
			SaturationTimeSeconds: saturation,
		})
		p50s = append(p50s, p50)
		p95s = append(p95s, p95)
		p99s = append(p99s, p99)
		errs = append(errs, errorRate)
		achieved = append(achieved, achievedRPS)
		utilizations = append(utilizations, rho)
		if saturation != nil {
			saturationTimes = append(saturationTimes, *saturation)
		}
	}

	n := sc.Iterations
	configured := hasP95 || hasP99 || hasErr || hasThr
	overallProb := 0.0
	if n > 0 {
		overallProb = float64(slaBreaches) / float64(n)
	}
	summary := Summary{
		Iterations:             n,
		AchievedRPS:            makeBand(achieved),
		Utilization:            makeBand(utilizations),
		P50MS:                  makeBand(p50s),
		P95MS:                  makeBand(p95s),
		P99MS:                  makeBand(p99s),
		ErrorRatePct:           makeBand(errs),
		P99BreachProbability:   breachProb(p99Breaches, n, hasP99),
		ErrorBreachProbability: breachProb(errBreaches, n, hasErr),
		SLAProbabilityBreach:   breachProb(slaBreaches, n, configured),
		SaturationProbability:  float64(len(saturationTimes)) / float64(maxInt(n, 1)),
		ThresholdsConfigured:   configured,
		BreachP95:              breachAssessment("p95_ms", sc.SLAP95MS, p95Breaches, n, hasP95, "P95 latency must be <= threshold"),
		BreachP99:              breachAssessment("p99_ms", sc.SLAP99MS, p99Breaches, n, hasP99, "P99 latency must be <= threshold"),
		BreachErrorRate:        breachAssessment("error_rate_pct", sc.MaxErrorRatePct, errBreaches, n, hasErr, "Error rate must be <= threshold"),
		BreachThroughput:       breachAssessment("min_throughput_rps", sc.MinThroughputRPS, thrBreaches, n, hasThr, "Achieved throughput must be >= threshold"),
	}
	if configured {
		summary.OverallBreachCI = wilsonInterval(slaBreaches, n, 0.95)
		summary.RiskLevel = riskLevel(overallProb)
	} else {
		summary.RiskLevel = "NOT_CONFIGURED"
	}
	if len(saturationTimes) > 0 {
		sorted := slices.Clone(saturationTimes)
		slices.Sort(sorted)
		median := percentileValue(sorted, 0.5)
		summary.PredictedSaturationSeconds = &median
	}

	return Result{
		SchemaVersion:  SchemaVersion,
		Scenario:       sc,
		Summary:        summary,
		Iterations:     iterations,
		Notes:          simulationNotes(sc, summary),
		SimulationSeed: seed,
		Simulated:      true,
		EstimateType:   "MODEL_ESTIMATE",
	}, nil
}

// validate rejects scenarios that cannot be simulated. Every message names the
// offending field so a CI log is actionable without the source.
func (s Scenario) validate() error {
	if strings.TrimSpace(s.Name) == "" {
		return fmt.Errorf("twin: scenario name is required")
	}
	switch s.Mode {
	case LoopOpen:
		if !finite(s.TargetRPS) || s.TargetRPS <= 0 {
			return fmt.Errorf("twin: scenario %q: target rps must be a positive finite number, got %v", s.Name, s.TargetRPS)
		}
		if s.TargetRPS > MaxRPS {
			return fmt.Errorf("twin: scenario %q: target rps %v exceeds the %v limit", s.Name, s.TargetRPS, MaxRPS)
		}
	case LoopClosed:
		if !finite(s.TargetUsers) || s.TargetUsers <= 0 {
			return fmt.Errorf("twin: scenario %q: target users must be a positive finite number, got %v", s.Name, s.TargetUsers)
		}
		if s.TargetUsers > MaxUsers {
			return fmt.Errorf("twin: scenario %q: target users %v exceeds the %v limit", s.Name, s.TargetUsers, MaxUsers)
		}
	default:
		return fmt.Errorf("twin: scenario %q: unknown loop mode %q (use %q or %q)", s.Name, s.Mode, LoopOpen, LoopClosed)
	}
	if !finite(s.DurationSeconds) || s.DurationSeconds <= 0 {
		return fmt.Errorf("twin: scenario %q: duration must be a positive number of seconds, got %v", s.Name, s.DurationSeconds)
	}
	if s.DurationSeconds > MaxDurationSeconds {
		return fmt.Errorf("twin: scenario %q: duration %.0fs exceeds the %.0fs limit", s.Name, s.DurationSeconds, float64(MaxDurationSeconds))
	}
	if !finite(s.RampSeconds) || s.RampSeconds < 0 || s.RampSeconds > s.DurationSeconds {
		return fmt.Errorf("twin: scenario %q: ramp must be in [0, duration] seconds, got %v", s.Name, s.RampSeconds)
	}
	if !finite(s.SLAP99MS) || s.SLAP99MS < 0 {
		return fmt.Errorf("twin: scenario %q: sla p99 must be a non-negative number of milliseconds, got %v", s.Name, s.SLAP99MS)
	}
	if !finite(s.SLAP95MS) || s.SLAP95MS < 0 {
		return fmt.Errorf("twin: scenario %q: sla p95 must be a non-negative number of milliseconds, got %v", s.Name, s.SLAP95MS)
	}
	if !finite(s.MaxErrorRatePct) || s.MaxErrorRatePct < 0 || s.MaxErrorRatePct > 100 {
		return fmt.Errorf("twin: scenario %q: max error rate must be in [0,100]%%, got %v", s.Name, s.MaxErrorRatePct)
	}
	if !finite(s.MinThroughputRPS) || s.MinThroughputRPS < 0 {
		return fmt.Errorf("twin: scenario %q: min throughput must be non-negative, got %v", s.Name, s.MinThroughputRPS)
	}
	if s.Iterations < 1 || s.Iterations > MaxIterations {
		return fmt.Errorf("twin: scenario %q: iterations must be in [1,%d], got %d", s.Name, MaxIterations, s.Iterations)
	}
	return nil
}

// amplification returns the latency multiplier at utilisation rho, anchored so
// that amp(rhoRef) = 1. See the file comment for the derivation.
func amplification(rho, ref float64) float64 {
	if !finite(rho) || rho <= ref {
		return 1
	}
	if rho >= maxUtilization {
		return maxAmplification
	}
	return math.Min((1-ref)/(1-rho), maxAmplification)
}

// closedLoopRPS solves N users against Little's law: throughput = users /
// mean-latency. Because latency itself depends on throughput, the twin iterates
// with damping until the fixed point settles. A closed loop cannot exceed
// capacity in this model: as throughput approaches capacity, latency diverges
// and the implied throughput collapses, so the iteration converges below it.
func closedLoopRPS(users, capacity float64, base Latency, ref, latencyNoise float64) float64 {
	baseAvg := math.Max(base.AvgMS, base.P50MS) * latencyNoise
	if baseAvg <= 0 || capacity <= 0 {
		return 0
	}
	rps := users * 1000 / baseAvg
	for i := 0; i < closedLoopMaxSteps; i++ {
		avg := baseAvg * amplification(rps/capacity, ref)
		if avg <= 0 || !finite(avg) {
			break
		}
		next := users * 1000 / avg
		next = closedLoopDamping*rps + (1-closedLoopDamping)*next
		if math.Abs(next-rps) <= 1e-9*math.Max(rps, 1) {
			rps = next
			break
		}
		rps = next
	}
	// The fixed point is mathematically below capacity, but rounding can put
	// it a hair above; clamp so utilisation never exceeds the pole.
	return math.Min(rps, capacity*maxUtilization)
}

// saturationTime predicts when a linear ramp crosses the latency objective.
//
// Solving amp(rho) = SLA / baselineP99 for rho gives
//
//	rho* = 1 - (1 - rhoRef) * baselineP99 / SLA
//
// and the ramp reaches rho* after ramp * rps*/target seconds. The result is
// nil when the target load never reaches rps*, when there is no ramp, or when
// there is no latency objective.
func saturationTime(sc Scenario, capacity, ref, baselineP99 float64) *float64 {
	if sc.Mode != LoopOpen || sc.RampSeconds <= 0 || sc.SLAP99MS <= 0 || sc.TargetRPS <= 0 {
		return nil
	}
	rhoStar := 1 - (1-ref)*baselineP99/sc.SLAP99MS
	rhoStar = clamp(rhoStar, ref, maxUtilization)
	rpsStar := rhoStar * capacity
	if sc.TargetRPS <= rpsStar {
		return nil
	}
	t := sc.RampSeconds * rpsStar / sc.TargetRPS
	return &t
}

// truncNormal draws a standard normal and clamps it to +/-3 sigma so one
// unlucky draw cannot produce a negative capacity.
func truncNormal(rng *rand.Rand, sigma float64) float64 {
	z := rng.NormFloat64()
	if z < -3 {
		z = -3
	}
	if z > 3 {
		z = 3
	}
	return z * sigma
}

// makeBand computes the band summary of values. The input is copied before
// sorting so callers retain their slice order.
func makeBand(values []float64) Band {
	if len(values) == 0 {
		return Band{}
	}
	sorted := slices.Clone(values)
	slices.Sort(sorted)
	return Band{
		P50: percentileValue(sorted, 0.5),
		P95: percentileValue(sorted, 0.95),
		Min: sorted[0],
		Max: sorted[len(sorted)-1],
	}
}

// percentileValue is the nearest-rank quantile of an ascending slice: the
// answer is always an observed value, never an interpolation. This mirrors the
// definition Sift uses in its reports.
func percentileValue(sorted []float64, p float64) float64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 1 {
		return sorted[n-1]
	}
	rank := int(math.Ceil(p * float64(n)))
	if rank < 1 {
		rank = 1
	}
	if rank > n {
		rank = n
	}
	return sorted[rank-1]
}

// riskLevel maps a breach probability to a vocabulary that does not overclaim.
func riskLevel(breach float64) string {
	switch {
	case breach < 0.05:
		return RiskLow
	case breach < 0.5:
		return RiskElevated
	default:
		return RiskHigh
	}
}

// simulationNotes returns deterministic, scenario-specific caveats.
func simulationNotes(sc Scenario, s Summary) []string {
	notes := []string{
		"results are model-based estimates, not guarantees: the twin extrapolates from one measured operating point",
		"all simulation outputs are labeled as model estimates and include uncertainty/confidence intervals where computed",
	}
	if !s.ThresholdsConfigured {
		notes = append(notes, "no SLA thresholds configured: breach probability/risk are NOT_CONFIGURED (not computed and never reported as low risk)")
	}
	if s.Utilization.P95 >= 1 {
		notes = append(notes, fmt.Sprintf("the requested load reaches or exceeds the estimated capacity in at least 5%% of draws (p95 utilisation %.2f); latency amplification is capped at %.0fx and the true latency at that load is likely worse", s.Utilization.P95, maxAmplification))
	}
	if sc.Mode == LoopClosed {
		notes = append(notes, "closed-loop scenario: achieved throughput is solved from the user count via Little's law, so adding users past capacity yields no extra throughput")
	}
	if s.SaturationProbability > 0 {
		notes = append(notes, fmt.Sprintf("the ramp crosses the latency objective in %.1f%% of draws; the reported saturation time is the median of those draws", s.SaturationProbability*100))
	}
	return notes
}

func breachProb(breaches, n int, configured bool) float64 {
	if !configured || n <= 0 {
		return 0
	}
	return float64(breaches) / float64(n)
}

func breachAssessment(metric string, threshold float64, breaches, n int, configured bool, rule string) BreachAssessment {
	a := BreachAssessment{Trials: n}
	if !configured {
		a.Status = "NOT_CONFIGURED"
		a.Note = "Threshold not configured; breach probability not computed"
		return a
	}
	a.Status = "OK"
	a.Threshold = threshold
	a.Breaches = breaches
	a.Probability = float64(breaches) / float64(maxInt(n, 1))
	a.CI = wilsonInterval(breaches, n, 0.95)
	a.Note = rule
	_ = metric
	return a
}

func wilsonInterval(successes, n int, level float64) Interval {
	if n <= 0 {
		return Interval{Low: 0, High: 1, Level: level, Method: "wilson-unavailable(n=0)"}
	}
	z := 1.96
	if level <= 0.90 {
		z = 1.645
	} else if level >= 0.99 {
		z = 2.576
	}
	phat := float64(successes) / float64(n)
	denom := 1 + (z*z)/float64(n)
	center := (phat + (z*z)/(2*float64(n))) / denom
	margin := (z / denom) * math.Sqrt((phat*(1-phat))/float64(n)+(z*z)/(4*float64(n*n)))
	low := math.Max(0, center-margin)
	high := math.Min(1, center+margin)
	return Interval{Low: round4(low), High: round4(high), Level: level, Method: "Wilson score interval"}
}

func round4(v float64) float64 { return math.Round(v*10000) / 10000 }
