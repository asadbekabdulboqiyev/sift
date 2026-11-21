# Full 100-Point System Guide (Sift 360°)

This guide explains how to prepare, run, and interpret a **Sift 360° audit** so that a target system can legitimately achieve a **100/100** result when the measured evidence supports it. It is written for authorized testing only.

> **Important:** A 100/100 score is not something to "force." It is the outcome of measured security checks, measurable capacity/resilience behavior, and complete, trustworthy evidence under the selected audit mode and test window. No score should be claimed without real measurements.

---

## 1. What "100/100" Means in Sift 360°

A standard Sift 360° report includes component scores and an overall result:

| Component | What it reflects | How to reach 100 |
|---|---|---|
| **Security (100)** | Findings from automated security checks (headers, TLS/SSL where applicable, lightweight/misconfiguration checks) | No security findings, no weak/missing protections detected by the executed checks |
| **Resilience (100)** | Service behavior under measured load (errors/latency/failure thresholds) | No breach of failure thresholds and no adverse reliability/latency signals in measured telemetry |
| **Capacity (100)** | Measured/assessed capacity outcome for the run | Capacity is measurable and shows no adverse measured capacity evidence (no breach/blocked-unmeasurable state) |
| **Evidence Quality (100)** | Completeness and availability of audit evidence | All required stages produce usable evidence (scan not partial, active load measured when required, no unavailable telemetry) |
| **Overall (100)** | Aggregate outcome (e.g. *Low Risk*, 100/100) | All components at 100 with a complete, consistent, sealed report |

**No-fabrication rule:** If something is not measured (for example, active load in Passive mode), Sift reports it explicitly instead of inventing values. That is correct behavior, but it may prevent a full-evidence 100/100 result in modes where capacity is intentionally skipped.

---

## 2. Prerequisites for a Legitimate 100/100 Run

### 2.1 Authorization and scope (mandatory)
- Test **only** systems you own or have explicit written permission to test.
- Define scope clearly: target URL/host, allowed endpoints, time window, and mode.
- Use the correct mode:
  - **Passive:** non-intrusive checks only; active load/capacity is skipped (capacity not measured).
  - **Standard:** requires explicit authorization confirmation; includes active load/breaking-point testing.
  - **Admin (if permitted by deployment):** operator-level mode where enabled; not shown in the standard UI.

### 2.2 A stable, reachable target
- The target must be reachable from the environment running the audit.
- Avoid intermittent failures, cold starts, or environment instability during the test window.
- For meaningful capacity results, ensure the load generator is not blocked by WAF/rate limits/bot protection (unless you are intentionally testing that behavior).

### 2.3 Security baseline (to aim for 0 findings)
- **HTTP security headers:** configure recommended headers (e.g. `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, and appropriate caching controls). On HTTPS, enable **HSTS** with a proper rollout plan.
- **TLS/SSL (HTTPS targets):** use modern TLS versions and ciphers, a valid certificate from a trusted CA, correct hostname/SANs, and no expired/self-signed certificates in production contexts.
- **Application hygiene:** avoid verbose error leakage, insecure defaults, and misconfigurations surfaced by lightweight checks.
- **Consistency:** ensure the same protections apply to the audited endpoints (not just the homepage).

### 2.4 Capacity and resilience baseline (for Standard mode)
- The service should handle the audit’s ramp/telemetry window without breaching thresholds (e.g. excessive error rate or high p99 latency as defined by the audit).
- Right-size resources, optimize slow paths, and remove avoidable bottlenecks.
- A result of "no breach within the test window" is **measured evidence**, not a guarantee under higher or different load.

### 2.5 Evidence completeness
- Security scan must complete without partial coverage.
- In Standard mode, load telemetry must be produced and measurable (not refused/blocked/unavailable).
- Use a consistent, known target and record the run configuration (mode, duration, target).

---

## 3. Step-by-Step: Running a 100-Point-Oriented Audit

### Step 1 — Start the target
Run your service (or the included demo) in a controlled, authorized environment.

Example (included demo site):
```bash
go run ./examples/perfect_demo_site -addr 127.0.0.1:8095
```

### Step 2 — Start Sift dashboard
```bash
Sift dashboard
# or: ./sift dashboard
```
Default local address (per configuration): `http://127.0.0.1:8888`

### Step 3 — Run Sift 360° in Standard mode
- Select **Standard** mode.
- Provide **explicit authorization confirmation**.
- Set the target URL (e.g. `http://127.0.0.1:8095`).
- Choose an appropriate maximum duration (higher allowed values provide more load-test budget within system limits).
- Start the audit and monitor stages:
  1. **Scanning Security**
  2. **Testing Load Limit**
  3. **Calculating Resilience**
  4. **Sealing VPMP Certificate**

### Step 4 — (Optional) Run via API
```bash
curl -sS -X POST http://127.0.0.1:8888/api/audit-360 \
  -H 'Content-Type: application/json' \
  -d '{"target_url":"http://127.0.0.1:8095","mode":"standard","authorized":true,"max_duration_sec":30}'
```
Poll status:
```bash
curl -sS "http://127.0.0.1:8888/api/audit-360/status?job_id=<JOB_ID>"
```

### Step 5 — Review the sealed report
Confirm:
- `state: completed`, all stages completed
- `findings` empty (or only acceptable informational context, if any)
- `scores.overall/security/resilience/capacity/evidence_quality` all **100** (when evidence supports it)
- `load_test_available: true`, `load_test_skipped: false`, `breaking_point_reached: false` (as applicable)
- `vpmp_signature`, `certificate_id`, `raw_evidence_hash` present (attested report)
- Notes reflect measured reality (no fabricated metrics)

---

## 4. Interpreting Results Correctly

- **100/100 = fully supported by this run:** it reflects what was measured and checked in the executed configuration/window.
- **Not a lifetime guarantee:** future code, config, traffic, dependencies, or infrastructure changes can alter results.
- **Passive mode trade-off:** safer/non-intrusive, but capacity is not measured; evidence/capacity scoring may reflect that by design.
- **Blocked/unmeasurable capacity:** if the target refuses load (e.g. 401/403/429/WAF), capacity cannot be claimed as measured; fix access/scope conditions for a proper capacity test.
- **Partial scans:** rerun with better reachability/time/budget to obtain complete evidence.

---

## 5. Common Reasons a Run Is Not 100/100 (and Fixes)

| Symptom | Likely cause | Corrective action |
|---|---|---|
| Security < 100 | Missing/weak headers, TLS issues, or scan findings | Apply recommended headers/TLS fixes; retest |
| Evidence < 100 (Passive) | Active load intentionally skipped | Use authorized Standard mode if capacity evidence is required |
| Evidence < 100 (partial/unavailable) | Scan/load incomplete or telemetry unavailable | Improve reachability, duration, and target stability; rerun |
| Capacity/resilience reduced | Breach, high error rate, or high latency under load | Optimize performance/capacity, tune timeouts/scaling, retest |
| Capacity not measurable | Target refused/blocked load traffic | Allowlist/authorize test traffic in-scope or test a suitable environment |

---

## 6. Operational Best Practices

- **Repeatability:** keep configurations/versioned artifacts so results are comparable over time.
- **Regression awareness:** re-run audits after significant changes and track score/finding trends.
- **Evidence hygiene:** retain sealed reports (JSON/HTML/PDF as available), hashes, and job metadata.
- **Honest reporting:** distinguish measured peaks from sustainable capacity estimates; never present skipped/unavailable checks as passing measurements.
- **Defense in depth:** a clean automated audit complements, but does not replace, deeper manual review, threat modeling, and continuous monitoring.

---

## 7. Quick Checklist (Full 100-Point Readiness)

- [ ] Authorized scope and correct mode selected
- [ ] Target reachable and stable throughout the run
- [ ] Recommended security headers/TLS correctly configured
- [ ] Security scan completes with 0 findings
- [ ] (Standard) Active load runs with measurable telemetry, no breach
- [ ] Evidence complete (no partial/unavailable stages)
- [ ] Report sealed (signature/certificate/hash present)
- [ ] Notes reviewed for transparency and next actions

When every item above is satisfied **and** the measured results support it, a **100/100** Sift 360° outcome is a legitimate, evidence-backed result.
