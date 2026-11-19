/* ==========================================================================
   app-14-insights.js — part 14 of 15 of the dashboard bundle.

   INSIGHTS — Digital Twin, Host X-Ray, and Bounty triage helpers

   Every file in this directory is concatenated, in name order, into the
   single /app.js the page loads. They share one global scope, so a
   function declared here is visible to later parts — order matters.
   Keep one feature per file: a part that grows past ~900 lines is a
   signal to split it, not to let it grow (see assets_test.go).
   ========================================================================== */

/* app-14-insights.js — Insights view (twin/xray/bounty helpers) */

(function () {
  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/\x22/g, '&quot;');
  }

  function setOut(id, html, cls) {
    var el = document.getElementById(id);
    if (!el) return;
    el.className = 'ins-out' + (cls ? ' ' + cls : '');
    el.innerHTML = html;
  }

  function setText(id, text, cls) {
    var el = document.getElementById(id);
    if (!el) return;
    el.className = 'ins-out' + (cls ? ' ' + cls : '');
    el.textContent = text;
  }

  async function api(path, opts) {
    if (window.S && S.locked) throw new Error('locked');
    var resp = await fetch(path, opts || {});
    var text = await resp.text();
    var data;
    try { data = JSON.parse(text); } catch (_) { data = { ok: false, error: text || ('HTTP ' + resp.status) }; }
    if (!resp.ok && data && !data.error) data.error = 'HTTP ' + resp.status;
    return data;
  }

  function parseJSONFrom(id) {
    var ta = document.getElementById(id);
    if (!ta) throw new Error('missing field #' + id);
    var raw = ta.value.trim();
    if (!raw) throw new Error('empty input');
    return JSON.parse(raw);
  }

  // trustedHTML marks a string that is already safe to insert as markup. Only
  // badge() creates one, and it escapes the text it interpolates. kv() unwraps
  // it so a badge renders as a real <span> instead of showing literal tags.
  function trustedHTML(html) { return { __html: html }; }

  function kv(k, v) {
    var val = (v == null || v === '') ? '—' : v;
    var html = (val && typeof val === 'object' && typeof val.__html === 'string') ? val.__html : esc(val);
    return '<div class="ins-kv-row"><span class="k">' + esc(k) + '</span><span class="v">' + html + '</span></div>';
  }
  function pct(v) { return (v == null || !isFinite(v)) ? '—' : (Number(v).toFixed(2) + '%'); }
  function num(v) {
    if (v == null || !isFinite(v)) return '—';
    var n = Number(v);
    return Math.abs(n) >= 100 ? n.toFixed(1) : n.toFixed(2);
  }
  function fmtInterval(iv) {
    if (!iv || (iv.low == null && iv.high == null)) return '—';
    return num(iv.low) + ' – ' + num(iv.high);
  }
  function badge(text, tone) {
    var cls = tone === 'good' ? 'ok' : (tone === 'bad' ? 'err' : (tone === 'warn' ? 'warn' : ''));
    return trustedHTML('<span class="ins-badge ' + cls + '">' + esc(text) + '</span>');
  }
  function renderList(items, cls) {
    items = items || [];
    if (!items.length) return '';
    return '<ul class="ins-notes' + (cls ? ' ' + cls : '') + '">' + items.map(function (x) { return '<li>' + esc(x) + '</li>'; }).join('') + '</ul>';
  }

  function getConf(m) { return (m && (m.confidence_assessment || m.confidence_v2 || m.ConfidenceV2 || m.confidenceAssessment)) || null; }
  function getCap(m) { return (m && (m.capacity_assessment || m.capacity || m.Capacity || m.capacityAssessment)) || null; }
  function getModelInfo(m) { return (m && (m.model_info || m.ModelInfo || m.modelInfo)) || null; }

  function renderConfidence(m) {
    var c = getConf(m);
    if (!c) {
      return '<div class="ins-kv">' + kv('Confidence (legacy)', (m && m.confidence) || '—') + '</div>' +
        '<p class="ins-note warn">Structured evidence-based confidence assessment unavailable. Confidence must not be treated as high without sufficient evidence.</p>';
    }
    var level = c.level || c.Level || '—';
    var score = (c.score != null ? c.score : c.Score);
    var sufficient = !!(c.sufficient_evidence != null ? c.sufficient_evidence : c.Sufficient);
    var tone = level === 'HIGH' ? (sufficient ? 'good' : 'bad') : (level === 'MEDIUM' ? 'warn' : 'bad');
    var explanation = c.summary || c.Summary || c.explanation || c.Explanation || '';
    var html = '<div class="ins-kv">' +
      kv('Confidence score', (score != null ? num(score) : '—') + '/100') +
      kv('Level', badge(level, tone)) +
      kv('Sufficient evidence', sufficient ? badge('yes', 'good') : badge('no', 'bad')) +
      kv('Data quality', c.data_quality || c.DataQuality || '—') +
      '</div>';
    if (explanation) html += '<p class="ins-note">' + esc(explanation) + '</p>';
    if (level === 'HIGH' && !sufficient) {
      html += '<p class="ins-note err">Integrity: HIGH confidence must not be assigned without sufficient evidence. Treat as unreliable if shown.</p>';
    }
    var factors = c.factors || c.Factors || [];
    if (factors.length) {
      html += '<table class="ins-table"><thead><tr><th>Factor</th><th>Score</th><th>Weight</th><th>Status</th><th>Evidence</th><th>Impact/Uncertainty</th></tr></thead><tbody>' +
        factors.map(function (f) {
          var impact = (f.impact || f.Impact || '');
          var unc = (f.uncertainty || f.Uncertainty || '');
          var detail = impact + (unc ? (impact ? ' | ' : '') + 'Uncertainty: ' + unc : '');
          return '<tr><td>' + esc(f.name || f.Name || '') + '</td><td>' + esc(num(f.score != null ? f.score : f.Score)) + '</td><td>' + esc(num(f.weight != null ? f.weight : f.Weight)) + '</td><td>' + esc(f.status || f.Status || '') + '</td><td>' + esc(f.evidence || f.Evidence || '') + '</td><td>' + esc(detail) + '</td></tr>';
        }).join('') + '</tbody></table>';
    }
    var missing = c.missing_data || c.MissingData || [];
    var uncertainties = c.uncertainties || c.Uncertainties || [];
    if (missing.length) html += '<p class="ins-note warn"><strong>Missing data (explicit):</strong> ' + esc(missing.join('; ')) + '</p>';
    if (uncertainties.length) html += '<p class="ins-note"><strong>Uncertainties (not missing):</strong> ' + esc(uncertainties.join('; ')) + '</p>';
    return html;
  }

  function renderCapacity(m) {
    var cap = getCap(m);
    var curve = (m && (m.curve || m.service_curve || m.ServiceCurve)) || {};
    var workload = (m && (m.workload || m.Workload)) || {};
    var observed = (cap && (cap.observed_rps != null ? cap.observed_rps : cap.ObservedRPS));
    if (observed == null) observed = workload.rps != null ? workload.rps : workload.RPS;
    if (!cap) {
      var low = curve.capacity_low_rps != null ? curve.capacity_low_rps : curve.CapacityLowRPS;
      var high = curve.capacity_high_rps != null ? curve.capacity_high_rps : curve.CapacityHighRPS;
      var est = curve.capacity_rps != null ? curve.capacity_rps : curve.CapacityRPS;
      return '<div class="ins-kv">' +
        kv('Observed RPS (measured)', num(observed)) +
        kv('Modeled capacity RPS (legacy est.)', num(est)) +
        kv('Capacity interval (legacy)', (low != null || high != null) ? (num(low) + ' – ' + num(high)) : '—') +
        kv('Sustainable capacity status', badge('LEGACY', 'warn')) +
        '</div>' + '<p class="ins-note warn">Observed vs sustainable evidence unavailable in legacy schema. Values are model-based estimates, never guarantees and observed load is never a maximum.</p>';
    }
    var status = cap.status || cap.Status || '—';
    var sustainable = (cap.sustainable_rps != null ? cap.sustainable_rps : cap.SustainableRPS);
    var interval = cap.sustainable_interval || cap.SustainableInterval || cap.interval || cap.Interval;
    var observedIsMax = !!(cap.observed_is_max != null ? cap.observed_is_max : cap.ObservedIsMax);
    var tone = status === 'INSUFFICIENT_DATA' ? 'bad' : (status === 'DEGRADED_EVIDENCE' ? 'warn' : 'good');
    var html = '<div class="ins-kv">' +
      kv('Observed RPS (measured evidence)', num(observed)) +
      kv('Sustainable RPS (model estimate)', (status === 'INSUFFICIENT_DATA' || sustainable == null) ? badge('INSUFFICIENT_DATA', 'bad') : num(sustainable)) +
      kv('Sustainable interval', (status === 'INSUFFICIENT_DATA' || !interval) ? '—' : fmtInterval(interval)) +
      kv('Capacity status', badge(status, tone)) +
      kv('Observed treated as max?', observedIsMax ? badge('true (invalid)', 'bad') : badge('false', 'good')) +
      '</div>';
    if (cap.uncertainty || cap.Uncertainty) html += '<p class="ins-note"><strong>Uncertainty:</strong> ' + esc(cap.uncertainty || cap.Uncertainty) + '</p>';
    var signals = cap.degradation_signals || cap.DegradationSignals || [];
    if (signals.length) html += '<p class="ins-note warn"><strong>Degradation/saturation/error signals:</strong> ' + esc(signals.join('; ')) + '</p>';
    var notes = cap.notes || cap.Notes || [];
    if (notes.length) html += renderList(notes);
    html += '<p class="ins-note">Sustainable capacity and intervals are model-based estimates from available evidence, not guarantees. Observed throughput is never treated as maximum capacity.</p>';
    return html;
  }

  function renderModelMeta(m, res) {
    var mi = getModelInfo(m) || {};
    var resSeed = res && (res.simulation_seed != null ? res.simulation_seed : (res.seed != null ? res.seed : (res.SimulationSeed != null ? res.SimulationSeed : (res.scenario && res.scenario.seed))));
    var simulated = res ? (res.simulated != null ? res.simulated : res.Simulated) : null;
    var estType = res ? (res.estimate_type || res.EstimateType || '') : '';
    var html = '<div class="ins-kv">' +
      kv('Model version', mi.version || mi.Version || (m && (m.schema_version || m.SchemaVersion)) || '—') +
      kv('Algorithm', mi.algorithm || mi.Algorithm || '—') +
      kv('Simulation seed', resSeed != null ? String(resSeed) : '—') +
      kv('Output type', res ? ((simulated === false) ? 'unexpected: not marked simulated' : (estType || 'MODEL_ESTIMATE / simulated')) : '—') +
      '</div>';
    var params = mi.parameters || mi.Parameters || {};
    if (params && Object.keys(params).length) html += '<details class="ins-details"><summary>Model parameters</summary><pre>' + esc(JSON.stringify(params, null, 2)) + '</pre></details>';
    var assumptions = mi.assumptions || mi.Assumptions || [];
    if (assumptions.length) html += '<p class="ins-note"><strong>Assumptions:</strong> ' + esc(assumptions.join('; ')) + '</p>';
    var vstatus = mi.backtest_status || mi.BacktestStatus || mi.validation_status || mi.ValidationStatus || '';
    var dstatus = mi.drift_status || mi.DriftStatus || '';
    if (vstatus || dstatus) html += '<p class="ins-note"><strong>Validation status:</strong> ' + esc(vstatus || '—') + (dstatus ? ' | <strong>Drift:</strong> ' + esc(dstatus) : '') + '</p>';
    return html;
  }

  function renderBreach(b, label) {
    if (!b || !b.status) return '';
    var tone = b.status === 'NOT_CONFIGURED' ? 'warn' : ((b.probability || 0) >= 0.5 ? 'bad' : ((b.probability || 0) >= 0.05 ? 'warn' : 'good'));
    var prob = b.status === 'NOT_CONFIGURED' ? 'NOT_CONFIGURED' : pct((b.probability || 0) * 100);
    var ci = b.status === 'NOT_CONFIGURED' ? '—' : (pct((b.confidence_interval && b.confidence_interval.low || 0) * 100) + ' – ' + pct((b.confidence_interval && b.confidence_interval.high || 0) * 100));
    var detail = b.status === 'NOT_CONFIGURED' ? (b.note || 'No threshold configured') : ((b.breaches || 0) + '/' + (b.trials || 0) + ' iterations; threshold ' + num(b.threshold));
    return '<tr><td>' + esc(label) + '</td><td>' + badge(b.status, tone).__html + '</td><td>' + esc(prob) + '</td><td>' + esc(ci) + '</td><td>' + esc(detail) + '</td></tr>';
  }

  function renderBreachSummary(sum) {
    sum = sum || {};
    var rows = '';
    rows += renderBreach(sum.breach_p95, 'p95 latency');
    rows += renderBreach(sum.breach_p99, 'p99 latency');
    rows += renderBreach(sum.breach_error_rate, 'Error rate');
    rows += renderBreach(sum.breach_throughput, 'Throughput (min)');
    var html = '<div class="ins-kv">' +
      kv('Thresholds configured', sum.thresholds_configured ? 'yes' : 'no') +
      kv('Overall breach probability', sum.sla_breach_probability == null ? '—' : pct(sum.sla_breach_probability * 100)) +
      kv('Overall breach CI', fmtInterval(sum.overall_breach_confidence_interval) === '—' ? '—' : (pct((sum.overall_breach_confidence_interval.low || 0) * 100) + ' – ' + pct((sum.overall_breach_confidence_interval.high || 0) * 100))) +
      kv('Risk level', badge(sum.risk_level || '—', sum.risk_level === 'high' ? 'bad' : (sum.risk_level === 'elevated' ? 'warn' : 'good'))) +
      '</div>';
    if (rows) html += '<table class="ins-table"><thead><tr><th>Metric</th><th>Status</th><th>Probability</th><th>CI</th><th>Detail</th></tr></thead><tbody>' + rows + '</tbody></table>';
    if (!sum.thresholds_configured) html += '<p class="ins-note warn">Breach probability is NOT_CONFIGURED when no thresholds are provided; risk is never reported as LOW in that case.</p>';
    return html;
  }

  async function loadXrayCaps() {
    setOut('xrayCapsOut', 'Loading…');
    try {
      var d = await api('/api/insights/xray/capabilities');
      var c = d.capabilities || {};
      var rows = [
        ['X-Ray available', c.available ? 'yes' : 'no'],
        ['Platform', c.platform || '—'],
        ['eBPF kernel tracing', c.ebpf_available ? 'yes' : 'no (opt-in aggregate sampling only)'],
        ['Privileged mode', c.privileged ? 'yes' : 'no'],
        ['CPU sample', c.cpu_sample ? 'yes' : 'no'],
        ['Memory sample', c.mem_sample ? 'yes' : 'no'],
        ['Network sample', c.net_sample ? 'yes' : 'no'],
      ];
      var html = '<table class="ins-table"><tbody>' + rows.map(function (r) {
        return '<tr><th>' + esc(r[0]) + '</th><td>' + esc(String(r[1])) + '</td></tr>';
      }).join('') + '</tbody></table>';
      if (c.notes && c.notes.length) html += renderList(c.notes);
      if (d.note) html += '<p class="ins-note">' + esc(d.note) + '</p>';
      setOut('xrayCapsOut', html, c.available ? 'ok' : 'warn');
    } catch (e) {
      if (e && e.message === 'locked') return;
      setText('xrayCapsOut', 'Failed to load capabilities: ' + e.message, 'err');
    }
  }

  async function doTwinFit() {
    setOut('twinFitOut', 'Fitting…');
    try {
      var report = parseJSONFrom('twinReportJson');
      var tp = parseFloat((document.getElementById('twinTargetP99') || {}).value || '0');
      var payload = { report: report };
      if (isFinite(tp) && tp > 0) payload.target_p99_ms = tp;
      var d = await api('/api/insights/twin/fit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
      if (!d || d.ok === false) throw new Error((d && d.error) || 'fit failed');
      var m = d.model || {};
      var html = '<div class="ins-subtitle">Confidence (evidence-based)</div>' + renderConfidence(m) +
        '<div class="ins-subtitle" style="margin-top:10px">Capacity (observed vs sustainable)</div>' + renderCapacity(m) +
        '<div class="ins-subtitle" style="margin-top:10px">Model metadata</div>' + renderModelMeta(m, null);
      if (d.note) html += '<p class="ins-note">' + esc(d.note) + '</p>';
      html += '<p class="ins-note">Sustainable capacity and intervals are model-based estimates (simulated evidence), not guarantees or measured maxima.</p>';
      html += '<details class="ins-details"><summary>Model JSON</summary><pre>' + esc(JSON.stringify(m, null, 2)) + '</pre></details>';
      setOut('twinFitOut', html, 'ok');
      window.__twinLastModel = m;
      window.__twinLastReport = report;
    } catch (e) {
      if (e && e.message === 'locked') return;
      setText('twinFitOut', 'Error: ' + (e && e.message ? e.message : String(e)), 'err');
    }
  }

  async function doTwinSim() {
    setOut('twinSimOut', 'Simulating…');
    try {
      var model = parseJSONFrom('twinModelJson');
      var scenario = (document.getElementById('twinScenario') || {}).value || 'normal';
      var rps = parseFloat((document.getElementById('twinRps') || {}).value || '0') || 0;
      var iters = parseInt((document.getElementById('twinIters') || {}).value || '200', 10) || 200;
      var p95t = parseFloat((document.getElementById('twinP95Thr') || {}).value || '0') || 0;
      var p99t = parseFloat((document.getElementById('twinP99Thr') || {}).value || '0') || 0;
      var errt = parseFloat((document.getElementById('twinErrThr') || {}).value || '0') || 0;
      var thrt = parseFloat((document.getElementById('twinThrRps') || {}).value || '0') || 0;
      var payload = { model: model, scenario: scenario, iterations: iters, seed: 42 };
      if (rps > 0) payload.target_rps = rps;
      if (p95t > 0) { payload.sla_p95_ms = p95t; payload.p95_ms = p95t; }
      if (p99t > 0) { payload.sla_p99_ms = p99t; payload.p99_ms = p99t; }
      if (errt > 0) payload.max_error_rate_pct = errt;
      if (thrt > 0) payload.min_throughput_rps = thrt;
      var d = await api('/api/insights/twin/simulate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
      if (!d || (d.ok === false && !d.result)) throw new Error((d && d.error) || 'simulation failed');
      var res = d.result || {};
      var sum = res.summary || {};
      window.__twinLastResult = res;
      var achieved = sum.achieved_rps || sum.AchievedRPS || {};
      var errBand = sum.error_rate_pct || sum.ErrorRatePct || {};
      var p99Band = sum.p99_ms || sum.P99MS || {};
      var risk = sum.risk_level || sum.RiskLevel || '—';
      var html = '<div class="ins-subtitle">Scenario result (model-based simulation)</div>' +
        '<div class="ins-kv">' +
        kv('Scenario', (res.scenario && (res.scenario.name || res.scenario.scenario_type || res.scenario.ScenarioType)) || scenario) +
        kv('Risk', badge(risk, risk === 'high' ? 'bad' : (risk === 'elevated' ? 'warn' : 'good'))) +
        kv('p99 (p95 of draws)', num(p99Band.p95 != null ? p99Band.p95 : p99Band.P95) + ' ms') +
        kv('Achieved RPS (p95 of draws)', num(achieved.p95 != null ? achieved.p95 : achieved.P95)) +
        kv('Error rate % (p95 of draws)', pct(errBand.p95 != null ? errBand.p95 : errBand.P95)) +
        kv('Saturation probability', pct(((sum.saturation_probability != null ? sum.saturation_probability : sum.SaturationProbability) || 0) * 100)) +
        '</div>' +
        '<div class="ins-subtitle" style="margin-top:10px">Breach probability & confidence intervals</div>' + renderBreachSummary(sum) +
        '<div class="ins-subtitle" style="margin-top:10px">Model metadata</div>' + renderModelMeta(model, res);
      if (d.breach_gate) html += '<p class="ins-note err">Breach-probability gate tripped by configured threshold.</p>';
      if (d.note) html += '<p class="ins-note">' + esc(d.note) + '</p>';
      html += '<p class="ins-note">All simulated metrics are model-based estimates derived from collected evidence; they are not direct measurements and not guarantees.</p>';
      html += '<details class="ins-details"><summary>Result JSON</summary><pre>' + esc(JSON.stringify(res, null, 2)) + '</pre></details>';
      setOut('twinSimOut', html, risk === 'high' ? 'warn' : 'ok');
    } catch (e) {
      if (e && e.message === 'locked') return;
      setText('twinSimOut', 'Error: ' + (e && e.message ? e.message : String(e)), 'err');
    }
  }

  async function doTwinCompare() {
    setOut('twinCompareOut', 'Comparing prediction vs actual…');
    try {
      var model = null;
      try { model = parseJSONFrom('twinModelJson'); } catch (_) { model = window.__twinLastModel || null; }
      var actual = parseJSONFrom('twinActualJson');
      var scenario = (document.getElementById('twinScenario') || {}).value || 'normal';
      var payload = { actual: actual, scenario: scenario };
      if (window.__twinLastResult) payload.result = window.__twinLastResult;
      else if (model) payload.model = model; else throw new Error('provide model JSON or run a simulation first');
      var d = await api('/api/insights/twin/compare', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
      if (!d || d.ok === false) throw new Error((d && d.error) || 'compare failed');
      var c = d.comparison || {};
      function row(name, unit, pred, act, errPct, mae) {
        var valid = (pred != null && act != null && isFinite(pred) && isFinite(act));
        var val = valid ? (num(act) + unit + ' actual vs ' + num(pred) + unit + ' predicted (error ' + pct(errPct) + (mae != null && isFinite(mae) ? ', MAE ' + num(mae) + unit : '') + ')') : 'INSUFFICIENT_DATA / not comparable';
        return '<tr><td>' + esc(name) + '</td><td>' + esc(val) + '</td></tr>';
      }
      var vStatus = d.derived_validation_status || '—';
      var drift = d.derived_drift_status || '—';
      var vTone = vStatus === 'OK' ? 'good' : ((vStatus === 'INSUFFICIENT_DATA' || vStatus === 'DRIFT' || vStatus === 'OOD') ? 'bad' : 'warn');
      var html = '<div class="ins-kv">' + kv('Derived validation status', badge(vStatus, vTone)) + kv('Derived drift status', badge(drift, drift === 'DETECTED' ? 'bad' : (drift === 'NONE' ? 'good' : 'warn'))) + '</div>';
      html += '<table class="ins-table"><thead><tr><th>Metric</th><th>Prediction vs actual (measured evidence)</th></tr></thead><tbody>' +
        row('RPS', '', c.predicted_rps, c.actual_rps, c.rps_error_pct, null) +
        row('p95 latency', ' ms', c.predicted_p95_ms, c.actual_p95_ms, c.p95_error_pct, c.p95_mae_ms) +
        row('p99 latency', ' ms', c.predicted_p99_ms, c.actual_p99_ms, c.p99_error_pct, c.p99_mae_ms) +
        '</tbody></table>';
      if (d.derived_note) html += '<p class="ins-note"><strong>Derived note:</strong> ' + esc(d.derived_note) + '</p>';
      if (c.notes && c.notes.length) html += renderList(c.notes);
      var leak = d.leakage || d.leakage_guard || null;
      if (leak) {
        var lStatus = leak.status || leak.Status || ((leak.verified || leak.proven) ? 'verified_no_leakage' : 'unverified');
        var lTone = lStatus === 'verified_no_leakage' ? 'good' : (lStatus === 'leakage_detected' ? 'bad' : 'warn');
        html += '<div class="ins-subtitle" style="margin-top:10px">Leakage / provenance (honesty check)</div>' +
          '<div class="ins-kv">' + kv('Leakage status', badge(lStatus, lTone)) + kv('Enforced', (leak.enforced ? 'yes' : 'no')) + kv('Proven/verified', ((leak.proven || leak.verified) ? 'yes' : 'no')) + kv('Method/source', (leak.method || leak.Method || leak.verification_source || leak.VerificationSource || '—')) + '</div>';
        if (leak.reason || leak.Reason) html += '<p class="ins-note">' + esc(leak.reason || leak.Reason) + '</p>';
      }
      if (d.verification) html += '<details class="ins-details"><summary>Manifest/leakage verification</summary><pre>' + esc(JSON.stringify(d.verification, null, 2)) + '</pre></details>';
      if (d.validation_record) html += '<details class="ins-details"><summary>Validation record (provenance)</summary><pre>' + esc(JSON.stringify(d.validation_record, null, 2)) + '</pre></details>';
      if (d.note) html += '<p class="ins-note">' + esc(d.note) + '</p>';
      html += '<details class="ins-details"><summary>Comparison JSON</summary><pre>' + esc(JSON.stringify(c, null, 2)) + '</pre></details>';
      setOut('twinCompareOut', html, vStatus === 'OK' ? 'ok' : 'warn');
    } catch (e) {
      if (e && e.message === 'locked') return;
      setText('twinCompareOut', 'Error: ' + (e && e.message ? e.message : String(e)), 'err');
    }
  }

  async function doTwinSensitivity() {
    setOut('twinSensitivityOut', 'Analyzing sensitivity…');
    try {
      var model = parseJSONFrom('twinModelJson');
      var scenario = (document.getElementById('twinScenario') || {}).value || 'normal';
      var payload = { model: model, scenario: scenario, seed: 42 };
      var d = await api('/api/insights/twin/sensitivity', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
      if (!d || d.ok === false) throw new Error((d && d.error) || 'sensitivity failed');
      var s = d.sensitivity || {};
      var points = s.points || s.Points || [];
      var base = s.baseline || s.Baseline || {};
      var html = '<div class="ins-kv">' +
        kv('Baseline scenario', base.name || base.Name || scenario) +
        kv('Baseline mode', base.mode || base.Mode || '—') +
        kv('Baseline target RPS', num(base.target_rps != null ? base.target_rps : base.TargetRPS)) +
        kv('Baseline target users', num(base.target_users != null ? base.target_users : base.TargetUsers)) +
        kv('Seed', s.seed != null ? String(s.seed) : (s.Seed != null ? String(s.Seed) : '—')) +
        '</div>';
      if (points.length) {
        html += '<table class="ins-table"><thead><tr><th>Parameter</th><th>Value</th><th>Delta</th><th>p99 (p50 draw, ms)</th><th>Breach probability</th><th>Risk</th><th>Note</th></tr></thead><tbody>' +
          points.map(function (it) {
            var breach = (it.breach != null ? it.breach : it.Breach);
            var risk = it.risk || it.Risk || '—';
            return '<tr><td>' + esc(it.parameter || it.Parameter || '') + '</td><td>' + esc(num(it.value != null ? it.value : it.Value)) + '</td><td>' + esc(num(it.delta != null ? it.delta : it.Delta)) + '</td><td>' + esc(num(it.p99_ms != null ? it.p99_ms : (it.p99_ms_p50 != null ? it.p99_ms_p50 : it.P99MS))) + '</td><td>' + esc(breach == null ? '—' : pct(Number(breach) * 100)) + '</td><td>' + badge(risk, risk === 'high' ? 'bad' : (risk === 'elevated' ? 'warn' : 'good')).__html + '</td><td>' + esc(it.note || it.Note || '') + '</td></tr>';
          }).join('') + '</tbody></table>';
      } else {
        html += '<p class="ins-note warn">No sensitivity points returned (insufficient data or simulation failure).</p>';
      }
      var notes = s.notes || s.Notes || [];
      if (notes.length) html += renderList(notes);
      if (d.note) html += '<p class="ins-note">' + esc(d.note) + '</p>';
      html += '<details class="ins-details"><summary>Sensitivity JSON</summary><pre>' + esc(JSON.stringify(s, null, 2)) + '</pre></details>';
      setOut('twinSensitivityOut', html, 'ok');
    } catch (e) {
      if (e && e.message === 'locked') return;
      setText('twinSensitivityOut', 'Error: ' + (e && e.message ? e.message : String(e)), 'err');
    }
  }

  async function doTwinBacktest() {
    setOut('twinBacktestOut', 'Computing backtest metrics…');
    try {
      var payload = parseJSONFrom('twinBacktestJson');
      var d = await api('/api/insights/twin/backtest', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
      if (!d || d.ok === false) throw new Error((d && d.error) || 'backtest failed');
      var b = d.backtest || {};
      var dStatus = d.derived_backtest_status || '—';
      var drift = d.derived_drift_status || b.drift || b.drift_status || b.Drift || '—';
      var ood = !!(b.out_of_domain != null ? b.out_of_domain : b.OutOfDomain);
      var tone = dStatus === 'OK' ? 'good' : ((dStatus === 'INSUFFICIENT_DATA' || dStatus === 'OOD' || dStatus === 'DRIFT') ? 'bad' : 'warn');
      var html = '<div class="ins-kv">' +
        kv('Derived backtest status', badge(dStatus, tone)) + kv('Derived drift status', badge(drift, drift === 'DETECTED' ? 'bad' : (drift === 'NONE' ? 'good' : 'warn'))) +
        kv('Samples', b.samples != null ? b.samples : b.Samples) + kv('MAE', num(b.mae != null ? b.mae : b.MAE)) + kv('RMSE', num(b.rmse != null ? b.rmse : b.RMSE)) + kv('MAPE %', num(b.mape_pct != null ? b.mape_pct : b.MAPE)) +
        kv('Drift detected', drift === 'DETECTED' ? badge('yes', 'bad') : (drift === 'NONE' ? badge('no', 'good') : badge('unknown', 'warn'))) +
        kv('Out-of-domain', ood ? badge('yes', 'warn') : badge('no', 'good')) +
        '</div>';
      if (b.calibration || b.Calibration) html += '<p class="ins-note"><strong>Calibration:</strong> ' + esc(b.calibration || b.Calibration) + '</p>';
      var notes = b.notes || b.Notes || [];
      if (notes.length) html += renderList(notes);
      var vr = d.validation_record || d.ValidationRecord || {};
      var leak = d.leakage || vr.leakage || null;
      if (leak) {
        var lStatus = leak.status || leak.Status || 'unverified';
        var lTone = lStatus === 'verified_no_leakage' ? 'good' : (lStatus === 'leakage_detected' ? 'bad' : 'warn');
        html += '<div class="ins-subtitle" style="margin-top:10px">Leakage/provenance verification</div>' +
          '<div class="ins-kv">' + kv('Leakage status', badge(lStatus, lTone)) + kv('Enforced', leak.enforced ? 'yes' : 'no') + kv('Proven/verified', (leak.proven || leak.verified) ? 'yes' : 'no') + kv('Method/source', (leak.method || leak.verification_source || '—')) + '</div>';
        if (leak.reason) html += '<p class="ins-note">' + esc(leak.reason) + '</p>';
      }
      if (vr.assumptions && vr.assumptions.length) html += '<p class="ins-note"><strong>Assumptions:</strong> ' + esc(vr.assumptions.join('; ')) + '</p>';
      if (d.verification) html += '<details class="ins-details"><summary>Manifest verification</summary><pre>' + esc(JSON.stringify(d.verification, null, 2)) + '</pre></details>';
      if (d.note) html += '<p class="ins-note">' + esc(d.note) + '</p>';
      html += '<details class="ins-details"><summary>Backtest JSON</summary><pre>' + esc(JSON.stringify(d, null, 2)) + '</pre></details>';
      setOut('twinBacktestOut', html, (drift === 'DETECTED' || ood || dStatus === 'INSUFFICIENT_DATA') ? 'warn' : 'ok');
    } catch (e) {
      if (e && e.message === 'locked') return;
      setText('twinBacktestOut', 'Error: ' + (e && e.message ? e.message : String(e)), 'err');
    }
  }

  async function doResourceAssess() {
    setOut('resourceAssessOut', 'Assessing resource evidence…');
    try {
      var payload = {};
      try { payload = parseJSONFrom('resourceAssessJson'); } catch (_) { payload = {}; }
      var d = await api('/api/insights/resources/assess', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
      if (!d || d.ok === false) throw new Error((d && d.error) || 'resource assessment failed');
      var r = d.resource_monitoring || d.ResourceMonitoring || {};
      var detail = r.metrics_detail || r.MetricsDetail || {};
      var values = r.values || r.Values || {};
      var missing = r.missing || r.Missing || [];
      var defs = [
        { key: 'cpu', label: 'CPU utilization', unit: 'percent' },
        { key: 'memory', label: 'Memory utilization', unit: 'percent' },
        { key: 'network', label: 'Network utilization', unit: 'percent' },
        { key: 'connections', label: 'Active connections', unit: 'count' },
        { key: 'server_response_time', label: 'Server response time', unit: 'ms' },
        { key: 'memory_growth', label: 'Memory growth', unit: 'percent' },
        { key: 'cpu_utilization_pct', label: 'CPU utilization', unit: 'percent' },
        { key: 'memory_utilization_pct', label: 'Memory utilization', unit: 'percent' },
        { key: 'network_utilization', label: 'Network utilization', unit: 'percent' },
        { key: 'active_connections', label: 'Active connections', unit: 'count' },
        { key: 'server_response_time_ms', label: 'Server response time', unit: 'ms' },
        { key: 'memory_growth_pct', label: 'Memory growth', unit: 'percentage_points' }
      ];
      var seen = {};
      var rows = [];
      function addRow(key, label, fallbackUnit) {
        if (seen[key]) return;
        var det = detail[key] || null;
        // remap common aliases
        if (!det) {
          var alias = null;
          if (key === 'cpu_utilization_pct') alias = detail['cpu'];
          else if (key === 'memory_utilization_pct') alias = detail['memory'];
          else if (key === 'network_utilization') alias = detail['network'];
          else if (key === 'active_connections') alias = detail['connections'];
          else if (key === 'server_response_time_ms') alias = detail['server_response_time'];
          else if (key === 'memory_growth_pct') alias = detail['memory_growth'];
          if (alias) { det = alias; seen[key] = true; }
        }
        if (!det && values[key] == null && missing.indexOf(key) === -1) return;
        seen[key] = true;
        det = det || {};
        var val = (det.value != null ? det.value : det.Value);
        if (val == null && values[key] != null) val = values[key];
        var status = det.status || det.Status || (val == null ? 'unavailable' : 'available');
        var unit = det.unit || det.Unit || fallbackUnit || '';
        var source = det.source || det.Source || r.source || r.Source || '—';
        var reason = det.reason || det.Reason || (val == null ? 'not collected/provided' : '');
        var notes = det.notes || det.Notes || [];
        var obs = det.observed_window_start || det.ObservedWindowStart || '';
        var obsEnd = det.observed_window_end || det.ObservedWindowEnd || '';
        var obsAt = det.observed_at || det.ObservedAt || '';
        var samp = det.observation_sample_count || det.ObservationSampleCount || 0;
        var meta = 'status=' + status + '; source=' + source + (unit ? '; unit=' + unit : '');
        if (reason) meta += '; reason=' + reason;
        if (obs || obsEnd) meta += '; window=' + (obs || '?') + ' .. ' + (obsEnd || '?');
        else if (obsAt) meta += '; observed_at=' + obsAt;
        if (samp) meta += '; samples=' + samp;
        if (notes.length) meta += '; notes=' + notes.join(' | ');
        var isPct = (unit === 'percent' || unit === 'percentage_points' || unit === '%');
        var valText = (val == null || !isFinite(Number(val))) ? ('— (' + status + ')') : (isPct ? pct(val) : (num(val) + (unit ? ' ' + unit : '')));
        rows.push('<tr><td>' + esc(label) + '</td><td>' + esc(valText) + '</td><td class="st-' + esc(status) + '">' + esc(meta) + '</td></tr>');
      }
      defs.forEach(function (mdef) { addRow(mdef.key, mdef.label, mdef.unit); });
      Object.keys(detail).sort().forEach(function (k) { if (!seen[k]) addRow(k, k, detail[k] && (detail[k].unit || detail[k].Unit) || ''); });
      var html = '<div class="ins-kv">' + kv('Evidence available', (r.available || r.Available) ? 'yes' : 'no') + kv('Source', r.source || r.Source || '—') + kv('Schema', r.schema_version || r.SchemaVersion || '—') + kv('Samples', (r.sample_count != null ? r.sample_count : r.SampleCount)) + '</div>';
      html += '<table class="ins-table"><thead><tr><th>Metric</th><th>Value</th><th>Status / unit / source / reason</th></tr></thead><tbody>' + (rows.length ? rows.join('') : '<tr><td colspan="3">No standardized resource metrics reported.</td></tr>') + '</tbody></table>';
      if (missing.length) html += '<p class="ins-note warn"><strong>Unavailable/insufficient metrics (explicit, never fabricated):</strong> ' + esc(missing.join(', ')) + '</p>';
      var notes = r.notes || r.Notes || [];
      if (notes.length) html += renderList(notes);
      if (d.note) html += '<p class="ins-note">' + esc(d.note) + '</p>';
      html += '<details class="ins-details"><summary>Resource assessment JSON</summary><pre>' + esc(JSON.stringify(r, null, 2)) + '</pre></details>';
      var warn = !!(missing.length || !(r.available || r.Available));
      setOut('resourceAssessOut', html, warn ? 'warn' : 'ok');
    } catch (e) {
      if (e && e.message === 'locked') return;
      setText('resourceAssessOut', 'Error: ' + (e && e.message ? e.message : String(e)), 'err');
    }
  }

  async function doBountyValidate() {
    setOut('bountyValidateOut', 'Validating…');
    try {
      var manifest = parseJSONFrom('bountyManifestJson');
      var d = await api('/api/insights/bounty/validate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ manifest: manifest }) });
      if (!d || d.ok === false) throw new Error((d && d.error) || 'validation failed');
      var checks = d.checks || d.manifest_checks || [];
      var html = '<div class="ins-kv">' + kv('Verdict', d.verdict) + kv('Package ID', d.package_id) + '</div>';
      if (checks && checks.length) html += renderChecks(checks);
      if (d.reasons && d.reasons.length) html += '<ul class="ins-notes err">' + d.reasons.map(function(x){return '<li>'+esc(x)+'</li>';}).join('') + '</ul>';
      if (d.notes && d.notes.length) html += renderList(d.notes);
      var cls = d.verdict === 'failed' ? 'err' : (d.verdict === 'verified' ? 'ok' : 'warn');
      setOut('bountyValidateOut', html, cls);
    } catch (e) {
      if (e && e.message === 'locked') return;
      setText('bountyValidateOut', 'Error: ' + (e && e.message ? e.message : String(e)), 'err');
    }
  }

  async function doBountyStatus() {
    setOut('bountyStatusOut', 'Replaying…');
    try {
      var events = parseJSONFrom('bountyEventsJson');
      if (!Array.isArray(events)) throw new Error('events must be a JSON array');
      var d = await api('/api/insights/bounty/status', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ events: events }) });
      if (!d || d.ok === false) throw new Error((d && d.error) || 'failed');
      var html = '<div class="ins-kv">' + kv('Current state', d.state) + kv('Events', d.events) + '</div>';
      if (d.last) html += '<div class="ins-kv" style="margin-top:8px">' + kv('Last actor', (d.last.actor || '') + ' (' + (d.last.role || '') + ')') + kv('Reason', d.last.reason || '—') + '</div>';
      if (d.note) html += '<p class="ins-note">' + esc(d.note) + '</p>';
      setOut('bountyStatusOut', html, 'ok');
    } catch (e) {
      if (e && e.message === 'locked') return;
      setText('bountyStatusOut', 'Error: ' + (e && e.message ? e.message : String(e)), 'err');
    }
  }

  function renderChecks(checks) {
    checks = checks || [];
    if (!checks.length) return '';
    return '<table class="ins-table"><thead><tr><th>Check</th><th>Status</th><th>Detail</th></tr></thead><tbody>' +
      checks.map(function (c) { return '<tr><td>' + esc(c.name) + '</td><td class="st-' + esc(c.status) + '">' + esc(c.status) + '</td><td>' + esc(c.detail || '') + '</td></tr>'; }).join('') +
      '</tbody></table>';
  }

  async function doBountyVerifyUpload() {
    setOut('bountyValidateOut', 'Uploading and verifying…');
    try {
      var manifestInput = document.getElementById('bountyManifestFile');
      var filesInput = document.getElementById('bountyArtifactFiles');
      var target = (document.getElementById('bountyTarget') || {}).value || '';
      var key = (document.getElementById('bountyKey') || {}).value || '';
      var skipCI = !!((document.getElementById('bountySkipCI') || {}).checked);
      var form = new FormData();
      if (manifestInput && manifestInput.files && manifestInput.files.length) form.append('manifest_file', manifestInput.files[0], manifestInput.files[0].name);
      else { var ta = document.getElementById('bountyManifestJson'); if (ta && ta.value.trim()) form.append('manifest', ta.value.trim()); }
      if (filesInput && filesInput.files) { for (var i = 0; i < filesInput.files.length; i++) form.append('files', filesInput.files[i], filesInput.files[i].name); }
      if (target) form.append('target', target);
      if (key) form.append('public_key', key);
      if (skipCI) form.append('skip_ci_check', '1');
      var resp = await fetch('/api/insights/bounty/verify-upload', { method: 'POST', body: form });
      var text = await resp.text();
      var d; try { d = JSON.parse(text); } catch (_) { d = { ok: false, error: text }; }
      if (!resp.ok && d && !d.error) d.error = 'HTTP ' + resp.status;
      if (!d || d.ok === false) throw new Error((d && d.error) || 'verification failed');
      var report = d.report || {};
      var verdict = d.verdict || report.verdict || 'unknown';
      var checks = report.checks || report.manifest_checks || d.checks || [];
      var html = '<div class="ins-kv">' + kv('Verdict', verdict) + kv('Package ID', report.package_id || d.package_id) + kv('Uploaded files', d.uploaded_artifacts) + '</div>';
      if (checks && checks.length) html += renderChecks(checks);
      if (report.reasons && report.reasons.length) html += '<ul class="ins-notes err">' + report.reasons.map(function(x){return '<li>'+esc(x)+'</li>';}).join('') + '</ul>';
      var notes = [].concat(report.notes || d.notes || []);
      if (notes.length) html += renderList(notes);
      if (report.attest) html += '<details class="ins-details"><summary>Attestation summary</summary><pre>' + esc(JSON.stringify(report.attest, null, 2)) + '</pre></details>';
      html += '<details class="ins-details"><summary>Verification report JSON</summary><pre>' + esc(JSON.stringify(report, null, 2)) + '</pre></details>';
      var cls = verdict === 'failed' ? 'err' : (verdict === 'verified' ? 'ok' : 'warn');
      setOut('bountyValidateOut', html, cls);
    } catch (e) {
      if (e && e.message === 'locked') return;
      setText('bountyValidateOut', 'Error: ' + (e && e.message ? e.message : String(e)), 'err');
    }
  }

  function parseDurationToNs(s) {
    if (s == null) return 0;
    if (typeof s === 'number' && isFinite(s)) return Math.round(s * 1e9);
    s = String(s).trim();
    if (!s) return 0;
    var re = /(\d+(?:\.\d+)?)(ns|us|µs|μs|ms|s|m|h)/g, m, total = 0, found = false;
    while ((m = re.exec(s)) !== null) {
      found = true; var v = parseFloat(m[1]); var u = m[2]; var mul = 1;
      if (u === 'ns') mul = 1; else if (u === 'us' || u === 'µs' || u === 'μs') mul = 1e3; else if (u === 'ms') mul = 1e6; else if (u === 's') mul = 1e9; else if (u === 'm') mul = 60e9; else if (u === 'h') mul = 3600e9;
      total += v * mul;
    }
    if (found) return Math.round(total);
    var n = parseFloat(s);
    if (isFinite(n)) return Math.round(n * 1e9);
    return 0;
  }

  function historyToReport(h) {
    h = h || {};
    var cfg = h.config || {};
    var res = h.result || {};
    var durSec = Number(cfg.duration_seconds || 0);
    var durNs = durSec > 0 ? Math.round(durSec * 1e9) : parseDurationToNs(h.duration);
    if (durNs <= 0) durNs = 1e9;
    var total = Number(res.total_requests || 0);
    var errs = Number(res.total_errors || 0);
    var rps = Number(res.rps || 0);
    if (rps <= 0 && total > 0) rps = total / (durNs / 1e9);
    var errPct = total > 0 ? (errs / total * 100) : 0;
    function msToNs(v) { v = Number(v || 0); return Math.round(v * 1e6); }
    var p50 = msToNs(res.p50_latency); var p95 = msToNs(res.p95_latency); var p99 = msToNs(res.p99_latency);
    var avg = msToNs(res.avg_latency); var min = msToNs(res.min_latency || res.p50_latency); var max = msToNs(res.max_latency);
    if (!(total > 0) || !(p50 > 0) || !(p95 > 0) || !(p99 > 0)) {
      throw new Error('latest run has no usable latency percentile evidence (need positive p50/p95/p99 and completed requests). Use a successful run report for Digital Twin fit.');
    }
    if (!(avg > 0)) avg = p50; if (!(min > 0)) min = p50; if (!(max > 0)) max = p99;
    if (p95 < p50) p95 = p50; if (p99 < p95) p99 = p95; if (max < p99) max = p99;
    var ts = h.timestamp ? String(h.timestamp) : new Date().toISOString();
    return {
      name: h.id || cfg.target_url || 'run', base_url: cfg.target_url || '', load_profile: cfg.profile || 'steady', target_rps: cfg.rate_limit || 0,
      started_at: ts, ended_at: ts, duration: durNs, active_users: cfg.users || 0, total_requests: total, total_errors: errs, error_rate_pct: errPct, rps: rps,
      status_codes: res.status_codes || {}, errors: {}, gate: false,
      overall: { name: 'overall', requests: total, errors: errs, status_codes: res.status_codes || {}, error_types: {}, min: min, avg: avg, max: max, p50: p50, p95: p95, p99: p99 },
      steps: []
    };
  }

  async function doTwinLoadLatest() {
    setOut('twinFitOut', 'Loading latest run…');
    try {
      var d = await api('/api/history');
      var hist = Array.isArray(d) ? d : (d && d.history ? d.history : (S && S.history ? S.history : []));
      if (!hist || !hist.length) throw new Error('no completed runs found in history');
      var latest = hist[hist.length - 1];
      var rep = historyToReport(latest);
      var ta = document.getElementById('twinReportJson');
      if (ta) ta.value = JSON.stringify(rep, null, 2);
      setOut('twinFitOut', 'Latest run loaded into Report JSON. Click <strong>Fit model</strong> to build a capacity model.', 'ok');
    } catch (e) {
      if (e && e.message === 'locked') return;
      setText('twinFitOut', 'Error: ' + (e && e.message ? e.message : String(e)), 'err');
    }
  }

  async function doXrayCorrelate() {
    setOut('xrayCorrelateOut', 'Correlating…');
    try {
      var samples = parseJSONFrom('xraySamplesJson');
      var signals = parseJSONFrom('xraySignalsJson');
      if (!Array.isArray(samples)) throw new Error('samples must be a JSON array');
      if (!Array.isArray(signals)) throw new Error('signals must be a JSON array');
      var win = (document.getElementById('xrayWindow') || {}).value || '';
      var payload = { samples: samples, signals: signals };
      if (String(win).trim()) payload.window = String(win).trim();
      var d = await api('/api/insights/xray/correlate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
      if (!d || d.ok === false) throw new Error((d && d.error) || 'correlation failed');
      var indicators = d.indicators || [];
      var html = '<div class="ins-kv">' + kv('Indicators', indicators.length) + kv('Samples', samples.length) + kv('Signals', signals.length) + '</div>';
      if (indicators.length) {
        html += '<table class="ins-table"><thead><tr><th>Indicator</th><th>Severity</th><th>Confidence</th><th>Summary</th></tr></thead><tbody>' +
          indicators.map(function (it) {
            var summary = it.title || it.summary || it.detail || it.message || '';
            if (it.explanation) summary += (summary ? ' — ' : '') + it.explanation;
            return '<tr><td>' + esc(it.id || it.kind || it.type || '') + '</td><td>' + esc(it.severity || '') + '</td><td>' + esc(it.confidence || '') + '</td><td>' + esc(summary || JSON.stringify(it)) + '</td></tr>';
          }).join('') + '</tbody></table>';
      } else {
        html += '<p class="ins-note">No indicators produced for the provided window/data.</p>';
      }
      if (d.note) html += '<p class="ins-note">' + esc(d.note) + '</p>';
      html += '<details class="ins-details"><summary>Indicators JSON</summary><pre>' + esc(JSON.stringify(indicators, null, 2)) + '</pre></details>';
      setOut('xrayCorrelateOut', html, 'ok');
    } catch (e) {
      if (e && e.message === 'locked') return;
      setText('xrayCorrelateOut', 'Error: ' + (e && e.message ? e.message : String(e)), 'err');
    }
  }

  function bind(id, fn) {
    try {
      var b = document.getElementById(id);
      if (!b || b.dataset.insWired === '1' || typeof fn !== 'function') return;
      b.addEventListener('click', fn);
      b.dataset.insWired = '1';
    } catch (_) { /* ignore */ }
  }

  function wire() {
    bind('btnXrayCaps', loadXrayCaps);
    bind('btnTwinFit', doTwinFit);
    bind('btnTwinLoadLatest', doTwinLoadLatest);
    bind('btnTwinSim', doTwinSim);
    bind('btnTwinCompare', doTwinCompare);
    bind('btnTwinSensitivity', doTwinSensitivity);
    bind('btnTwinBacktest', doTwinBacktest);
    bind('btnResourceAssess', doResourceAssess);
    bind('btnBountyValidate', doBountyValidate);
    bind('btnBountyVerifyUpload', doBountyVerifyUpload);
    bind('btnBountyStatus', doBountyStatus);
    bind('btnXrayCorrelate', doXrayCorrelate);
    bind('btnTwinUseModel', function () {
      if (window.__twinLastModel) {
        var ta = document.getElementById('twinModelJson');
        if (ta) ta.value = JSON.stringify(window.__twinLastModel, null, 2);
        setText('twinSimOut', 'Fitted model copied. Configure scenario/thresholds and click Simulate.', 'ok');
      } else {
        setText('twinFitOut', 'Fit a model first.', 'warn');
      }
    });
    bind('btnTwinLoadActualFromLatest', async function () {
      try {
        var d = await api('/api/history');
        var hist = Array.isArray(d) ? d : (d && d.history ? d.history : (S && S.history ? S.history : []));
        if (!hist || !hist.length) throw new Error('no completed runs found in history');
        var rep = historyToReport(hist[hist.length - 1]);
        var ta = document.getElementById('twinActualJson');
        if (ta) ta.value = JSON.stringify(rep, null, 2);
        setText('twinCompareOut', 'Latest run loaded as actual report evidence.', 'ok');
      } catch (e) { if (!(e && e.message === 'locked')) setText('twinCompareOut', 'Error: ' + e.message, 'err'); }
    });
    wired = true;
  }

  var wired = false;
  var capsLoaded = false;
  function onShow() {
    wire();
    if (!capsLoaded) { capsLoaded = true; try { loadXrayCaps(); } catch (_) { capsLoaded = false; } }
  }

  if (typeof showView === 'function') {
    var _origShowView = showView;
    showView = function (id, opts) {
      var r = _origShowView(id, opts);
      if (id === 'viewInsights') onShow();
      return r;
    };
    window.showView = showView;
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', wire);
  else wire();
})();
