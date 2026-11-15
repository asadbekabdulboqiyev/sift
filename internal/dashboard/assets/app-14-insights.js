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

  function kv(k, v) { return '<div class="ins-kv-row"><span class="k">' + esc(k) + '</span><span class="v">' + esc(v == null || v === '' ? '—' : v) + '</span></div>'; }
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
    return '<span class="ins-badge ' + cls + '">' + esc(text) + '</span>';
  }
  function renderList(items, cls) {
    items = items || [];
    if (!items.length) return '';
    return '<ul class="ins-notes' + (cls ? ' ' + cls : '') + '">' + items.map(function (x) { return '<li>' + esc(x) + '</li>'; }).join('') + '</ul>';
  }

  function getConf(m) { return (m && (m.confidence_v2 || m.ConfidenceV2)) || null; }
  function getCap(m) { return (m && (m.capacity || m.Capacity)) || null; }
  function getModelInfo(m) { return (m && (m.model_info || m.ModelInfo)) || null; }

  function renderConfidence(m) {
    var c = getConf(m);
    if (!c) {
      return '<div class="ins-kv">' + kv('Confidence', (m && m.confidence) || '—') + '</div>' + '<p class="ins-note warn">Structured confidence explanation unavailable (legacy/insufficient schema).</p>';
    }
    var level = c.level || c.Level || '—';
    var tone = level === 'HIGH' ? 'good' : (level === 'MEDIUM' ? 'warn' : 'bad');
    var html = '<div class="ins-kv">' +
      kv('Confidence score', (c.score != null ? num(c.score) : '—') + '/100') +
      kv('Level', badge(level, tone)) +
      kv('Sufficient evidence', c.sufficient_evidence ? 'yes' : 'no') +
      kv('Data quality', c.data_quality || '—') +
      '</div>';
    if (c.explanation) html += '<p class="ins-note">' + esc(c.explanation) + '</p>';
    if (c.no_high_confidence_without_sufficient_evidence && level === 'HIGH' && !c.sufficient_evidence) {
      html += '<p class="ins-note err">Integrity warning: HIGH confidence reported without sufficient evidence (should not occur).</p>';
    }
    var factors = c.factors || [];
    if (factors.length) {
      html += '<table class="ins-table"><thead><tr><th>Factor</th><th>Score</th><th>Weight</th><th>Impact</th><th>Evidence</th></tr></thead><tbody>' +
        factors.map(function (f) {
          return '<tr><td>' + esc(f.name) + '</td><td>' + esc(num(f.score)) + '</td><td>' + esc(num(f.weight)) + '</td><td>' + esc(f.impact || '') + '</td><td>' + esc(f.evidence || '') + '</td></tr>';
        }).join('') + '</tbody></table>';
    }
    if (c.missing_data && c.missing_data.length) html += '<p class="ins-note warn"><strong>Missing data:</strong> ' + esc(c.missing_data.join('; ')) + '</p>';
    if (c.uncertainties && c.uncertainties.length) html += '<p class="ins-note"><strong>Uncertainties:</strong> ' + esc(c.uncertainties.join('; ')) + '</p>';
    return html;
  }

  function renderCapacity(m) {
    var cap = getCap(m);
    var curve = (m && m.curve) || {};
    if (!cap) {
      var legacyCi = curve.capacity_ci || {};
      return '<div class="ins-kv">' +
        kv('Observed RPS (measured ref)', num((m && m.reference && m.reference.achieved_rps) || 0)) +
        kv('Sustainable capacity RPS (est.)', num(curve.capacity_rps)) +
        kv('Capacity interval', fmtInterval(legacyCi)) +
        kv('Status', 'LEGACY') +
        '</div>' + '<p class="ins-note warn">Observed vs sustainable breakdown unavailable (legacy). Sustainable values are model-based estimates, not guarantees.</p>';
    }
    var status = cap.status || '—';
    var tone = status === 'INSUFFICIENT_DATA' ? 'bad' : (status === 'ESTIMATED' ? 'warn' : 'good');
    var html = '<div class="ins-kv">' +
      kv('Observed RPS (measured)', num(cap.observed_rps)) +
      kv('Sustainable RPS (est.)', status === 'INSUFFICIENT_DATA' ? 'INSUFFICIENT_DATA' : num(cap.sustainable_rps)) +
      kv('Capacity interval', status === 'INSUFFICIENT_DATA' ? '—' : fmtInterval(cap.interval)) +
      kv('Capacity status', badge(status, tone)) +
      kv('Observed is max?', cap.observed_is_max ? 'true (invalid)' : 'false') +
      '</div>';
    if (cap.degradation_signals && cap.degradation_signals.length) html += '<p class="ins-note"><strong>Degradation/saturation signals:</strong> ' + esc(cap.degradation_signals.join('; ')) + '</p>';
    if (cap.notes && cap.notes.length) html += renderList(cap.notes);
    return html;
  }

  function renderModelMeta(m, res) {
    var mi = getModelInfo(m) || (res && res.model_info) || {};
    var seed = (res && res.seed != null) ? res.seed : mi.seed;
    var html = '<div class="ins-kv">' +
      kv('Model version', mi.version || (m && m.schema_version) || '—') +
      kv('Simulation seed', seed != null ? String(seed) : '—') +
      kv('Simulated ≠ measured', (mi.simulated_not_measured === false) ? 'false (unexpected)' : 'true') +
      '</div>';
    var params = mi.parameters || {};
    if (Object.keys(params).length) html += '<details class="ins-details"><summary>Model parameters</summary><pre>' + esc(JSON.stringify(params, null, 2)) + '</pre></details>';
    if (mi.assumptions && mi.assumptions.length) html += '<p class="ins-note"><strong>Assumptions:</strong> ' + esc(mi.assumptions.join('; ')) + '</p>';
    if (mi.validation_status) html += '<p class="ins-note"><strong>Validation status:</strong> ' + esc(mi.validation_status) + '</p>';
    return html;
  }

  function renderBreach(b, label) {
    if (!b || !b.status) return '';
    var tone = b.status === 'NOT_CONFIGURED' ? 'warn' : ((b.probability || 0) >= 0.5 ? 'bad' : ((b.probability || 0) >= 0.05 ? 'warn' : 'good'));
    var prob = b.status === 'NOT_CONFIGURED' ? 'NOT_CONFIGURED' : pct((b.probability || 0) * 100);
    var ci = b.status === 'NOT_CONFIGURED' ? '—' : (pct((b.confidence_interval && b.confidence_interval.low || 0) * 100) + ' – ' + pct((b.confidence_interval && b.confidence_interval.high || 0) * 100));
    var detail = b.status === 'NOT_CONFIGURED' ? (b.note || 'No threshold configured') : ((b.breaches || 0) + '/' + (b.trials || 0) + ' iterations; threshold ' + num(b.threshold));
    return '<tr><td>' + esc(label) + '</td><td>' + badge(b.status, tone) + '</td><td>' + esc(prob) + '</td><td>' + esc(ci) + '</td><td>' + esc(detail) + '</td></tr>';
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
      if (p95t > 0) payload.p95_ms = p95t;
      if (p99t > 0) payload.p99_ms = p99t;
      if (errt > 0) payload.max_error_rate_pct = errt;
      if (thrt > 0) payload.min_throughput_rps = thrt;
      var d = await api('/api/insights/twin/simulate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
      if (!d || d.ok === false && !d.result) throw new Error((d && d.error) || 'simulation failed');
      var res = d.result || {};
      var sum = res.summary || {};
      window.__twinLastResult = res;
      var html = '<div class="ins-subtitle">Scenario result (model-based simulation)</div>' +
        '<div class="ins-kv">' +
        kv('Scenario', (res.scenario && (res.scenario.name || res.scenario.scenario_type)) || scenario) +
        kv('Risk', badge(sum.risk_level || '—', sum.risk_level === 'high' ? 'bad' : (sum.risk_level === 'elevated' ? 'warn' : 'good'))) +
        kv('p95(p99) ms', num(sum.p99_ms && sum.p99_ms.p95)) +
        kv('p95(RPS)', num(sum.achieved_rps && sum.achieved_rps.p95)) +
        kv('p95(err %)', pct(sum.error_rate_pct && sum.error_rate_pct.p95)) +
        kv('Saturation prob', pct((sum.saturation_probability || 0) * 100)) +
        '</div>' +
        '<div class="ins-subtitle" style="margin-top:10px">Breach probability & confidence intervals</div>' + renderBreachSummary(sum) +
        '<div class="ins-subtitle" style="margin-top:10px">Model metadata</div>' + renderModelMeta(model, res);
      if (d.breach_gate) html += '<p class="ins-note err">Breach-probability gate tripped by configured threshold.</p>';
      if (d.note) html += '<p class="ins-note">' + esc(d.note) + '</p>';
      html += '<p class="ins-note">All simulated metrics are model-based estimates derived from collected evidence; not direct measurements.</p>';
      html += '<details class="ins-details"><summary>Result JSON</summary><pre>' + esc(JSON.stringify(res, null, 2)) + '</pre></details>';
      setOut('twinSimOut', html, sum.risk_level === 'high' ? 'warn' : 'ok');
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
      var m = c.metrics || {};
      function mrow(name, obj) {
        obj = obj || {};
        var val = (obj.valid === false) ? ('INVALID: ' + (obj.reason || 'n/a')) : (num(obj.actual) + ' actual vs ' + num(obj.predicted) + ' pred (err ' + pct(obj.error_pct) + ')');
        return '<tr><td>' + esc(name) + '</td><td>' + esc(val) + '</td></tr>';
      }
      var html = '<div class="ins-kv">' + kv('Derived validation status', badge(d.derived_validation_status || '—', d.derived_validation_status === 'OK' ? 'good' : (d.derived_validation_status === 'INSUFFICIENT_DATA' ? 'bad' : 'warn'))) + kv('Derived drift status', d.derived_drift_status || '—') + '</div>';
      html += '<table class="ins-table"><tbody>' + mrow('RPS', m.rps) + mrow('p95 (ms)', m.p95_ms) + mrow('p99 (ms)', m.p99_ms) + mrow('Error %', m.error_rate_pct) + '</tbody></table>';
      if (d.derived_note) html += '<p class="ins-note">' + esc(d.derived_note) + '</p>';
      if (c.notes && c.notes.length) html += renderList(c.notes);
      if (d.note) html += '<p class="ins-note">' + esc(d.note) + '</p>';
      html += '<details class="ins-details"><summary>Comparison JSON</summary><pre>' + esc(JSON.stringify(c, null, 2)) + '</pre></details>';
      setOut('twinCompareOut', html, d.derived_validation_status === 'OK' ? 'ok' : 'warn');
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
      var impacts = s.impacts || [];
      var html = '<div class="ins-kv">' + kv('Base RPS', num(s.base_rps)) + kv('Base p95', num(s.base_p95_ms)) + kv('Base p99', num(s.base_p99_ms)) + kv('Base err %', pct(s.base_err_pct)) + '</div>';
      if (impacts.length) {
        html += '<table class="ins-table"><thead><tr><th>Parameter</th><th>Delta</th><th>ΔRPS</th><th>Δp95</th><th>Δp99</th><th>Δerr%</th><th>Notes</th></tr></thead><tbody>' +
          impacts.map(function (it) { return '<tr><td>' + esc(it.parameter) + '</td><td>' + esc(it.delta) + '</td><td>' + esc(num(it.delta_rps)) + '</td><td>' + esc(num(it.delta_p95_ms)) + '</td><td>' + esc(num(it.delta_p99_ms)) + '</td><td>' + esc(num(it.delta_error_pct)) + '</td><td>' + esc((it.notes || []).join('; ')) + '</td></tr>'; }).join('') +
          '</tbody></table>';
      }
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
      var dStatus = d.derived_backtest_status || (b.samples ? '—' : 'INSUFFICIENT_DATA');
      var html = '<div class="ins-kv">' +
        kv('Derived backtest status', badge(dStatus, dStatus === 'OK' ? 'good' : (dStatus === 'INSUFFICIENT_DATA' ? 'bad' : 'warn'))) + kv('Derived drift status', d.derived_drift_status || b.drift || '—') +
        kv('Samples', b.samples) + kv('MAE', num(b.mae)) + kv('RMSE', num(b.rmse)) + kv('MAPE %', num(b.mape_pct)) + kv('Mean error %', num(b.mean_error_pct)) +
        kv('Drift detected', b.drift_detected ? badge('yes', 'warn') : 'no') + kv('OOD detected', b.ood_detected ? badge('yes', 'warn') : 'no') +
        '</div>';
      if (b.reasons && b.reasons.length) html += renderList(b.reasons);
      var vr = d.validation_record || {};
      if (vr.assumptions && vr.assumptions.length) html += '<p class="ins-note"><strong>Assumptions/no-leakage:</strong> ' + esc(vr.assumptions.join('; ')) + '</p>';
      if (d.note) html += '<p class="ins-note">' + esc(d.note) + '</p>';
      html += '<details class="ins-details"><summary>Backtest JSON</summary><pre>' + esc(JSON.stringify(d, null, 2)) + '</pre></details>';
      setOut('twinBacktestOut', html, (b.drift_detected || b.ood_detected) ? 'warn' : 'ok');
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
      var r = d.resource_monitoring || {};
      var av = r.available || {};
      var un = r.unavailable || [];
      var values = (r && r.values) ? r.values : {};
      var detail = r.metrics_detail || {};
      var defs = [
        { key: 'cpu', label: 'CPU utilization', legacy: av.cpu_utilization_pct, pct: true },
        { key: 'memory', label: 'Memory utilization', legacy: av.memory_utilization_pct, pct: true },
        { key: 'network', label: 'Network utilization', legacy: av.network_utilization_pct, pct: true },
        { key: 'connections', label: 'Active connections', legacy: av.active_connections, pct: false },
        { key: 'server_response_time', label: 'Server response time (ms)', legacy: av.server_response_time_ms, pct: false },
        { key: 'memory_growth', label: 'Memory growth', legacy: (r.memory_growth_pct != null ? r.memory_growth_pct : null), pct: true }
      ];
      var rows = defs.map(function (m) {
        var d = detail[m.key] || {};
        var val = d.value != null ? d.value : (m.legacy != null ? m.legacy : values[m.key]);
        var status = d.status || (val == null ? 'unavailable' : 'available');
        var unit = d.unit || (m.pct ? 'percent' : (m.key === 'server_response_time' ? 'ms' : 'count'));
        var labelVal = val == null ? status : ((m.pct || unit === 'percent' || unit === 'percentage_points') ? pct(val) : num(val));
        var reason = d.reason || (val == null ? 'not collected/provided' : 'provided/derived evidence');
        var src = d.source ? (' [' + d.source + ']') : '';
        var statusCell = esc(status + src + (reason ? ' — ' + reason : ''));
        return '<tr><td>' + esc(m.label) + (unit && val != null ? ' <span class="ins-note">(' + esc(unit) + ')</span>' : '') + '</td><td>' + esc(labelVal) + '</td><td>' + statusCell + '</td></tr>';
      }).join('');
      var html = '<table class="ins-table"><thead><tr><th>Metric</th><th>Value</th><th>Status / evidence</th></tr></thead><tbody>' + rows + '</tbody></table>';
      if (un.length) html += '<p class="ins-note warn"><strong>Unavailable/insufficient metrics (explicit):</strong> ' + esc(un.join(', ')) + '</p>';
      if (r.notes && r.notes.length) html += renderList(r.notes);
      if (d.note) html += '<p class="ins-note">' + esc(d.note) + '</p>';
      html += '<details class="ins-details"><summary>Resource assessment JSON</summary><pre>' + esc(JSON.stringify(r, null, 2)) + '</pre></details>';
      setOut('resourceAssessOut', html, un.length ? 'warn' : 'ok');
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
      var html = '<div class="ins-kv">' + kv('Verdict', d.verdict) + kv('Package ID', d.package_id) + '</div>';
      if (d.manifest_checks && d.manifest_checks.length) html += renderChecks(d.manifest_checks);
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
      var html = '<div class="ins-kv">' + kv('Verdict', verdict) + kv('Package ID', report.package_id || d.package_id) + kv('Uploaded files', d.uploaded_artifacts) + '</div>';
      if (report.manifest_checks && report.manifest_checks.length) html += renderChecks(report.manifest_checks);
      if (report.reasons && report.reasons.length) html += '<ul class="ins-notes err">' + report.reasons.map(function(x){return '<li>'+esc(x)+'</li>';}).join('') + '</ul>';
      var notes = [].concat(report.reasons || [], report.notes || []);
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

  function wire() {
    if (wired) return;
    wired = true;
    var b;
    b = document.getElementById('btnXrayCaps'); if (b) b.addEventListener('click', loadXrayCaps);
    b = document.getElementById('btnTwinFit'); if (b) b.addEventListener('click', doTwinFit);
    b = document.getElementById('btnTwinLoadLatest'); if (b) b.addEventListener('click', doTwinLoadLatest);
    b = document.getElementById('btnTwinSim'); if (b) b.addEventListener('click', doTwinSim);
    b = document.getElementById('btnTwinCompare'); if (b) b.addEventListener('click', doTwinCompare);
    b = document.getElementById('btnTwinSensitivity'); if (b) b.addEventListener('click', doTwinSensitivity);
    b = document.getElementById('btnTwinBacktest'); if (b) b.addEventListener('click', doTwinBacktest);
    b = document.getElementById('btnResourceAssess'); if (b) b.addEventListener('click', doResourceAssess);
    b = document.getElementById('btnBountyValidate'); if (b) b.addEventListener('click', doBountyValidate);
    b = document.getElementById('btnBountyVerifyUpload'); if (b) b.addEventListener('click', doBountyVerifyUpload);
    b = document.getElementById('btnBountyStatus'); if (b) b.addEventListener('click', doBountyStatus);
    b = document.getElementById('btnXrayCorrelate'); if (b) b.addEventListener('click', doXrayCorrelate);
    b = document.getElementById('btnTwinUseModel'); if (b) b.addEventListener('click', function () {
      if (window.__twinLastModel) {
        var ta = document.getElementById('twinModelJson');
        if (ta) ta.value = JSON.stringify(window.__twinLastModel, null, 2);
        setText('twinSimOut', 'Fitted model copied. Configure scenario/thresholds and click Simulate.', 'ok');
      } else {
        setText('twinFitOut', 'Fit a model first.', 'warn');
      }
    });
    b = document.getElementById('btnTwinLoadActualFromLatest'); if (b) b.addEventListener('click', async function () {
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
  }

  var wired = false;
  var capsLoaded = false;
  function onShow() {
    if (!wired) wire();
    if (!capsLoaded) { capsLoaded = true; loadXrayCaps(); }
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
