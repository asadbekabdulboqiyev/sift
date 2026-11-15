/* ==========================================================================
   app-05-render.js — part 05 of 15 of the dashboard bundle.

   RENDER — live metrics, status codes, workers, history

   Every file in this directory is concatenated, in name order, into the
   single /app.js the page loads. They share one global scope, so a
   function declared here is visible to later parts — order matters.
   Keep one feature per file: a part that grows past ~900 lines is a
   signal to split it, not to let it grow (see assets_test.go).
   ========================================================================== */

/* ==========================================================================
   RENDER
   ========================================================================== */
function logRenderError(e) {
  try { console.error('[Sift] render error:', e); } catch (_) {}
}
function render() {
  var s = S.snapshot || {};
  var r = S.run || {};
  var running = r.status === 'running';
  var elapsed = r.elapsed || 0;
  var duration = (r.config && r.config.duration_seconds) || (S.run.duration || 30);
  if (typeof elapsed === 'number') elapsed = elapsed / 1e9; // nanoseconds to seconds
  var elapsedNum = parseFloat(elapsed) || 0;
  var progress = r.progress || 0;

  // Status badge
  var badge = document.getElementById('statusBadge');
  if (badge && badge.getAttribute('data-status') !== (r.status || 'idle')) {
    badge.setAttribute('data-status', r.status || 'idle');
    badge.className = 'badge badge-' + (r.status || 'idle');
    badge.textContent = (r.status || 'idle');
  }

  // Buttons
  updateStartButton();
  var btnStop = document.getElementById('btnStop');
  if (btnStop) btnStop.disabled = !running;
  if (!running) disarmStop();
  var cf = document.getElementById('controlsForm');
  if (cf) cf.classList.toggle('is-running', !!running);

  // Progress
  var pf = document.getElementById('progressFill');
  if (pf) {
    pf.style.width = progress + '%';
    pf.className = 'progress-fill' + (running ? ' active' : '');
  }
  var remain = Math.max(0, duration - elapsedNum);
  var ptext = progress.toFixed(0) + '% | ' + formatDuration(elapsedNum) + ' / ' + formatDuration(duration) + ' | ' + formatDuration(remain) + ' left';
  var pt = document.getElementById('progressText');
  if (pt && pt.textContent !== ptext) pt.textContent = ptext;
  var pbar = document.getElementById('progressBar');
  if (pbar) {
    pbar.setAttribute('aria-valuenow', String(Math.round(progress)));
    pbar.setAttribute('aria-valuetext', formatDuration(elapsedNum) + ' of ' + formatDuration(duration));
  }

  // Populate inputs from config when running (guards: skip the field the user
  // is actively editing, including the linked sliders)
  if (r.config) {
    var inpUrl = document.getElementById('inpUrl');
    if (inpUrl && document.activeElement.id !== 'inpUrl') inpUrl.value = r.config.target_url || '';
    var inpUsers = document.getElementById('inpUsers');
    if (inpUsers && document.activeElement.id !== 'inpUsers' && document.activeElement.id !== 'rngUsers') inpUsers.value = r.config.users || 10;
    var inpDuration = document.getElementById('inpDuration');
    if (inpDuration && document.activeElement.id !== 'inpDuration' && document.activeElement.id !== 'rngDuration') inpDuration.value = r.config.duration_seconds || 30;
    var inpMethod = document.getElementById('inpMethod');
    if (inpMethod && document.activeElement.id !== 'inpMethod') inpMethod.value = r.config.method || 'GET';
    var inpRate = document.getElementById('inpRate');
    if (inpRate && document.activeElement.id !== 'inpRate') inpRate.value = r.config.rate_limit || 0;
    var inpProfile = document.getElementById('inpProfile');
    if (inpProfile && document.activeElement.id !== 'inpProfile' && r.config.profile) inpProfile.value = r.config.profile;
    var inpFingerprint = document.getElementById('inpFingerprint');
    if (inpFingerprint && document.activeElement.id !== 'inpFingerprint' && r.config.tls_fingerprint) inpFingerprint.value = r.config.tls_fingerprint;
  }
  updateFieldHints();

  // Config meta + live latency strip
  var metaProfile = document.getElementById('metaProfile');
  if (metaProfile) metaProfile.textContent = (r.config && r.config.profile) || '\u2014';
  var metaRate = document.getElementById('metaRate');
  if (metaRate) metaRate.textContent = (r.config && r.config.rate_limit) ? r.config.rate_limit + ' req/s' : '\u2014';
  var metaFingerprint = document.getElementById('metaFingerprint');
  if (metaFingerprint) metaFingerprint.textContent = (r.config && r.config.tls_fingerprint) || '\u2014';
  var metaP50 = document.getElementById('metaP50');
  if (metaP50) metaP50.textContent = (s.p50_latency_ms || 0).toFixed(1) + ' ms';
  var metaP95 = document.getElementById('metaP95');
  if (metaP95) metaP95.textContent = (s.p95_latency_ms || 0).toFixed(1) + ' ms';
  var metaP99 = document.getElementById('metaP99');
  if (metaP99) metaP99.textContent = (s.p99_latency_ms || 0).toFixed(1) + ' ms';
  var metaAvg = document.getElementById('metaAvg');
  if (metaAvg) metaAvg.textContent = (s.avg_latency_ms || 0).toFixed(1) + ' ms';
  var metaMax = document.getElementById('metaMax');
  if (metaMax) metaMax.textContent = (s.max_latency_ms || 0).toFixed(1) + ' ms';

  // Metric cards
  var rps = s.rps || 0;
  var valRPS = document.getElementById('valRPS');
  if (valRPS) valRPS.textContent = Math.round(rps);
  var subRPS = document.getElementById('subRPS');
  if (subRPS) subRPS.textContent = fmt(s.total_requests || 0) + ' total requests';

  var avg = s.avg_latency_ms || 0;
  var valAvg = document.getElementById('valAvg');
  if (valAvg) valAvg.textContent = avg.toFixed(1) + ' ms';
  var subLatency = document.getElementById('subLatency');
  if (subLatency) subLatency.textContent =
    'P50: ' + (s.p50_latency_ms || 0).toFixed(1) + ' \u00b7 P95: ' + (s.p95_latency_ms || 0).toFixed(1) + ' \u00b7 P99: ' + (s.p99_latency_ms || 0).toFixed(1) + ' ms';

  var errRate = s.error_rate || 0;
  var errEl = document.getElementById('valErrors');
  if (errEl) {
    errEl.style.color = errRate > 5 ? 'var(--red)' : errRate > 1 ? 'var(--yellow)' : 'var(--green)';
    errEl.textContent = errRate.toFixed(2) + ' %';
  }
  var subErrors = document.getElementById('subErrors');
  if (subErrors) subErrors.textContent = fmt(s.total_errors || 0) + ' errors / ' + fmt(s.total_requests || 0) + ' total';

  var valUsers = document.getElementById('valUsers');
  if (valUsers) valUsers.textContent = s.active_users || 0;

  // Latency detail cards
  var latP50 = document.getElementById('latP50');
  if (latP50) latP50.textContent = (s.p50_latency_ms || 0).toFixed(1);
  var latP95 = document.getElementById('latP95');
  if (latP95) latP95.textContent = (s.p95_latency_ms || 0).toFixed(1);
  var latP99 = document.getElementById('latP99');
  if (latP99) latP99.textContent = (s.p99_latency_ms || 0).toFixed(1);

  // Status codes
  renderStatusCodes(s.status_codes || {});

  // Workers
  renderWorkers(s.workers || []);

  // Charts
  drawSparkline('sparkRPS', S.rpsHist, 'rgba(0,232,123,0.6)');
  drawSparkline('sparkLatency', S.latAvgHist, 'rgba(59,130,246,0.6)');
  drawSparkline('sparkErrors', S.errHist, errRate > 5 ? 'rgba(239,68,68,0.6)' : 'rgba(0,232,123,0.6)');
  drawSparkline('sparkUsers', S.userHist, 'rgba(245,158,11,0.6)');
  drawTimelineChart('chartRPS', [
    { data: S.rpsHist, color: '#00e87b', label: 'RPS' }
  ]);
  drawTimelineChart('chartLatency', [
    { data: S.latP50Hist, color: '#00e87b', label: 'P50' },
    { data: S.latP95Hist, color: '#f59e0b', label: 'P95' },
    { data: S.latP99Hist, color: '#ef4444', label: 'P99' }
  ]);
  drawMiniLine('chartP50', S.latP50Hist, '#00e87b');
  drawMiniLine('chartP95', S.latP95Hist, '#f59e0b');
  drawMiniLine('chartP99', S.latP99Hist, '#ef4444');

  syncOnboarding();
}

/* ==========================================================================
   STATUS CODES (DOM-built — CSP-safe, no style="" attributes)
   ========================================================================== */
function emptyNote(text) {
  var d = document.createElement('div');
  d.className = 'empty-note';
  d.textContent = text;
  return d;
}
function renderStatusCodes(codes) {
  var el = document.getElementById('statusBars');
  if (!el) return;
  var keys = Object.keys(codes).sort();
  el.textContent = '';
  if (keys.length === 0) {
    el.appendChild(emptyNote('No data yet'));
    return;
  }
  var total = 0, k;
  for (var i = 0; i < keys.length; i++) { total += codes[keys[i]]; }
  keys.forEach(function(kStr) {
    var kn = parseInt(kStr, 10);
    var v = codes[kStr];
    var pct = total > 0 ? (v / total * 100) : 0;
    var cls = kn < 300 ? 'c2xx' : kn < 400 ? 'c3xx' : kn < 500 ? 'c4xx' : 'c5xx';
    var row = document.createElement('div'); row.className = 'status-row';
    var code = document.createElement('span');
    code.className = 'status-code ' + cls;
    code.textContent = kStr;
    var bg = document.createElement('div'); bg.className = 'status-bar-bg';
    var bar = document.createElement('div');
    bar.className = 'status-bar ' + cls;
    bar.style.width = pct + '%';
    bg.appendChild(bar);
    var cnt = document.createElement('span');
    cnt.className = 'status-count';
    cnt.textContent = fmt(v) + ' (' + pct.toFixed(1) + '%)';
    row.appendChild(code); row.appendChild(bg); row.appendChild(cnt);
    el.appendChild(row);
  });
}

/* ==========================================================================
   WORKERS (DOM-built, textContent-escaped)
   ========================================================================== */
function renderWorkers(workers) {
  var section = document.getElementById('workersSection');
  if (!section) return;
  if (!workers || workers.length === 0) {
    section.classList.add('hidden');
    return;
  }
  section.classList.remove('hidden');
  var body = document.getElementById('workersBody');
  if (!body) return;
  body.textContent = '';
  workers.forEach(function(w) {
    var isActive = w.status === 'running' || w.status === 'active';
    var tr = document.createElement('tr');
    var tdId = document.createElement('td');
    var strong = document.createElement('strong');
    strong.textContent = w.id;
    tdId.appendChild(strong);
    var tdAddr = document.createElement('td');
    tdAddr.className = 't-dim';
    tdAddr.textContent = w.address;
    var tdStatus = document.createElement('td');
    var span = document.createElement('span'); span.className = 'worker-status';
    var dot = document.createElement('span');
    dot.className = 'worker-dot ' + (isActive ? 'active' : 'idle');
    var st = document.createTextNode(String(w.status));
    span.appendChild(dot); span.appendChild(st);
    tdStatus.appendChild(span);
    var tdRps = document.createElement('td'); tdRps.textContent = (w.rps || 0).toFixed(0);
    var tdLat = document.createElement('td'); tdLat.textContent = (w.latency_ms || 0).toFixed(1) + ' ms';
    var tdErr = document.createElement('td'); tdErr.textContent = fmt(w.errors || 0);
    tr.appendChild(tdId); tr.appendChild(tdAddr); tr.appendChild(tdStatus);
    tr.appendChild(tdRps); tr.appendChild(tdLat); tr.appendChild(tdErr);
    body.appendChild(tr);
  });
}

/* ==========================================================================
   REPORT (latest run, rendered inline)
   ========================================================================== */
function renderHistory() {
  var section = document.getElementById('historySection');
  if (!section) return;
  var body = document.getElementById('historyBody');
  if (!body) return;

  var hist = S.history || [];
  if (!hist.length) {
    S.reportIndex = -1;
    section.classList.remove('hidden');
    body.innerHTML = '<div class="empty-note">No run report yet — start a run from Overview.</div>';
    return;
  }

  section.classList.remove('hidden');

  var idx = (typeof S.reportIndex === 'number') ? S.reportIndex : -1;
  if (idx < 0 || idx >= hist.length) idx = hist.length - 1;
  S.reportIndex = idx;
  var h = hist[idx] || {};

  var hasConfig = h && h.config && typeof h.config === 'object';
  var hasResult = h && h.result && typeof h.result === 'object';
  var cfg = hasConfig ? h.config : {};
  var res = hasResult ? h.result : {};
  var codes = (hasResult && res.status_codes && typeof res.status_codes === 'object') ? res.status_codes : {};
  var codeKeys = Object.keys(codes).sort(function(a,b){ return Number(a)-Number(b); });
  var codesText = codeKeys.length ? codeKeys.map(function(k){ return k + ': ' + codes[k]; }).join(', ') : (hasResult ? '—' : 'unavailable');

  function esc(v){ return String(v == null ? '' : v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\x22/g,'&quot;'); }
  function isNum(v){ return typeof v === 'number' && isFinite(v); }
  function fmtNum(v, digits){ return isNum(v) ? Number(v).toFixed(digits == null ? 2 : digits) : 'unavailable'; }
  function fmtCountVal(v){ return isNum(v) ? fmt(v) : 'unavailable'; }
  function row(k,v, unavailable){ var val = unavailable ? 'unavailable' : ((v == null || v === '') ? '—' : v); return '<div class="ins-kv-row"><span class="k">'+esc(k)+'</span><span class="v">'+esc(val)+'</span></div>'; }

  var when = h.timestamp || '';
  try { when = h.timestamp ? new Date(h.timestamp).toLocaleString() : '—'; } catch(e) { when = String(h.timestamp || '—'); }

  var durationText = h.duration || (isNum(cfg.duration_seconds) ? (cfg.duration_seconds + 's') : '');
  var rateText = isNum(cfg.rate_limit) && cfg.rate_limit > 0 ? (cfg.rate_limit + ' req/s') : (hasConfig ? '—' : 'unavailable');

  var html = '';
  html += '<div class="ins-actions" style="margin:0 0 10px;flex-wrap:wrap;align-items:center;gap:8px">';
  if (hist.length > 1) {
    html += '<label class="ins-label" for="reportSelect" style="margin:0">Run history</label>';
    html += '<select id="reportSelect" class="ins-select" style="min-width:260px;max-width:100%">';
    for (var i = hist.length - 1; i >= 0; i--) {
      var it = hist[i] || {};
      var itWhen = '';
      try { itWhen = it.timestamp ? new Date(it.timestamp).toLocaleString() : ''; } catch (e2) { itWhen = String(it.timestamp || ''); }
      var label = (it.id || ('run-' + (i + 1))) + (itWhen ? (' — ' + itWhen) : '');
      html += '<option value="' + i + '"' + (i === idx ? ' selected' : '') + '>' + esc(label) + '</option>';
    }
    html += '</select>';
  } else {
    html += '<span class="ins-note" style="margin:0">Showing latest completed run report.</span>';
  }
  html += '<button type="button" class="btn btn-ghost btn-sm" id="btnReportCopyJson">Copy JSON</button>';
  html += '<button type="button" class="btn btn-ghost btn-sm" id="btnReportDownloadJson">Download JSON</button>';
  html += '<button type="button" class="btn btn-ghost btn-sm" id="btnReportPrint">Print</button>';
  html += '</div>';

  html += '<div class="ins-kv">';
  html += row('Run ID', h.id);
  html += row('Time', when);
  html += row('Duration', durationText, !h.duration && !isNum(cfg.duration_seconds));
  html += row('Target', cfg.target_url, !hasConfig);
  html += row('Method', cfg.method || (hasConfig ? 'GET' : ''), !hasConfig);
  html += row('Users', cfg.users, !hasConfig);
  html += row('Profile', cfg.profile, !hasConfig);
  html += row('TLS fingerprint', cfg.tls_fingerprint, !hasConfig);
  html += row('Rate limit', rateText, !hasConfig);
  html += '</div>';

  if (!hasResult) {
    html += '<div class="empty-note" style="margin-top:10px">Run result data is unavailable for this report entry.</div>';
  } else {
    html += '<div class="ins-kv" style="margin-top:10px">';
    html += row('Total requests', fmtCountVal(res.total_requests));
    html += row('Total errors', fmtCountVal(res.total_errors));
    html += row('RPS', fmtNum(res.rps, 2));
    html += row('Avg latency', fmtNum(res.avg_latency, 2) !== 'unavailable' ? (fmtNum(res.avg_latency, 2) + ' ms') : 'unavailable');
    html += row('P50 latency', fmtNum(res.p50_latency, 2) !== 'unavailable' ? (fmtNum(res.p50_latency, 2) + ' ms') : 'unavailable');
    html += row('P95 latency', fmtNum(res.p95_latency, 2) !== 'unavailable' ? (fmtNum(res.p95_latency, 2) + ' ms') : 'unavailable');
    html += row('P99 latency', fmtNum(res.p99_latency, 2) !== 'unavailable' ? (fmtNum(res.p99_latency, 2) + ' ms') : 'unavailable');
    html += row('Max latency', fmtNum(res.max_latency, 2) !== 'unavailable' ? (fmtNum(res.max_latency, 2) + ' ms') : 'unavailable');
    html += row('Status codes', codesText);
    html += '</div>';
  }

  // Attestation consistency (latest known attestation state vs selected run)
  var att = S.attestation || null;
  html += '<div class="ins-kv" style="margin-top:10px">';
  if (!att || !att.exists) {
    html += row('Attestation', 'unavailable (no attestation evidence for the latest run state)');
  } else {
    var attRun = att.runID || '';
    if (attRun && h.id && attRun === h.id) {
      html += row('Attestation', 'available and matches this run (' + esc(attRun) + ')');
      html += row('Attestation fingerprint', att.fingerprint || att.pubKeyHex || '—');
      html += row('Attestation percentiles', att.coCorrected ? 'coordinated-omission corrected' : 'raw (uncorrected)');
    } else if (attRun) {
      html += row('Attestation', 'latest attestation is for a different run (' + esc(attRun) + '), not this report');
    } else {
      html += row('Attestation', 'available, but run association is unavailable');
    }
  }
  html += '</div>';

  if (!hasResult) {
    html += '<div class="ins-note" style="margin-top:8px">Evidence note: result metrics are unavailable for this entry; values are not fabricated.</div>';
  }
  html += '<details class="ins-details" open><summary>Full report JSON</summary><pre>' + esc(JSON.stringify(h, null, 2)) + '</pre></details>';

  body.innerHTML = html;

  var sel = document.getElementById('reportSelect');
  if (sel) {
    sel.addEventListener('change', function() {
      var v = parseInt(sel.value, 10);
      S.reportIndex = isNaN(v) ? (hist.length - 1) : v;
      renderHistory();
    });
  }

  var copyBtn = document.getElementById('btnReportCopyJson');
  if (copyBtn) {
    copyBtn.addEventListener('click', function() {
      var text = JSON.stringify(h, null, 2);
      function done(msg, type){ if (typeof toast === 'function') toast(msg, type); }
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(function(){ done('Report JSON copied', 'success'); }, function(){
          var ok = fallbackCopyText(text);
          done(ok ? 'Report JSON copied' : 'Copy failed', ok ? 'success' : 'error');
        });
      } else {
        var ok = fallbackCopyText(text);
        done(ok ? 'Report JSON copied' : 'Copy failed', ok ? 'success' : 'error');
      }
    });
  }

  var dlBtn = document.getElementById('btnReportDownloadJson');
  if (dlBtn) {
    dlBtn.addEventListener('click', function() {
      try {
        var blob = new Blob([JSON.stringify(h, null, 2)], { type: 'application/json' });
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        var safeId = String(h.id || ('run-' + (idx + 1))).replace(/[^a-zA-Z0-9._-]+/g, '-');
        a.href = url;
        a.download = 'sift-report-' + safeId + '.json';
        document.body.appendChild(a);
        a.click();
        setTimeout(function(){ URL.revokeObjectURL(url); if (a.parentNode) a.parentNode.removeChild(a); }, 0);
        if (typeof toast === 'function') toast('Report JSON downloaded', 'success');
      } catch (e) {
        if (typeof toast === 'function') toast('Download failed', 'error');
      }
    });
  }

  var printBtn = document.getElementById('btnReportPrint');
  if (printBtn) {
    printBtn.addEventListener('click', function() {
      try {
        var w = window.open('', '_blank');
        if (!w) { if (typeof toast === 'function') toast('Popup blocked — allow popups to print', 'error'); return; }
        var docTitle = 'Sift Report - ' + (h.id || 'run');
        var pre = esc(JSON.stringify(h, null, 2));
        w.document.open();
        w.document.write('<!doctype html><html><head><meta charset="utf-8"><title>' + esc(docTitle) + '</title>' +
          '<style>body{font:14px/1.5 -apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;margin:24px;color:#111}h1{font-size:20px;margin:0 0 12px}pre{white-space:pre-wrap;word-break:break-word;background:#f6f8fa;border:1px solid #d0d7de;border-radius:8px;padding:12px}</style></head><body>' +
          '<h1>' + esc(docTitle) + '</h1><pre>' + pre + '</pre></body></html>');
        w.document.close();
        w.focus();
        setTimeout(function(){ try { w.print(); } catch (e2) {} }, 150);
      } catch (e) {
        if (typeof toast === 'function') toast('Print failed', 'error');
      }
    });
  }
}

function fallbackCopyText(text) {
  try {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    var ok = document.execCommand('copy');
    if (ta.parentNode) ta.parentNode.removeChild(ta);
    return !!ok;
  } catch (e) { return false; }
}
