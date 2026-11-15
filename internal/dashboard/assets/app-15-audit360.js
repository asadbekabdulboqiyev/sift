/* ==========================================================================
   app-15-audit360.js — part 15 of 15 of the dashboard bundle.

   SIFT 360° — 1-click security + capacity audit panel

   Every file in this directory is concatenated, in name order, into the
   single /app.js the page requests, so the numeric prefix is the boot order.
   ========================================================================== */
(function () {
  var form = document.getElementById('audit360Form');
  if (!form) return;

  var targetEl = document.getElementById('a360Target');
  var authEl = document.getElementById('a360Authorized');
  var authWrap = document.getElementById('a360AuthWrap');
  var fillDemoBtn = document.getElementById('a360FillDemo');
  var startBtn = document.getElementById('a360StartBtn');
  var errEl = document.getElementById('a360Error');
  var progressEl = document.getElementById('audit360Progress');
  var resultEl = document.getElementById('audit360Result');
  var pctEl = document.getElementById('a360Pct');
  var stageLabelEl = document.getElementById('a360StageLabel');
  var trackFillEl = document.getElementById('a360TrackFill');
  var runningEl = document.getElementById('a360RunningIndicator');
  var printBtn = document.getElementById('a360PrintBtn');
  var downloadBtn = document.getElementById('a360DownloadBtn');
  var modeBtns = Array.prototype.slice.call(document.querySelectorAll('.a360-mode[data-mode]'));

  var pollTimer = null;
  var es = null;
  var currentJobId = null;
  var currentMode = 'standard';
  var lastReport = null;
  var lastStatus = null;

  function getMode() { return currentMode || 'standard'; }
  function needsAuth() { return getMode() === 'standard'; }
  function setMode(mode) {
    currentMode = mode || 'standard';
    modeBtns.forEach(function (b) {
      var on = b.getAttribute('data-mode') === currentMode;
      b.classList.toggle('active', on);
      b.setAttribute('aria-pressed', on ? 'true' : 'false');
    });
    if (authWrap) authWrap.classList.toggle('hidden', !needsAuth());
    if (!needsAuth() && authEl) authEl.checked = false;
    setError('');
  }

  function setError(msg) { if (errEl) errEl.textContent = msg || ''; }
  function show(el, on) { if (!el) return; el.classList.toggle('hidden', !on); }

  function stageLabel(id) {
    switch (id) {
      case 'scan_security': return 'Scanning Security';
      case 'test_load': return 'Testing Load Limit';
      case 'calculate_resilience': return 'Calculating Resilience';
      case 'seal_certificate': return 'Sealing VPMP Certificate';
      default: return id || 'Working…';
    }
  }

  function resetStages() {
    var nodes = document.querySelectorAll('#a360Stages .a360-stage');
    nodes.forEach(function (n) {
      n.classList.remove('running', 'completed', 'failed');
      var id = n.getAttribute('data-stage');
      var d = document.getElementById('a360Detail-' + id);
      if (d) d.textContent = 'Pending';
    });
  }

  function updateStages(status) {
    if (!status || !status.stages) return;
    var stages = status.stages;
    stages.forEach(function (st) {
      var node = document.querySelector('#a360Stages .a360-stage[data-stage="' + st.id + '"]');
      if (!node) return;
      node.classList.remove('running', 'completed', 'failed');
      if (st.status === 'running') node.classList.add('running');
      else if (st.status === 'completed') node.classList.add('completed');
      else if (st.status === 'failed') node.classList.add('failed');
      var d = document.getElementById('a360Detail-' + st.id);
      if (d) {
        var txt = st.detail || (st.status === 'pending' ? 'Pending' : (st.status === 'running' ? 'In progress…' : st.status));
        if (st.error) txt += ' (' + st.error + ')';
        d.textContent = txt;
      }
    });
    var pct = Math.max(0, Math.min(100, Number(status.progress_pct || 0)));
    if (pctEl) pctEl.textContent = pct + '%';
    if (trackFillEl) trackFillEl.style.width = pct + '%';
    var label = status.current_stage ? stageLabel(status.current_stage) : (status.state === 'completed' ? 'Completed' : (status.state === 'failed' ? 'Failed' : 'Working…'));
    if (stageLabelEl) stageLabelEl.textContent = label;
  }

  function stopTracking() {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    if (es) { try { es.close(); } catch (_) {} es = null; }
  }

  function startPolling(jobId) {
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(function () { fetchStatus(jobId, false); }, 1200);
  }

  function startStream(jobId) {
    if (!window.EventSource) return false;
    try {
      es = new EventSource('/api/audit-360/stream?job_id=' + encodeURIComponent(jobId));
      es.onmessage = function (e) { handleEventPayload(e.data); };
      ['status','stage','completed','failed'].forEach(function (t) {
        es.addEventListener(t, function (e) { handleEventPayload(e.data, t); });
      });
      es.onerror = function () {
        // fallback to polling on stream issues
        try { es.close(); } catch (_) {}
        es = null;
        if (currentJobId) startPolling(currentJobId);
      };
      return true;
    } catch (_) {
      return false;
    }
  }

  function handleEventPayload(raw, typeHint) {
    if (!raw) return;
    var data;
    try { data = JSON.parse(raw); } catch (_) { return; }
    var status = data.status || data;
    if (data.type === 'status' || data.type === 'stage' || data.type === 'completed' || data.type === 'failed' || status.stages) {
      if (status.stages) updateStages(status);
    }
    if ((data.type === 'completed') || (status && status.state === 'completed' && (status.report || data.report))) {
      var report = data.report || status.report;
      stopTracking();
      show(runningEl, false);
      renderResult(report, status);
      setBusy(false);
    } else if ((data.type === 'failed') || (status && status.state === 'failed')) {
      stopTracking();
      show(runningEl, false);
      setError((status && status.error) || data.error || 'Audit failed.');
      setBusy(false);
    }
  }

  function fetchStatus(jobId, terminalOnly) {
    fetch('/api/audit-360/status?job_id=' + encodeURIComponent(jobId), { headers: { 'Accept': 'application/json' } })
      .then(function (r) { return r.json().catch(function(){ return null; }).then(function(j){ return { ok: r.ok, status: r.status, json: j }; }); })
      .then(function (res) {
        if (!res || !res.json) return;
        var st = res.json;
        if (st && st.stages) updateStages(st);
        if (st && st.state === 'completed') {
          stopTracking();
          show(runningEl, false);
          renderResult(st.report, st);
          setBusy(false);
        } else if (st && st.state === 'failed') {
          stopTracking();
          show(runningEl, false);
          setError(st.error || 'Audit failed.');
          setBusy(false);
        }
      })
      .catch(function () {
        // transient polling error; keep trying
      });
  }

  function setBusy(busy) {
    if (startBtn) {
      startBtn.disabled = !!busy;
      startBtn.textContent = busy ? 'Running Sift 360°…' : 'Run Sift 360° Audit';
    }
    if (targetEl) targetEl.disabled = !!busy;
    if (authEl) authEl.disabled = !!busy;
    if (fillDemoBtn) fillDemoBtn.disabled = !!busy;
    modeBtns.forEach(function (b) { b.disabled = !!busy; });
  }

  function sevClass(sev) {
    sev = String(sev || 'info').toLowerCase();
    if (sev === 'critical' || sev === 'high' || sev === 'medium' || sev === 'low' || sev === 'info') return sev;
    return 'info';
  }

  function esc(s) {
    // Written without regex literals: a bare `/"` in this file would derail the
    // naive delimiter scan in assets_test.go (and has done so before).
    return String(s == null ? '' : s)
      .split('&').join('&amp;')
      .split('<').join('&lt;')
      .split('>').join('&gt;')
      .split('"').join('&quot;');
  }

  function renderGauge(score, risk) {
    var s = Number(score);
    if (!isFinite(s)) s = 0;
    s = Math.max(0, Math.min(100, Math.round(s)));
    var fg = document.getElementById('a360GaugeFg');
    var scoreEl = document.getElementById('a360Score');
    var riskEl = document.getElementById('a360Risk');
    var circumference = 2 * Math.PI * 50;
    if (fg) {
      fg.style.strokeDasharray = String(circumference);
      fg.style.strokeDashoffset = String(circumference * (1 - s / 100));
      var color = '#ef4444';
      if (s >= 80) color = '#22c55e';
      else if (s >= 55) color = '#f59e0b';
      fg.style.stroke = color;
    }
    if (scoreEl) scoreEl.textContent = String(s);
    if (riskEl) {
      riskEl.textContent = risk || '—';
      var r = String(risk || '').toLowerCase();
      riskEl.style.color = r.indexOf('low') >= 0 ? '#86efac' : (r.indexOf('moderate') >= 0 ? '#fcd34d' : '#fca5a5');
    }
  }

  function drawQrPreview(reportOrText) {
    var canvas = document.getElementById('a360Qr');
    var hint = document.getElementById('a360QrHint');
    if (!canvas) return;
    var ctx = canvas.getContext('2d');
    if (!ctx) return;

    var payload = '';
    if (reportOrText && typeof reportOrText === 'object') {
      var r = reportOrText;
      // Encode a compact, scannable verification reference (no fabricated fields).
      // Signature is omitted to keep payload within QR capacity; hash/cert/target/ts/score retained.
      var compact = {
        v: 1,
        type: 'sift.audit360',
        cert: String(r.certificate_id || ''),
        hash: String(r.raw_evidence_hash || ''),
        score: (r.resilience_score != null ? Number(r.resilience_score) : null),
        ts: String(r.timestamp || ''),
        target: String(r.target_url || '')
      };
      payload = JSON.stringify(compact);
      // If still too large for the embedded QR generator, drop less-critical fields.
      if (payload.length > 240) {
        delete compact.target;
        payload = JSON.stringify(compact);
      }
      if (payload.length > 240) {
        delete compact.ts;
        payload = JSON.stringify(compact);
      }
      if (payload.length > 240) {
        // Last resort: cert + hash only
        payload = JSON.stringify({ v: 1, type: 'sift.audit360', cert: String(r.certificate_id || ''), hash: String(r.raw_evidence_hash || '') });
      }
    } else {
      payload = String(reportOrText || 'sift360');
    }

    try {
      if (window.SiftQRCode && typeof window.SiftQRCode.drawToCanvas === 'function') {
        var ok = window.SiftQRCode.drawToCanvas(canvas, payload, { ecLevel: 'M', margin: 4, dark: '#111827', light: '#ffffff' });
        if (ok) {
          if (hint) hint.textContent = 'Scannable QR: certificate ID and evidence hash (verification reference).';
          return;
        }
      }
    } catch (e) {
      // fall through to fallback
    }

    // Fallback: clear canvas if QR generation unavailable/overflow
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = '#111827';
    ctx.font = '10px sans-serif';
    ctx.fillText('QR unavailable', 18, 68);
    if (hint) hint.textContent = 'QR preview unavailable for this payload.';
  }

  function renderResult(report, status) {
    if (!report) {
      setError('Audit completed but no report was returned.');
      return;
    }
    lastReport = report;
    lastStatus = status || null;
    if (downloadBtn) downloadBtn.disabled = false;
    setError('');
    show(progressEl, true);
    show(resultEl, true);

    renderGauge(report.resilience_score, report.risk_level);

    var meta = document.getElementById('a360ResultMeta');
    if (meta) {
      var when = report.timestamp || (status && status.finished_at) || '';
      meta.textContent = (report.target_url || 'Target') + ' · ' + when + ' · certificate ' + (report.certificate_id || '—');
    }

    var capMain = document.getElementById('a360CapacityMain');
    var capSub = document.getElementById('a360CapacitySub');
    if (capMain && capSub) {
      if (report.load_test_skipped) {
        capMain.textContent = 'Load/breaking-point test skipped (Passive mode)';
        capSub.textContent = 'Active load testing was not run in Passive mode; only non-intrusive checks were performed.';
      } else if (report.capacity_blocked) {
        var blockedShare = Number(report.blocked_share_pct || 0);
        capMain.textContent = 'Capacity not measurable: target refused load (HTTP ' + Number(report.blocked_status || 0) + ')';
        capSub.textContent = (blockedShare > 0 ? (blockedShare.toFixed(0) + '% of audit requests were rejected. ') : '') +
          'The access gate answered instead of the service, so no breaking point is claimed. Allowlist the load generator or use a staging target and re-run.';
      } else if (report.stress_test_available && report.breaking_point_reached) {
        var bpUsers = Number(report.breaking_point_users || 0);
        capMain.textContent = bpUsers > 0
          ? 'Capacity Limit Reached: System fails at ' + bpUsers.toLocaleString() + ' concurrent users'
          : 'Capacity limit reached during stress test';
        capSub.textContent = 'Measured during linear-ramp stress test (failure threshold: error rate > 5% or p99 latency > 2000ms).';
      } else if (report.stress_test_available) {
        var observed = Number(report.max_observed_rps || 0);
        capMain.textContent = 'No breaking point reached within the audit window';
        capSub.textContent = observed > 0 ? ('Peak observed throughput: ' + observed.toFixed(1) + ' req/s. Higher load may still cause failure.') : 'Stress test ran but no failure threshold was breached in the allotted time.';
      } else {
        capMain.textContent = 'Capacity limit unavailable';
        capSub.textContent = 'Stress/load evidence could not be measured for this target in this run (not fabricated).';
      }
    }

    var notesEl = document.getElementById('a360Notes');
    if (notesEl) {
      var notes = (report.notes || []).slice(0, 6);
      if (report.max_safe_rps && Number(report.max_safe_rps) > 0) {
        notes.unshift('Estimated max safe throughput (measured before breach): ' + Number(report.max_safe_rps).toFixed(1) + ' req/s.');
      }
      notesEl.innerHTML = notes.map(function (n) { return '<li>' + esc(n) + '</li>'; }).join('') || '<li>No additional notes.</li>';
    }

    var certIdEl = document.getElementById('a360CertId');
    var sigShortEl = document.getElementById('a360SigShort');
    if (certIdEl) certIdEl.textContent = 'Certificate: ' + (report.certificate_id || '—');
    if (sigShortEl) {
      var sig = String(report.vpmp_signature || '');
      sigShortEl.textContent = 'Signature: ' + (sig ? (sig.slice(0, 24) + '…' + sig.slice(-12)) : 'unavailable');
      sigShortEl.title = sig || 'No cryptographic signature available';
    }
    drawQrPreview(report);

    var findingsEl = document.getElementById('a360Findings');
    if (findingsEl) {
      var findings = report.findings || [];
      if (!findings.length) {
        findingsEl.innerHTML = '<div class="a360-empty">No significant findings reported by the measured checks in this run.</div>';
      } else {
        findingsEl.innerHTML = findings.map(function (f) {
          var sev = sevClass(f.severity);
          return '<article class="a360-finding">' +
            '<div class="a360-finding-head"><div class="a360-finding-title">' + esc(f.title || 'Finding') + '</div><span class="a360-sev ' + sev + '">' + esc(sev) + '</span></div>' +
            '<p><strong>Business impact:</strong> ' + esc(f.impact_summary || 'Impact not specified.') + '</p>' +
            '<p><strong>How to fix:</strong> ' + esc(f.remediation || 'Review and remediate this issue.') + '</p>' +
            '</article>';
        }).join('');
      }
    }

    try { resultEl.scrollIntoView({ behavior: 'smooth', block: 'start' }); } catch (_) {}
  }

  if (modeBtns.length) {
    modeBtns.forEach(function (b) {
      b.addEventListener('click', function () { setMode(b.getAttribute('data-mode') || 'standard'); });
    });
    setMode('standard');
  }

  if (fillDemoBtn) {
    fillDemoBtn.addEventListener('click', function () {
      if (targetEl) targetEl.value = 'http://127.0.0.1:8090';
      setError('');
    });
  }

  if (downloadBtn) {
    downloadBtn.disabled = true;
    downloadBtn.addEventListener('click', function () {
      if (!lastReport) return;
      var payload = {
        job: (lastStatus && (lastStatus.job_id || lastStatus.jobId)) || currentJobId || null,
        report: lastReport
      };
      var blob = new Blob([JSON.stringify(payload, null, 2) + '\n'], { type: 'application/json' });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      var cert = String(lastReport.certificate_id || 'report').replace(/[^a-zA-Z0-9._-]/g, '_');
      a.href = url;
      a.download = 'sift-audit360-signed-' + cert + '.json';
      document.body.appendChild(a);
      a.click();
      setTimeout(function(){ URL.revokeObjectURL(url); if (a.parentNode) a.parentNode.removeChild(a); }, 0);
    });
  }

  if (printBtn) {
    printBtn.addEventListener('click', function () {
      window.print();
    });
  }

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    setError('');
    stopTracking();
    currentJobId = null;
    lastReport = null;
    lastStatus = null;
    if (downloadBtn) downloadBtn.disabled = true;

    var mode = getMode();
    var target = (targetEl && targetEl.value || '').trim();
    var authorized = !!(authEl && authEl.checked);
    if (mode === 'standard' && !authorized) {
      setError('In Standard mode, confirm explicit authorization before starting the audit.');
      return;
    }
    if (!target) {
      setError('Target URL is required (for example: https://example.com or http://127.0.0.1:8090).');
      return;
    }

    resetStages();
    show(progressEl, true);
    show(resultEl, false);
    show(runningEl, true);
    updateStages({ stages: [
      {id:'scan_security', status:'pending'},
      {id:'test_load', status:'pending'},
      {id:'calculate_resilience', status:'pending'},
      {id:'seal_certificate', status:'pending'}
    ], progress_pct: 0, current_stage: '' });
    setBusy(true);

    fetch('/api/audit-360', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({ target_url: target, authorized: (mode !== 'standard' ? true : authorized), max_duration_sec: 25, mode: mode })
    })
    .then(function (r) {
      return r.json().catch(function(){ return {}; }).then(function (j) {
        if (!r.ok || !j || j.ok === false) {
          var msg = (j && j.error) ? j.error : ('Request failed (' + r.status + ')');
          throw new Error(msg);
        }
        return j;
      });
    })
    .then(function (j) {
      currentJobId = j.job_id;
      if (!currentJobId) throw new Error('Missing job id from server.');
      // Prefer SSE for real-time updates, fallback to polling.
      if (!startStream(currentJobId)) startPolling(currentJobId);
      // Also start polling as safety net (SSE may be blocked in some setups).
      if (!pollTimer) startPolling(currentJobId);
      fetchStatus(currentJobId, false);
    })
    .catch(function (err) {
      show(runningEl, false);
      setBusy(false);
      setError(err && err.message ? err.message : 'Failed to start Sift 360° audit.');
    });
  });
})();
