/* ==========================================================================
   app-15-audit360.js — Sift 360° (1-click full audit)
   ========================================================================== */
(function () {
  var form = document.getElementById('audit360Form');
  if (!form) return;

  var targetEl = document.getElementById('a360Target');
  var authEl = document.getElementById('a360Authorized');
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

  var pollTimer = null;
  var es = null;
  var currentJobId = null;

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
  }

  function sevClass(sev) {
    sev = String(sev || 'info').toLowerCase();
    if (sev === 'critical' || sev === 'high' || sev === 'medium' || sev === 'low' || sev === 'info') return sev;
    return 'info';
  }

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
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

  function drawQrPreview(text) {
    var canvas = document.getElementById('a360Qr');
    if (!canvas) return;
    var ctx = canvas.getContext('2d');
    if (!ctx) return;
    var size = 21; // visual grid
    var cell = Math.floor(canvas.width / size);
    var pad = Math.floor((canvas.width - cell * size) / 2);
    // simple deterministic hash
    var h = 2166136261 >>> 0;
    var str = String(text || 'sift360');
    for (var i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = Math.imul(h, 16777619) >>> 0;
    }
    function bit(x, y) {
      var n = (x * 374761393 + y * 668265263 + h) >>> 0;
      n ^= n >>> 13; n = Math.imul(n, 1274126177) >>> 0; n ^= n >>> 16;
      return (n & 1) === 1;
    }
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = '#111827';
    // finder-like corners for QR preview appearance
    function finder(ox, oy) {
      for (var y = 0; y < 7; y++) for (var x = 0; x < 7; x++) {
        var on = (x===0||x===6||y===0||y===6 || (x>=2&&x<=4&&y>=2&&y<=4));
        if (on) ctx.fillRect(pad + (ox+x)*cell, pad + (oy+y)*cell, cell-1, cell-1);
      }
    }
    finder(0,0); finder(size-7,0); finder(0,size-7);
    for (var y = 0; y < size; y++) {
      for (var x = 0; x < size; x++) {
        var inFinder = (x<8 && y<8) || (x>=size-8 && y<8) || (x<8 && y>=size-8);
        if (inFinder) continue;
        if (bit(x,y)) ctx.fillRect(pad + x*cell, pad + y*cell, cell-1, cell-1);
      }
    }
  }

  function renderResult(report, status) {
    if (!report) {
      setError('Audit completed but no report was returned.');
      return;
    }
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
      if (report.stress_test_available && report.breaking_point_reached && Number(report.breaking_point_users) > 0) {
        capMain.textContent = 'Capacity Limit Reached: System fails at ' + Number(report.breaking_point_users).toLocaleString() + ' concurrent users';
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
    drawQrPreview((report.certificate_id || '') + '|' + (report.vpmp_signature || '') + '|' + (report.target_url || ''));

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

  if (fillDemoBtn) {
    fillDemoBtn.addEventListener('click', function () {
      if (targetEl) targetEl.value = 'http://127.0.0.1:8090';
      setError('');
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

    var target = (targetEl && targetEl.value || '').trim();
    var authorized = !!(authEl && authEl.checked);
    if (!authorized) {
      setError('You must confirm explicit authorization before starting the audit.');
      return;
    }
    if (!target) {
      setError('Target URL is required (use the local VoltStore demo server for this 1-click audit).');
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
      body: JSON.stringify({ target_url: target, authorized: true, max_duration_sec: 25 })
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
