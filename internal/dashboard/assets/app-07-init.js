/* ==========================================================================
   app-07-init.js — part 07 of 15 of the dashboard bundle.

   POLLING FALLBACK, keyboard shortcuts, init

   Every file in this directory is concatenated, in name order, into the
   single /app.js the page loads. They share one global scope, so a
   function declared here is visible to later parts — order matters.
   Keep one feature per file: a part that grows past ~900 lines is a
   signal to split it, not to let it grow (see assets_test.go).
   ========================================================================== */

/* ==========================================================================
   POLLING FALLBACK (for when the WebSocket is down)
   ========================================================================== */
setInterval(function() {
  if (S.locked) return;
  if (!S.connected && S.run && S.run.status === 'running') {
    fetch(API + '/api/snapshot').then(function(r) {
      if (guardStatus(r)) return null;
      return r.json();
    }).then(function(d) {
      if (!d || S.locked) return;
      S.snapshot = d;
      pushHist('rpsHist', d.rps || 0);
      pushHist('latAvgHist', d.avg_latency_ms || 0);
      pushHist('latP50Hist', d.p50_latency_ms || 0);
      pushHist('latP95Hist', d.p95_latency_ms || 0);
      pushHist('latP99Hist', d.p99_latency_ms || 0);
      pushHist('errHist', d.error_rate || 0);
      pushHist('userHist', d.active_users || 0);
      try { render(); } catch (e) { logRenderError(e); }
    }).catch(function() {});
  }
}, 1000);

/* ==========================================================================
   KEYBOARD SHORTCUTS
   S -> start, E/X -> stop (two-step confirm), Esc -> cancel confirm.
   Ignored while typing in inputs/selects or when a modifier is held.
   ========================================================================== */
document.addEventListener('keydown', function(e) {
  if (e.ctrlKey || e.metaKey || e.altKey) return;
  if (e.repeat || e.defaultPrevented) return;
  var t = e.target;
  if (t && (t.tagName === 'INPUT' || t.tagName === 'SELECT' || t.tagName === 'TEXTAREA' || t.isContentEditable)) return;
  var k = (e.key || '').toLowerCase();
  if (k === 's') { e.preventDefault(); startRun(); }
  else if (k === 'e' || k === 'x') { e.preventDefault(); requestStop(); }
  else if (k === 'escape') { disarmStop(); }
});

/* ==========================================================================
   RELIABLE TOGGLE HANDLING (delegated fallback)
   Ensures .scan-toggle buttons always respond, even if per-module init failed.
   ========================================================================== */
document.addEventListener('click', function(e) {
  var btn = e.target && e.target.closest ? e.target.closest('button.scan-toggle') : null;
  if (!btn) return;
  try {
    var on = !(btn.classList.contains('active') || btn.getAttribute('aria-pressed') === 'true');
    btn.classList.toggle('active', on);
    btn.setAttribute('aria-pressed', on ? 'true' : 'false');
  } catch (err) { /* ignore */ }
}, false);

/* ==========================================================================
   RELIABLE ACTION HANDLING (capture fallback for critical controls)
   Uses capture to provide a consistent path when module listeners are missing.
   ========================================================================== */
document.addEventListener('click', function(e) {
  try {
    var t = e.target;
    if (!t || !t.closest) return;

    var a360Mode = t.closest('.a360-mode[data-mode]');
    if (a360Mode) {
      var mode = a360Mode.getAttribute('data-mode') || 'standard';
      if (typeof window.__a360SetMode === 'function') {
        e.preventDefault();
        e.stopImmediatePropagation();
        window.__a360SetMode(mode);
        return;
      }
      // Fallback: visual + auth visibility if app-15 handler unavailable
      try {
        document.querySelectorAll('.a360-mode[data-mode]').forEach(function (b) {
          var on = b.getAttribute('data-mode') === mode;
          b.classList.toggle('active', on);
          b.setAttribute('aria-pressed', on ? 'true' : 'false');
        });
        var authWrap = document.getElementById('a360AuthWrap');
        if (authWrap) authWrap.classList.toggle('hidden', mode !== 'standard');
      } catch (_) {}
      return;
    }

    if (t.closest('button.scan-toggle')) return;

    var nav = t.closest('[data-view]');
    if (nav && typeof showView === 'function') {
      var view = nav.getAttribute('data-view');
      if (view) {
        e.preventDefault();
        e.stopImmediatePropagation();
        showView(view);
        return;
      }
    }

    var startBtn = t.closest('#btnStart, #btnRunAgain');
    if (startBtn && typeof startRun === 'function') {
      e.preventDefault();
      e.stopImmediatePropagation();
      startRun();
      return;
    }

    var stopBtn = t.closest('#btnStop');
    if (stopBtn && typeof requestStop === 'function') {
      e.preventDefault();
      e.stopImmediatePropagation();
      requestStop();
      return;
    }

    var demoBtn = t.closest('#btnDemoStore');
    if (demoBtn && typeof demoStoreClick === 'function') {
      e.preventDefault();
      e.stopImmediatePropagation();
      demoStoreClick();
      return;
    }

    var demoUrlBtn = t.closest('#btnLoadDemo');
    if (demoUrlBtn && typeof loadDemoUrl === 'function') {
      e.preventDefault();
      e.stopImmediatePropagation();
      loadDemoUrl();
      return;
    }

    var obClose = t.closest('#onboardingClose');
    if (obClose && typeof dismissOnboarding === 'function') {
      e.preventDefault();
      e.stopImmediatePropagation();
      dismissOnboarding();
      return;
    }

    var viewReportBtn = t.closest('#btnViewReport');
    if (viewReportBtn && typeof viewReport === 'function') {
      e.preventDefault();
      e.stopImmediatePropagation();
      viewReport();
      return;
    }

    var sumClose = t.closest('#summaryClose');
    if (sumClose && typeof hideSummary === 'function') {
      e.preventDefault();
      e.stopImmediatePropagation();
      hideSummary();
      return;
    }
  } catch (err) { /* ignore */ }
}, true);

document.addEventListener('submit', function(e) {
  try {
    var form = e.target;
    if (!form || !form.id) return;
    var map = {
      controlsForm: 'startRun',
      onboardingForm: 'obSubmit',
      owaspForm: 'owaspRun',
      pentestForm: 'pentestRun',
      crawlForm: 'crawlRun',
      fuzzForm: 'fuzzRun',
      subdomainForm: 'subdomainRun',
      portscanForm: 'portscanRun',
      dirbustForm: 'dirbustRun',
      sslscanForm: 'sslscanRun',
      jwtForm: 'jwtRun',
      graphqlForm: 'graphqlRun',
      websocketForm: 'websocketRun'
    };
    var fnName = map[form.id];
    if (!fnName) return;
    var fn = (typeof window !== 'undefined' ? window[fnName] : null) || (typeof eval === 'function' ? null : null);
    // functions declared at top level are globals; access via global scope
    var handler = null;
    try { handler = (new Function('return typeof ' + fnName + ' !== "undefined" ? ' + fnName + ' : null'))(); } catch (_) { handler = null; }
    if (typeof handler === 'function') {
      e.preventDefault();
      e.stopImmediatePropagation();
      handler(e);
    }
  } catch (err) { /* ignore */ }
}, true);

/* ==========================================================================
   LOADING BARS (auto-inject into .btn.loading)
   ========================================================================== */
function ensureLoadingBars(btn) {
  if (!btn || !btn.classList || !btn.classList.contains('btn')) return;
  var bars = btn.querySelector('.ld-bars');
  if (btn.classList.contains('loading')) {
    if (!bars) {
      bars = document.createElement('div');
      bars.className = 'ld-bars';
      bars.innerHTML = '<i></i><i></i><i></i><i></i><i></i>';
      bars.setAttribute('aria-hidden', 'true');
      btn.appendChild(bars);
    }
  } else if (bars) {
    bars.remove();
  }
}
try {
  var mo = new MutationObserver(function(muts) {
    for (var i = 0; i < muts.length; i++) {
      var m = muts[i];
      if (m.type === 'attributes' && m.target && m.target.classList && m.target.classList.contains('btn')) {
        ensureLoadingBars(m.target);
      }
    }
  });
  mo.observe(document.documentElement, { attributes: true, subtree: true, attributeFilter: ['class'] });
  var existing = document.querySelectorAll('.btn.loading');
  for (var j = 0; j < existing.length; j++) ensureLoadingBars(existing[j]);
} catch (e) {}

/* ==========================================================================
   INIT
   ========================================================================== */
restoreLastConfig();
connect();
try { render(); } catch (e) { logRenderError(e); }
refreshDemoStore();
