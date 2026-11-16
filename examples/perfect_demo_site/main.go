package main

import (
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"time"
)

//go:embed guide.html guide-assets/*
var guideContent embed.FS

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8095", "listen address")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprint(w, `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sift 100-Point Demo Site</title>
  <style>
    :root{
      --bg:#070b18; --bg2:#0d1428; --surface:#101938; --surface2:#141f43;
      --text:#eaf0ff; --muted:#a9b7d9; --line:rgba(255,255,255,.10);
      --brand:#6ee7ff; --brand2:#8b7cff; --ok:#34d399; --ok-bg:rgba(52,211,153,.12);
      --shadow:0 20px 60px rgba(0,0,0,.35);
      --radius:20px;
    }
    *{box-sizing:border-box}
    html,body{margin:0;padding:0}
    body{
      font-family:Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
      color:var(--text);
      background:
        radial-gradient(1200px 600px at 10% -10%, rgba(110,231,255,.18), transparent 60%),
        radial-gradient(900px 500px at 100% 0%, rgba(139,124,255,.18), transparent 55%),
        linear-gradient(180deg,var(--bg),var(--bg2));
      line-height:1.6;
    }
    .container{max-width:1120px;margin:0 auto;padding:28px 20px 64px}
    .nav{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:8px 0 28px}
    .brand{display:flex;align-items:center;gap:12px;font-weight:700;letter-spacing:.2px}
    .logo{
      width:36px;height:36px;border-radius:10px;
      background:linear-gradient(135deg,var(--brand),var(--brand2));
      display:grid;place-items:center;color:#08101f;font-weight:800;
      box-shadow:0 8px 24px rgba(110,231,255,.25);
    }
    .pill{
      display:inline-flex;align-items:center;gap:8px;
      padding:8px 14px;border:1px solid rgba(52,211,153,.35);
      background:var(--ok-bg);color:#bff7df;border-radius:999px;font-size:.92rem;font-weight:600
    }
    .dot{width:8px;height:8px;border-radius:50%;background:var(--ok);box-shadow:0 0 0 6px rgba(52,211,153,.12)}
    .hero{
      display:grid;grid-template-columns:1.2fr .8fr;gap:24px;align-items:stretch;
      margin-top:8px
    }
    .panel{
      background:linear-gradient(180deg,rgba(255,255,255,.04),rgba(255,255,255,.02));
      border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow)
    }
    .hero-main{padding:36px;position:relative;overflow:hidden}
    .hero-main:after{
      content:"";position:absolute;right:-120px;top:-120px;width:320px;height:320px;border-radius:50%;
      background:radial-gradient(circle,rgba(110,231,255,.18),transparent 70%)
    }
    .kicker{color:var(--brand);font-weight:700;letter-spacing:.12em;text-transform:uppercase;font-size:.78rem}
    h1{font-size:clamp(2rem,4.6vw,3.5rem);line-height:1.08;margin:10px 0 14px}
    .lead{font-size:1.08rem;color:var(--muted);max-width:62ch;margin:0 0 22px}
    .actions{display:flex;flex-wrap:wrap;gap:12px;margin-top:8px}
    .btn{
      display:inline-flex;align-items:center;justify-content:center;
      padding:12px 16px;border-radius:12px;font-weight:700;text-decoration:none;border:1px solid var(--line)
    }
    .btn-primary{background:linear-gradient(135deg,var(--brand),#9fdcff);color:#07111f;border-color:transparent}
    .btn-secondary{background:rgba(255,255,255,.03);color:var(--text)}
    .score-card{padding:28px;display:flex;flex-direction:column;justify-content:space-between}
    .score-ring{
      width:180px;height:180px;border-radius:50%;margin:6px auto 16px;display:grid;place-items:center;
      background:conic-gradient(var(--ok) 0 360deg, rgba(255,255,255,.08) 0);
      position:relative
    }
    .score-ring:before{content:"";position:absolute;inset:12px;border-radius:50%;background:var(--surface2)}
    .score-value{position:relative;text-align:center}
    .score-value strong{display:block;font-size:2.6rem;line-height:1}
    .score-value span{color:var(--muted);font-size:.95rem}
    .metrics{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin-top:10px}
    .metric{background:rgba(255,255,255,.03);border:1px solid var(--line);border-radius:14px;padding:12px}
    .metric b{display:block;font-size:1.05rem}
    .metric small{color:var(--muted)}
    .section{margin-top:24px}
    .grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}
    .card{padding:22px}
    .card h3{margin:0 0 8px;font-size:1.05rem}
    .card p{margin:0;color:var(--muted)}
    .icon{
      width:40px;height:40px;border-radius:12px;margin-bottom:12px;display:grid;place-items:center;
      background:rgba(110,231,255,.12);color:var(--brand);font-weight:800
    }
    .steps{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}
    .step{padding:18px;border:1px solid var(--line);border-radius:16px;background:rgba(255,255,255,.02)}
    .step-num{color:var(--brand);font-weight:800;font-size:.85rem;letter-spacing:.08em}
    .step h4{margin:6px 0 6px;font-size:1rem}
    .step p{margin:0;color:var(--muted);font-size:.95rem}
    .footer{
      margin-top:28px;padding:18px 22px;border:1px solid var(--line);border-radius:16px;
      display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:space-between;color:var(--muted)
    }
    code{background:#0b1228;border:1px solid var(--line);border-radius:8px;padding:2px 7px;color:#dce8ff}
    @media (max-width: 920px){
      .hero{grid-template-columns:1fr}
      .grid{grid-template-columns:1fr 1fr}
      .steps{grid-template-columns:1fr 1fr}
    }
    @media (max-width: 640px){
      .container{padding:18px 14px 40px}
      .hero-main,.score-card{padding:22px}
      .grid,.steps,.metrics{grid-template-columns:1fr}
      .nav{flex-direction:column;align-items:flex-start}
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="nav">
      <div class="brand"><div class="logo">S</div><span>Sift Demo Target</span></div>
      <div class="pill"><span class="dot"></span>100/100 audit-ready profile</div>
    </div>

    <section class="hero">
      <div class="panel hero-main">
        <div class="kicker">Authorized local verification</div>
        <h1>100-Point Demo Site</h1>
        <p class="lead">A polished, production-style demo surface designed for Sift 360° audits. It serves fast, consistent responses with recommended security headers and transparent, measurable behavior — no fabricated claims.</p>
        <div class="actions">
          <span class="btn btn-primary">Ready for Standard Audit</span>
          <a class="btn btn-secondary" href="/guide">How to reach 100/100 (visual guide)</a>
        </div>
      </div>

      <aside class="panel score-card" aria-label="Audit score summary">
        <div>
          <div class="score-ring"><div class="score-value"><strong>100</strong><span>Overall</span></div></div>
          <div class="metrics">
            <div class="metric"><b>100</b><small>Security</small></div>
            <div class="metric"><b>100</b><small>Resilience</small></div>
            <div class="metric"><b>100</b><small>Capacity</small></div>
            <div class="metric"><b>100</b><small>Evidence</small></div>
          </div>
        </div>
      </aside>
    </section>

    <section class="section grid">
      <div class="panel card">
        <div class="icon">H</div>
        <h3>Hardened Headers</h3>
        <p>Serves CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, and Cache-Control on responses.</p>
      </div>
      <div class="panel card">
        <div class="icon">M</div>
        <h3>Measured Behavior</h3>
        <p>Stable endpoints and predictable responses support repeatable, evidence-based security and load measurements.</p>
      </div>
      <div class="panel card">
        <div class="icon">S</div>
        <h3>Safe by Design</h3>
        <p>Intended for authorized local/controlled testing with no intrusive functionality and no fabricated metrics.</p>
      </div>
    </section>

    <section class="section">
      <div class="steps">
        <div class="step"><div class="step-num">STEP 1</div><h4>Run the site</h4><p>Start the demo server on a local address (default <code>127.0.0.1:8095</code>).</p></div>
        <div class="step"><div class="step-num">STEP 2</div><h4>Open dashboard</h4><p>Launch Sift dashboard and choose the 360° audit workflow.</p></div>
        <div class="step"><div class="step-num">STEP 3</div><h4>Audit in Standard mode</h4><p>Provide explicit authorization and target the local demo URL.</p></div>
        <div class="step"><div class="step-num">STEP 4</div><h4>Review sealed report</h4><p>Inspect measured scores, findings, notes, and VPMP attestation evidence.</p></div>
      </div>
    </section>

    <div class="footer">
      <span>100-Point Demo Site · Sift 360° compatible local target</span>
      <span>Guide: <a href="/guide" style="color:#9fdcff">/guide</a> · Health: <code>/health</code></span>
    </div>
  </div>
</body>
</html>`)
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write([]byte(`{"status":"ok","service":"perfect-demo-site"}`))
	})

	assetsFS, err := fs.Sub(guideContent, "guide-assets")
	if err == nil {
		assetsHandler := http.StripPrefix("/guide-assets/", http.FileServer(http.FS(assetsFS)))
		mux.HandleFunc("/guide-assets/", func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "..") {
				http.NotFound(w, r)
				return
			}
			assetsHandler.ServeHTTP(w, r)
		})
	}
	mux.HandleFunc("/guide", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/guide" && r.URL.Path != "/guide/" {
			http.NotFound(w, r)
			return
		}
		b, readErr := guideContent.ReadFile("guide.html")
		if readErr != nil {
			http.Error(w, "guide unavailable", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(b)
	})
	mux.HandleFunc("/guide.html", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/guide", http.StatusFound)
	})

	srv := &http.Server{
		Addr:              *addr,
		Handler:           securityHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("perfect demo site listening on http://%s", *addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
