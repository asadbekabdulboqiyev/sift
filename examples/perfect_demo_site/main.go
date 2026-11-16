package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"
)

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
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
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#0b1020;color:#e8eefc}
    .wrap{max-width:860px;margin:0 auto;padding:48px 20px}
    .card{background:#121a33;border:1px solid #243056;border-radius:16px;padding:28px}
    h1{margin:0 0 12px;font-size:2rem} p{line-height:1.6;color:#c8d4f0}
    .badge{display:inline-block;background:#123d2a;color:#9ff0c8;border:1px solid #1f6a48;border-radius:999px;padding:6px 12px;font-weight:600;margin-bottom:16px}
    code{background:#0b1020;border:1px solid #243056;border-radius:6px;padding:2px 6px}
    ul{color:#c8d4f0}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <div class="badge">Sift 360° target</div>
      <h1>100-Point Demo Site</h1>
      <p>This minimal site is designed as a clean, authorized local target for Sift 360° audits. It serves safe responses with recommended security headers and no fabricated behavior.</p>
      <ul>
        <li>Endpoint: <code>/</code> (HTML)</li>
        <li>Security headers: CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, Cache-Control</li>
        <li>Intended use: local/authorized performance and security verification with Sift</li>
      </ul>
    </div>
  </div>
</body>
</html>`)
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write([]byte(`{"status":"ok","service":"perfect-demo-site"}`))
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
