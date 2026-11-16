# 100-Point Demo Site

Minimal local demo site intended as a clean, authorized target for **Sift 360°** audits.

## Run

```bash
go run ./examples/perfect_demo_site -addr 127.0.0.1:8095
```

Endpoints:
- `/` — HTML page
- `/health` — JSON health response

## Example audit (dashboard API)

With `Sift dashboard` running on `127.0.0.1:8888`:

```bash
curl -sS -X POST http://127.0.0.1:8888/api/audit-360 \
  -H 'Content-Type: application/json' \
  -d '{"target_url":"http://127.0.0.1:8095","mode":"standard","authorized":true,"max_duration_sec":25}'
```

Poll `/api/audit-360/status?job_id=...` for completion and the sealed report. In an authorized local standard run with measurable load telemetry and no security findings, this target can achieve a **100/100** overall score (as measured by Sift).
