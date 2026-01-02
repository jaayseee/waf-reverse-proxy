# WAF Reverse Proxy (MVP) — Python + FastAPI

A lightweight **Layer 7 Web Application Firewall (WAF)** built as a **reverse proxy**.  
It inspects HTTP requests for common web attack indicators (SQLi / XSS / path traversal), supports **config-driven rules**, **allow/deny lists**, **rate-limit escalation**, **hot-reload rules**, and generates an **HTML security report** from JSONL logs.

> ⚠️ Educational project: defensive learning tool. Test only on systems you own.

---

## Features

- ✅ Reverse proxy WAF in front of a backend web app
- ✅ Rule engine via `rules/base_rules.json` (regex-based matching)
- ✅ Detects: SQLi, XSS, path traversal
- ✅ Rule actions:
  - `BLOCK` (403)
  - `LOG` (allow + record for tuning)
- ✅ Allowlist / Denylist
- ✅ Rate-limit escalation: after **N blocks** in a time window → temporary ban (429)
- ✅ Structured JSONL logging (`logs/events.jsonl`)
- ✅ Stats endpoint (`/admin/stats`)
- ✅ **Hot reload** rules: edit JSON rules without restarting
- ✅ HTML report generator (`reports/waf_report.html`)
- ✅ Unit tests (`pytest`)

---

## Architecture (local)


Client (curl/browser)
        |
        v
WAF Reverse Proxy  http://127.0.0.1:8080
        |
        v
Backend App        http://127.0.0.1:5000



## Tech Stack

Python 3.12+
FastAPI + Uvicorn
httpx
pytest


## Getting Started (macOS)
1) Setup environment + install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install fastapi uvicorn httpx pytest

2) Run the backend app (Terminal 1)
source .venv/bin/activate
uvicorn backend.backend_app:app --host 127.0.0.1 --port 5000 --reload

3) Run the WAF proxy (Terminal 2)
source .venv/bin/activate
uvicorn app.waf:app --host 127.0.0.1 --port 8080 --reload




## Demo Commands
Allowed requests (forwarded to backend)
curl http://127.0.0.1:8080/; echo
curl "http://127.0.0.1:8080/search?q=hello"; echo

curl -X POST http://127.0.0.1:8080/login \
  -H "Content-Type: application/json" \
  -d '{"username":"jc","password":"test"}'; echo


SQLi block example (403)
curl -i "http://127.0.0.1:8080/search?q=union%20select"; echo

Rate limit escalation (429 after repeated violations)
curl -i "http://127.0.0.1:8080/search?q=union%20select"; echo
curl -i "http://127.0.0.1:8080/search?q=union%20select"; echo
curl -i "http://127.0.0.1:8080/search?q=union%20select"; echo
curl -i "http://127.0.0.1:8080/search?q=union%20select"; echo

View stats
curl http://127.0.0.1:8080/admin/stats; echo


Rules (Hot Reload)

Rules live in:
rules/base_rules.json

You can change rule actions between BLOCK and LOG.
The WAF checks the rules file modification time on each request and reloads automatically.

Example (tuning mode):
"action": "LOG"


Logging + Report

Events are stored as JSON Lines in:
logs/events.jsonl

Generate an HTML report:
source .venv/bin/activate
python tools/generate_report.py
open reports/waf_report.html

Tests
Run unit tests:
.venv/bin/python -m pytest -v

Screenshots
/waf-reverse-proxy/assets/test_passed.png
/waf-reverse-proxy/assets/waf_blocked_429.png
/waf-reverse-proxy/assets/report.png
/waf-reverse-proxy/assets/report2.png
/waf-reverse-proxy/assets/waf_report.html


## What I learned

How a reverse proxy inspects and forwards HTTP traffic
Why WAFs face false positives and need tuning (LOG mode)
Gradual response (block → rate limit)
SOC-style reporting (JSONL → HTML report)
Hot reloading config without restarts


## Future Improvements

Add deeper request normalization/canonicalization
Add rule packs inspired by OWASP CRS
Improve reporting (group by action, charts)
Dockerize (one-command run)
Add CI (GitHub Actions) to run pytest on every push


## Disclaimer

This project is for learning and defensive demonstration only.
Do not use it to attack systems or bypass security controls.


---

## What to remove from your README
✅ Remove the “Repo checklist” and `.gitignore` section from the README.  
Those belong as actual files/config in the repo, not in the README text.

---

## Two quick improvements you should do in the repo
1) Make sure you have a `.gitignore` file (separate file) with:
```gitignore
.venv/
__pycache__/
*.pyc
.DS_Store
logs/
reports/
.pytest_cache/
