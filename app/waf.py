import json
import re
import time
import uuid
from collections import deque, defaultdict
from pathlib import Path
from threading import Lock
from urllib.parse import unquote_plus

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

app = FastAPI(title="WAF Reverse Proxy (MVP)")

BACKEND_BASE = "http://127.0.0.1:5000"

ROOT = Path(__file__).resolve().parent.parent
RULES_PATH = ROOT / "rules" / "base_rules.json"
LOG_PATH = ROOT / "logs" / "events.jsonl"

# ----------------------------
# Hot-reloadable config
# ----------------------------
CONFIG_LOCK = Lock()
CONFIG_MTIME = 0.0
CONFIG_LOADED_AT = 0.0

RULES = []
ALLOWLIST = {"ip": [], "paths": []}
DENYLIST = {"ip": []}

def _load_config_from_disk():
    """Load rules.json and compile regex patterns."""
    data = json.loads(RULES_PATH.read_text(encoding="utf-8"))

    compiled_rules = []
    for r in data.get("rules", []):
        compiled_rules.append({**r, "_re": re.compile(r["pattern"])})

    allowlist = data.get("allowlist", {"ip": [], "paths": []})
    denylist = data.get("denylist", {"ip": []})

    return compiled_rules, allowlist, denylist

def maybe_reload_config():
    """
    Hot reload if base_rules.json changed.
    Called on each request (lightweight mtime check).
    """
    global RULES, ALLOWLIST, DENYLIST, CONFIG_MTIME, CONFIG_LOADED_AT

    try:
        mtime = RULES_PATH.stat().st_mtime
    except FileNotFoundError:
        return

    if mtime <= CONFIG_MTIME:
        return

    with CONFIG_LOCK:
        # Re-check inside lock
        mtime2 = RULES_PATH.stat().st_mtime
        if mtime2 <= CONFIG_MTIME:
            return

        new_rules, new_allow, new_deny = _load_config_from_disk()
        RULES = new_rules
        ALLOWLIST = new_allow
        DENYLIST = new_deny
        CONFIG_MTIME = mtime2
        CONFIG_LOADED_AT = time.time()

# Load once at startup
maybe_reload_config()

# ----------------------------
# Helpers
# ----------------------------
def normalize(s: str) -> str:
    return unquote_plus(s or "")

def log_event(event: dict):
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")

def extract_fields(request: Request, body_text: str) -> dict:
    path = normalize(str(request.url.path))
    query = normalize(str(request.url.query))
    body = normalize(body_text)
    headers_joined = "\n".join([f"{k}: {v}" for k, v in request.headers.items()])
    headers_joined = normalize(headers_joined)
    return {"path": path, "query": query, "body": body, "headers": headers_joined}

def allowlisted(client_ip: str, path: str) -> bool:
    return (client_ip in ALLOWLIST.get("ip", [])) or (path in ALLOWLIST.get("paths", []))

def denylisted(client_ip: str) -> bool:
    return client_ip in DENYLIST.get("ip", [])

def inspect(fields: dict):
    for rule in RULES:
        joined = "\n".join(fields.get(t, "") for t in rule["targets"])
        if rule["_re"].search(joined):
            return rule
    return None

# ----------------------------
# Stats + rate limiting
# ----------------------------
STATS = {"allowed": 0, "blocked": 0, "logged": 0, "rate_limited": 0, "by_rule": {}}

VIOLATION_WINDOW_SEC = 60
MAX_VIOLATIONS = 3
BAN_SECONDS = 120

violations = defaultdict(deque)
banned_until = {}

@app.get("/admin/stats")
def admin_stats():
    return {
        **STATS,
        "config_last_loaded_epoch": CONFIG_LOADED_AT,
        "config_file_mtime_epoch": CONFIG_MTIME,
        "allowlist": ALLOWLIST,
        "denylist": DENYLIST,
        "rule_count": len(RULES),
    }

@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
async def proxy(full_path: str, request: Request):
    # Hot reload rules if the JSON changed
    maybe_reload_config()

    request_id = str(uuid.uuid4())
    now = time.time()
    client_ip = request.client.host if request.client else "unknown"
    path = str(request.url.path)

    # Denylist: immediate block
    if denylisted(client_ip):
        STATS["blocked"] += 1
        STATS["by_rule"]["DENYLIST"] = STATS["by_rule"].get("DENYLIST", 0) + 1
        log_event({
            "timestamp": now,
            "request_id": request_id,
            "client_ip": client_ip,
            "method": request.method,
            "path": path,
            "query": str(request.url.query),
            "action": "BLOCK",
            "rule_id": "DENYLIST",
            "severity": "HIGH",
            "tags": ["denylist"],
        })
        return JSONResponse(status_code=403, content={"blocked": True, "rule_id": "DENYLIST"})

    # Rate limit: temporary ban
    if client_ip in banned_until and now < banned_until[client_ip]:
        STATS["rate_limited"] += 1
        return JSONResponse(
            status_code=429,
            content={"blocked": True, "reason": "rate_limited", "retry_after_seconds": int(banned_until[client_ip] - now)},
        )

    body_bytes = await request.body()
    body_text = body_bytes.decode("utf-8", errors="ignore")
    fields = extract_fields(request, body_text)

    # Allowlist: bypass inspection
    if not allowlisted(client_ip, path):
        matched = inspect(fields)

        if matched:
            action = matched.get("action", "BLOCK").upper()
            rule_id = matched["id"]

            # LOG action: record but allow traffic to backend
            if action == "LOG":
                STATS["logged"] += 1
                STATS["by_rule"][rule_id] = STATS["by_rule"].get(rule_id, 0) + 1
                log_event({
                    "timestamp": now,
                    "request_id": request_id,
                    "client_ip": client_ip,
                    "method": request.method,
                    "path": path,
                    "query": str(request.url.query),
                    "action": "LOG",
                    "rule_id": rule_id,
                    "severity": matched.get("severity", "LOW"),
                    "tags": matched.get("tags", []),
                })

            # BLOCK action: record + escalate
            elif action == "BLOCK":
                STATS["blocked"] += 1
                STATS["by_rule"][rule_id] = STATS["by_rule"].get(rule_id, 0) + 1

                q = violations[client_ip]
                q.append(now)
                while q and (now - q[0]) > VIOLATION_WINDOW_SEC:
                    q.popleft()

                if len(q) >= MAX_VIOLATIONS:
                    banned_until[client_ip] = now + BAN_SECONDS
                    log_event({
                        "timestamp": now,
                        "request_id": request_id,
                        "client_ip": client_ip,
                        "method": request.method,
                        "path": path,
                        "query": str(request.url.query),
                        "action": "RATE_LIMIT",
                        "rule_id": "RATE_LIMIT",
                        "severity": "MEDIUM",
                        "tags": ["rate_limit"],
                    })

                log_event({
                    "timestamp": now,
                    "request_id": request_id,
                    "client_ip": client_ip,
                    "method": request.method,
                    "path": path,
                    "query": str(request.url.query),
                    "action": "BLOCK",
                    "rule_id": rule_id,
                    "severity": matched.get("severity", "UNKNOWN"),
                    "tags": matched.get("tags", []),
                })

                return JSONResponse(
                    status_code=403,
                    content={"blocked": True, "request_id": request_id, "rule_id": rule_id, "message": "Blocked by WAF rule"},
                )

    # Forward to backend
    STATS["allowed"] += 1

    url = f"{BACKEND_BASE}{request.url.path}"
    if request.url.query:
        url += f"?{request.url.query}"

    headers = dict(request.headers)
    headers.pop("host", None)

    async with httpx.AsyncClient(timeout=10.0) as client:
        backend_resp = await client.request(
            method=request.method,
            url=url,
            headers=headers,
            content=body_bytes,
        )

    return Response(
        content=backend_resp.content,
        status_code=backend_resp.status_code,
        headers=dict(backend_resp.headers),
        media_type=backend_resp.headers.get("content-type"),
    )
