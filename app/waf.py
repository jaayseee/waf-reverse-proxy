import json
import re
import time
import uuid
from pathlib import Path
from urllib.parse import unquote_plus

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

APP_ROOT = Path(__file__).resolve().parent.parent
RULES_PATH = APP_ROOT / "rules" / "base_rules.json"
LOG_PATH = APP_ROOT / "logs" / "events.jsonl"

BACKEND_BASE = "http://127.0.0.1:5000"

app = FastAPI(title="WAF Reverse Proxy (MVP)")

stats = {
    "blocked": 0,
    "allowed": 0,
    "by_rule": {},
    "by_tag": {},
    "top_paths": {},
}

def load_rules():
    with open(RULES_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    compiled = []
    for r in data.get("rules", []):
        compiled.append({**r, "_re": re.compile(r["pattern"])})
    data["_compiled_rules"] = compiled
    return data

RULESET = load_rules()

def normalize_text(value: str) -> str:
    if not value:
        return ""
    return unquote_plus(value)

def extract_request_fields(request: Request, body_text: str) -> dict:
    path = str(request.url.path)
    query = str(request.url.query)
    headers = "\n".join([f"{k}: {v}" for k, v in request.headers.items()])
    return {
        "path": normalize_text(path),
        "query": normalize_text(query),
        "headers": normalize_text(headers),
        "body": normalize_text(body_text),
    }

def is_allowlisted(client_ip: str, path: str) -> bool:
    allow = RULESET.get("allowlist", {})
    if client_ip in allow.get("ip", []):
        return True
    if path in allow.get("paths", []):
        return True
    return False

def log_event(event: dict):
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")

def bump_stats(allowed: bool, path: str, rule_id: str | None = None, tags=None):
    if allowed:
        stats["allowed"] += 1
    else:
        stats["blocked"] += 1

    stats["top_paths"][path] = stats["top_paths"].get(path, 0) + 1

    if rule_id:
        stats["by_rule"][rule_id] = stats["by_rule"].get(rule_id, 0) + 1

    if tags:
        for t in tags:
            stats["by_tag"][t] = stats["by_tag"].get(t, 0) + 1

def inspect_request(request: Request, fields: dict):
    client_ip = request.client.host if request.client else "unknown"
    path = fields["path"]

    if is_allowlisted(client_ip, path):
        return None

    for rule in RULESET["_compiled_rules"]:
        targets = rule.get("targets", [])
        joined = "\n".join([fields.get(t, "") for t in targets])
        if rule["_re"].search(joined):
            return rule
    return None

async def forward_to_backend(request: Request, body: bytes) -> Response:
    url = f"{BACKEND_BASE}{request.url.path}"
    if request.url.query:
        url += f"?{request.url.query}"

    headers = dict(request.headers)
    headers.pop("host", None)

    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.request(
            method=request.method,
            url=url,
            headers=headers,
            content=body,
        )

    return Response(
        content=resp.content,
        status_code=resp.status_code,
        headers=dict(resp.headers),
        media_type=resp.headers.get("content-type"),
    )

@app.get("/admin/stats")
def admin_stats():
    return stats

@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
async def waf_proxy(full_path: str, request: Request):
    request_id = str(uuid.uuid4())
    ts = time.time()
    client_ip = request.client.host if request.client else "unknown"

    body_bytes = await request.body()
    body_text = body_bytes.decode("utf-8", errors="ignore")

    fields = extract_request_fields(request, body_text)
    matched_rule = inspect_request(request, fields)

    if matched_rule and matched_rule.get("action") == "BLOCK":
        event = {
            "timestamp": ts,
            "request_id": request_id,
            "client_ip": client_ip,
            "method": request.method,
            "path": str(request.url.path),
            "query": str(request.url.query),
            "action": "BLOCK",
            "rule_id": matched_rule["id"],
            "severity": matched_rule.get("severity", "UNKNOWN"),
            "tags": matched_rule.get("tags", []),
        }
        log_event(event)
        bump_stats(False, str(request.url.path), matched_rule["id"], matched_rule.get("tags", []))

        return JSONResponse(
            status_code=403,
            content={
                "blocked": True,
                "request_id": request_id,
                "reason": "Request matched WAF rule",
                "rule_id": matched_rule["id"],
            },
        )

    bump_stats(True, str(request.url.path))
    return await forward_to_backend(request, body_bytes)
