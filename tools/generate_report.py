import json
from collections import Counter
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOG_PATH = ROOT / "logs" / "events.jsonl"
REPORT_PATH = ROOT / "reports" / "waf_report.html"


def load_events():
    if not LOG_PATH.exists():
        return []
    events = []
    with open(LOG_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            events.append(json.loads(line))
    return events


def fmt_ts(ts: float) -> str:
    # Convert unix timestamp to readable time
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def main():
    events = load_events()

    total_blocked = len(events)
    by_rule = Counter(e.get("rule_id", "UNKNOWN") for e in events)
    by_path = Counter(e.get("path", "UNKNOWN") for e in events)

    recent = sorted(events, key=lambda e: e.get("timestamp", 0), reverse=True)[:20]

    html = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>WAF Report</title>
  <style>
    body {{ font-family: -apple-system, system-ui, Arial; margin: 24px; }}
    .card {{ border: 1px solid #ddd; border-radius: 12px; padding: 16px; margin-bottom: 16px; }}
    h1 {{ margin-top: 0; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ border-bottom: 1px solid #eee; padding: 10px; text-align: left; font-size: 14px; }}
    th {{ background: #fafafa; }}
    .muted {{ color: #666; }}
    .pill {{ display: inline-block; padding: 3px 10px; border-radius: 999px; border: 1px solid #ddd; font-size: 12px; }}
  </style>
</head>
<body>
  <h1>WAF Security Report</h1>
  <p class="muted">Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>

  <div class="card">
    <h2>Summary</h2>
    <p><span class="pill">Blocked events</span> <b>{total_blocked}</b></p>
    <p class="muted">Note: This report summarizes <b>blocked</b> requests captured in <code>logs/events.jsonl</code>.</p>
  </div>

  <div class="card">
    <h2>Blocked by Rule</h2>
    <table>
      <tr><th>Rule ID</th><th>Count</th></tr>
      {''.join(f"<tr><td>{rid}</td><td>{count}</td></tr>" for rid, count in by_rule.most_common())}
    </table>
  </div>

  <div class="card">
    <h2>Top Targeted Paths</h2>
    <table>
      <tr><th>Path</th><th>Count</th></tr>
      {''.join(f"<tr><td>{path}</td><td>{count}</td></tr>" for path, count in by_path.most_common(10))}
    </table>
  </div>

  <div class="card">
    <h2>Recent Blocked Events (last 20)</h2>
    <table>
      <tr>
        <th>Time</th>
        <th>Client IP</th>
        <th>Method</th>
        <th>Path</th>
        <th>Query</th>
        <th>Rule</th>
        <th>Severity</th>
      </tr>
      {''.join(
        "<tr>"
        f"<td>{fmt_ts(e.get('timestamp', 0))}</td>"
        f"<td>{e.get('client_ip', '')}</td>"
        f"<td>{e.get('method', '')}</td>"
        f"<td>{e.get('path', '')}</td>"
        f"<td>{e.get('query', '')}</td>"
        f"<td>{e.get('rule_id', '')}</td>"
        f"<td>{e.get('severity', '')}</td>"
        "</tr>"
        for e in recent
      )}
    </table>
  </div>

</body>
</html>"""

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(html, encoding="utf-8")
    print(f"[OK] Wrote report to: {REPORT_PATH}")


if __name__ == "__main__":
    main()
