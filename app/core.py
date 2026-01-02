from collections import deque, defaultdict
from typing import Dict, Deque, List, Tuple

def allowlisted(client_ip: str, path: str, allowlist: dict) -> bool:
    return (client_ip in allowlist.get("ip", [])) or (path in allowlist.get("paths", []))

def denylisted(client_ip: str, denylist: dict) -> bool:
    return client_ip in denylist.get("ip", [])

def rule_matches(rule: dict, fields: dict) -> bool:
    """
    rule: {targets: [...], _re: compiled regex}
    fields: {path/query/body/headers: "..."}
    """
    joined = "\n".join(fields.get(t, "") for t in rule["targets"])
    return bool(rule["_re"].search(joined))

def record_violation_and_maybe_ban(
    ip: str,
    now: float,
    violations: Dict[str, Deque[float]],
    banned_until: Dict[str, float],
    window_sec: int,
    max_violations: int,
    ban_seconds: int,
) -> Tuple[bool, int]:
    """
    Returns (banned_now, violation_count_in_window)
    """
    q = violations[ip]
    q.append(now)

    # trim outside window
    while q and (now - q[0]) > window_sec:
        q.popleft()

    if len(q) >= max_violations:
        banned_until[ip] = now + ban_seconds
        return True, len(q)

    return False, len(q)
