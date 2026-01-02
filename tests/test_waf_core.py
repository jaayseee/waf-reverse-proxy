import re
from collections import deque, defaultdict

from app.core import allowlisted, rule_matches, record_violation_and_maybe_ban


def test_allowlist_path_bypass():
    allow = {"ip": [], "paths": ["/admin/stats"]}
    assert allowlisted("127.0.0.1", "/admin/stats", allow) is True
    assert allowlisted("127.0.0.1", "/search", allow) is False


def test_sqli_rule_matches_union_select():
    rule = {
        "id": "SQLI_BASIC",
        "targets": ["query"],
        "_re": re.compile(r"(?i)(union\s+select)"),
    }
    fields = {"query": "q=union select"}
    assert rule_matches(rule, fields) is True


def test_rate_limit_triggers_after_threshold():
    violations = defaultdict(deque)
    banned_until = {}

    window_sec = 60
    max_violations = 3
    ban_seconds = 120
    ip = "127.0.0.1"

    # 1st violation
    banned, count = record_violation_and_maybe_ban(ip, 1000.0, violations, banned_until, window_sec, max_violations, ban_seconds)
    assert banned is False
    assert count == 1

    # 2nd violation
    banned, count = record_violation_and_maybe_ban(ip, 1005.0, violations, banned_until, window_sec, max_violations, ban_seconds)
    assert banned is False
    assert count == 2

    # 3rd violation -> ban
    banned, count = record_violation_and_maybe_ban(ip, 1010.0, violations, banned_until, window_sec, max_violations, ban_seconds)
    assert banned is True
    assert count == 3
    assert banned_until[ip] == 1010.0 + ban_seconds
