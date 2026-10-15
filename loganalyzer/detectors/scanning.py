"""Web access-log detectors: scanning, attack patterns in URLs, suspicious user agents."""
from __future__ import annotations

import re
from urllib.parse import unquote

import pandas as pd

from detectors.util import max_in_window
from models import Alert

ATTACK_PATTERNS = {
    "SQL injection": re.compile(r"('|%27)\s*(or|and)\s+\S+=|union(\s|\+)+select|sleep\(\d+\)|--\s*$|'\s*or\s*'1'\s*=\s*'1", re.I),
    "XSS": re.compile(r"<\s*script|javascript:|onerror\s*=", re.I),
    "Path traversal": re.compile(r"\.\./|\.\.\\|/etc/passwd|/etc/shadow", re.I),
    "Command injection": re.compile(r";\s*(cat|ls|id|wget|curl)\b|\|\s*(cat|ls|id)\b|`[^`]+`", re.I),
}


def _decode(path: str) -> str:
    # URL-decode twice to catch double encoding (%252e%252e%252f)
    return unquote(unquote(path))


def detect_web_scanning(df: pd.DataFrame, cfg: dict) -> list[Alert]:
    """Many 403/404 responses from one IP, or hits on well-known sensitive paths. (T1595)"""
    alerts = []
    n, window = cfg["max_errors"], cfg["window_seconds"]
    errors = df[df["status"].isin([403, 404])].sort_values("ts")
    flagged = set()
    for ip, grp in errors.groupby("ip"):
        count, first, last = max_in_window(list(grp["ts"]), window)
        if count >= n:
            flagged.add(ip)
            alerts.append(Alert(
                rule="Web scanning (many 403/404)",
                severity="high" if count >= 3 * n else "medium",
                ip=ip,
                description=f"{count} error responses within {window}s "
                            f"({len(grp)} in total)",
                mitre="T1595",
                count=len(grp),
                first_seen=first,
                last_seen=last,
            ))

    sensitive = [p.lower() for p in cfg["sensitive_paths"]]
    paths = df["path"].map(lambda p: _decode(p).lower())
    hit_mask = paths.map(lambda p: any(s in p for s in sensitive))
    for ip, grp in df[hit_mask].groupby("ip"):
        distinct = grp["path"].map(lambda p: _decode(p).lower().split("?")[0]).nunique()
        sample = ", ".join(grp["path"].drop_duplicates().head(3))
        alerts.append(Alert(
            rule="Access to sensitive paths",
            severity="medium" if distinct >= 3 else "low",
            ip=ip,
            description=f"{distinct} sensitive path(s) requested (e.g. {sample})",
            mitre="T1595",
            count=len(grp),
            first_seen=grp["ts"].min(),
            last_seen=grp["ts"].max(),
        ))
    return alerts


def detect_attack_patterns(df: pd.DataFrame) -> list[Alert]:
    """SQLi / XSS / path traversal / command injection payloads in the URL. (T1190)"""
    found: dict[str, dict] = {}
    for row in df.itertuples():
        decoded = _decode(row.path)
        for name, rx in ATTACK_PATTERNS.items():
            if rx.search(decoded):
                entry = found.setdefault(row.ip, {"types": {}, "ts": [], "n": 0, "sample": row.path})
                entry["types"][name] = entry["types"].get(name, 0) + 1
                entry["ts"].append(row.ts)
                entry["n"] += 1
    alerts = []
    for ip, e in found.items():
        types = ", ".join(f"{k} x{v}" for k, v in sorted(e["types"].items()))
        alerts.append(Alert(
            rule="Attack payload in URL",
            severity="high",
            ip=ip,
            description=f"{types}; sample: {e['sample'][:80]}",
            mitre="T1190",
            count=e["n"],
            first_seen=min(e["ts"]),
            last_seen=max(e["ts"]),
        ))
    return alerts


def detect_suspicious_ua(df: pd.DataFrame, cfg: dict) -> list[Alert]:
    """Known attack-tool user agents; curl & friends only in bulk. (T1595)"""
    alerts = []
    tools = [t.lower() for t in cfg["tools"]]
    bulk = [t.lower() for t in cfg["bulk_tools"]]
    ua = df["ua"].str.lower()

    tool_mask = ua.map(lambda u: any(t in u for t in tools))
    for ip, grp in df[tool_mask].groupby("ip"):
        name = next(t for t in tools if t in grp["ua"].iloc[0].lower())
        alerts.append(Alert(
            rule="Attack tool user-agent",
            severity="medium",
            ip=ip,
            description=f"User-agent identifies as '{name}' ({len(grp)} requests)",
            mitre="T1595",
            count=len(grp),
            first_seen=grp["ts"].min(),
            last_seen=grp["ts"].max(),
        ))

    bulk_mask = ua.map(lambda u: any(t in u for t in bulk))
    for ip, grp in df[bulk_mask & ~tool_mask].groupby("ip"):
        if len(grp) >= cfg["bulk_min"]:
            alerts.append(Alert(
                rule="Bulk scripted requests",
                severity="low",
                ip=ip,
                description=f"{len(grp)} requests from scripted client "
                            f"'{grp['ua'].iloc[0][:40]}'",
                mitre="T1595",
                count=len(grp),
                first_seen=grp["ts"].min(),
                last_seen=grp["ts"].max(),
            ))
    return alerts
