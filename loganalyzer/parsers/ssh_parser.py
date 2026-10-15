"""Parser for sshd lines in syslog / auth.log format."""
from __future__ import annotations

import re
from datetime import datetime
from typing import Iterable

import pandas as pd

COLUMNS = ["ts", "event", "user", "ip"]

_IP = r"\d{1,3}(?:\.\d{1,3}){3}"
SSH_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"(?:"
    rf"(?P<event>Failed password|Accepted password|Accepted publickey)\s+for\s+"
    rf"(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>{_IP})"
    r"|"
    rf"(?P<event2>Invalid user)\s+(?P<user2>\S*)\s+from\s+(?P<ip2>{_IP})"
    r")"
)

_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def parse_lines(lines: Iterable[str], year: int) -> pd.DataFrame:
    """Parse sshd log lines. Syslog timestamps carry no year, so `year` is
    the year of the first line; it is bumped when the log rolls Dec -> Jan."""
    rows = []
    prev_month = None
    for line in lines:
        m = SSH_RE.match(line)
        if not m:
            continue
        ts_str = " ".join(m.group("ts").split())
        month = _MONTHS[ts_str[:3]]
        if prev_month == 12 and month == 1:
            year += 1
        prev_month = month
        try:
            ts = datetime.strptime(f"{year} {ts_str}", "%Y %b %d %H:%M:%S")
        except ValueError:  # e.g. Feb 29 in a non-leap year
            continue
        if m.group("event"):
            rows.append((ts, m.group("event"), m.group("user"), m.group("ip")))
        else:
            rows.append((ts, m.group("event2"), m.group("user2"), m.group("ip2")))
    df = pd.DataFrame(rows, columns=COLUMNS)
    if df.empty:
        return df.astype({"ts": "datetime64[ns]"})
    df["ts"] = pd.to_datetime(df["ts"])
    return df.sort_values("ts").reset_index(drop=True)


def parse_file(path: str, year: int) -> pd.DataFrame:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return parse_lines(fh, year)
