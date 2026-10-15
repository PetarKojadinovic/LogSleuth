"""Parser for Apache / Nginx 'combined' access log format."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Iterable

import pandas as pd

COLUMNS = ["ts", "ip", "method", "path", "status", "size", "referer", "ua"]

APACHE_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+[^"]*)?"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\d+|-)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)


def parse_lines(lines: Iterable[str]) -> pd.DataFrame:
    rows = []
    for line in lines:
        m = APACHE_RE.match(line)
        if not m:
            continue
        try:
            dt = datetime.strptime(m.group("ts"), "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            continue
        ts = dt.astimezone(timezone.utc).replace(tzinfo=None)  # normalise to naive UTC
        size = 0 if m.group("size") == "-" else int(m.group("size"))
        rows.append((
            ts, m.group("ip"), m.group("method"), m.group("path"),
            int(m.group("status")), size,
            m.group("referer") or "-", m.group("ua") or "-",
        ))
    df = pd.DataFrame(rows, columns=COLUMNS)
    if df.empty:
        return df.astype({"ts": "datetime64[ns]"})
    df["ts"] = pd.to_datetime(df["ts"])
    return df.sort_values("ts").reset_index(drop=True)


def parse_file(path: str) -> pd.DataFrame:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return parse_lines(fh)
