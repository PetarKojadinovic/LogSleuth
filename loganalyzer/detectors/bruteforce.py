"""SSH detectors: brute force, username enumeration, success after guessing."""
from __future__ import annotations

import pandas as pd

from detectors.util import max_in_window
from models import Alert


def detect_bruteforce(df: pd.DataFrame, cfg: dict) -> list[Alert]:
    """>= max_attempts failed logins from one IP inside a sliding window. (T1110.001)"""
    n = cfg["max_attempts"]
    window = cfg["window_seconds"]
    alerts = []
    fails = df[df["event"] == "Failed password"].sort_values("ts")
    for ip, grp in fails.groupby("ip"):
        count, first, last = max_in_window(list(grp["ts"]), window)
        if count >= n:
            alerts.append(Alert(
                rule="SSH brute force",
                severity="high" if count >= 3 * n else "medium",
                ip=ip,
                description=f"{count} failed logins within {window}s "
                            f"({len(grp)} failures in total)",
                mitre="T1110.001",
                count=len(grp),
                first_seen=first,
                last_seen=last,
            ))
    return alerts


def detect_enumeration(df: pd.DataFrame, cfg: dict) -> list[Alert]:
    """One IP trying many different usernames (password spraying / enumeration). (T1110.003)"""
    n = cfg["min_distinct_users"]
    alerts = []
    tries = df[df["event"].isin(["Failed password", "Invalid user"])]
    for ip, grp in tries.groupby("ip"):
        users = grp["user"].nunique()
        if users >= n:
            sample = ", ".join(grp["user"].value_counts().head(5).index)
            alerts.append(Alert(
                rule="Username enumeration / password spraying",
                severity="high" if users >= 3 * n else "medium",
                ip=ip,
                description=f"{users} distinct usernames tried (e.g. {sample})",
                mitre="T1110.003",
                count=len(grp),
                first_seen=grp["ts"].min(),
                last_seen=grp["ts"].max(),
            ))
    return alerts


def detect_success_after_failures(df: pd.DataFrame, cfg: dict) -> list[Alert]:
    """Accepted login from an IP that previously had many failures. Most critical finding. (T1110)"""
    n = cfg["min_failures"]
    lookback = pd.Timedelta(minutes=cfg["lookback_minutes"])
    alerts = []
    fails = df[df["event"] == "Failed password"]
    accepted = df[df["event"].isin(["Accepted password", "Accepted publickey"])]
    fails_by_ip = {ip: g["ts"] for ip, g in fails.groupby("ip")}
    seen = set()
    for row in accepted.itertuples():
        f = fails_by_ip.get(row.ip)
        if f is None:
            continue
        prior = f[(f < row.ts) & (f >= row.ts - lookback)]
        if len(prior) >= n and (row.ip, row.user) not in seen:
            seen.add((row.ip, row.user))
            alerts.append(Alert(
                rule="Successful login after brute force",
                severity="high",
                ip=row.ip,
                description=f"User '{row.user}' logged in after {len(prior)} failed "
                            f"attempts from the same IP - possible compromise",
                mitre="T1110",
                count=len(prior),
                first_seen=prior.min(),
                last_seen=row.ts,
            ))
    return alerts
