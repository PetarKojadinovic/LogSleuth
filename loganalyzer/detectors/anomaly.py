"""Statistical anomalies: request-rate spikes (z-score) and off-hours logins."""
from __future__ import annotations

import pandas as pd

from models import Alert


def rate_series(df: pd.DataFrame, bin_: str) -> pd.Series:
    return df.set_index("ts").resample(bin_).size()


def detect_rate_spikes(df: pd.DataFrame, cfg: dict, label: str) -> list[Alert]:
    """Time bins whose event count is more than `zscore` std-devs above the mean."""
    if df.empty:
        return []
    counts = rate_series(df, cfg["bin"])
    if len(counts) < cfg["min_bins"]:
        return []
    std = counts.std(ddof=0)
    if std == 0:
        return []
    z = (counts - counts.mean()) / std
    alerts = []
    bin_td = pd.tseries.frequencies.to_offset(cfg["bin"])
    for ts in z[z > cfg["zscore"]].index:
        window = df[(df["ts"] >= ts) & (df["ts"] < ts + bin_td)]
        top_ip = window["ip"].value_counts().idxmax() if not window.empty else "-"
        alerts.append(Alert(
            rule=f"Traffic spike ({label})",
            severity="high" if z[ts] > 2 * cfg["zscore"] else "medium",
            ip=top_ip,
            description=f"{int(counts[ts])} events in one {cfg['bin']} bin "
                        f"(z-score {z[ts]:.1f}, mean {counts.mean():.1f}); top source shown",
            mitre="-",
            count=int(counts[ts]),
            first_seen=ts,
            last_seen=ts + bin_td,
        ))
    return alerts


def detect_offhours_logins(df: pd.DataFrame, cfg: dict) -> list[Alert]:
    """Successful logins during unusual hours."""
    hours = set(cfg["hours"])
    ok = df[df["event"].isin(["Accepted password", "Accepted publickey"])]
    ok = ok[ok["ts"].dt.hour.isin(hours)]
    alerts = []
    for (ip, user), grp in ok.groupby(["ip", "user"]):
        alerts.append(Alert(
            rule="Off-hours login",
            severity="low",
            ip=ip,
            description=f"User '{user}' logged in {len(grp)}x between "
                        f"{min(hours):02d}:00 and {max(hours) + 1:02d}:00",
            mitre="-",
            count=len(grp),
            first_seen=grp["ts"].min(),
            last_seen=grp["ts"].max(),
        ))
    return alerts
