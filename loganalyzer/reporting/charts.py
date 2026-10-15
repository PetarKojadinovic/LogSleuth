"""Matplotlib charts returned as base64 PNG strings (embedded straight into the HTML)."""
from __future__ import annotations

import base64
import io

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

BLUE, RED = "#2563eb", "#dc2626"


def _to_b64(fig) -> str:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=110, bbox_inches="tight")
    plt.close(fig)
    return base64.b64encode(buf.getvalue()).decode("ascii")


def chart_timeline(counts: pd.Series, title: str, zscore: float = 3.0) -> str:
    fig, ax = plt.subplots(figsize=(9, 3.2))
    if len(counts):
        std = counts.std(ddof=0)
        z = (counts - counts.mean()) / std if std else counts * 0
        colors = [RED if v > zscore else BLUE for v in z]
        width = (counts.index[1] - counts.index[0]) * 0.9 if len(counts) > 1 else pd.Timedelta(minutes=30)
        ax.bar(counts.index, counts.values, width=width, color=colors)
    ax.set_title(title)
    ax.set_ylabel("events")
    ax.grid(axis="y", alpha=0.3)
    fig.autofmt_xdate()
    return _to_b64(fig)


def chart_top(series: pd.Series, title: str, xlabel: str = "count", n: int = 10) -> str:
    top = series.head(n)[::-1]
    fig, ax = plt.subplots(figsize=(6, 3.4))
    ax.barh([str(i) for i in top.index], top.values, color=BLUE)
    ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.grid(axis="x", alpha=0.3)
    return _to_b64(fig)
