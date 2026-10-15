from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Optional

import pandas as pd

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


@dataclass
class Alert:
    rule: str
    severity: str  # low / medium / high
    ip: str
    description: str
    mitre: str = "-"
    count: int = 0
    first_seen: Optional[pd.Timestamp] = None
    last_seen: Optional[pd.Timestamp] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["first_seen"] = str(self.first_seen) if self.first_seen is not None else ""
        d["last_seen"] = str(self.last_seen) if self.last_seen is not None else ""
        return d


def sort_alerts(alerts: list[Alert]) -> list[Alert]:
    return sorted(
        alerts,
        key=lambda a: (SEVERITY_ORDER.get(a.severity, 9), -a.count, a.ip),
    )
