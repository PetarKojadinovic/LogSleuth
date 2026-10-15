from __future__ import annotations

import pandas as pd


def max_in_window(times: list[pd.Timestamp], window_seconds: float):
    """Largest number of events inside any sliding window of `window_seconds`.

    `times` must be sorted. Returns (count, first_ts, last_ts) of the densest window.
    """
    if not times:
        return 0, None, None
    window = pd.Timedelta(seconds=window_seconds)
    best, best_lo, best_hi, lo = 0, 0, 0, 0
    for hi, t in enumerate(times):
        while t - times[lo] > window:
            lo += 1
        if hi - lo + 1 > best:
            best, best_lo, best_hi = hi - lo + 1, lo, hi
    return best, times[best_lo], times[best_hi]
