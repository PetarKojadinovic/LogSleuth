"""Optional GeoIP enrichment with a MaxMind GeoLite2-City database."""
from __future__ import annotations

from pathlib import Path
from typing import Iterable


def enrich_ips(ips: Iterable[str], db_path: str | None) -> dict[str, dict]:
    """Return {ip: {country, city, lat, lon}}. Empty dict if DB or geoip2 is missing."""
    if not db_path or not Path(db_path).exists():
        return {}
    try:
        import geoip2.database
    except ImportError:
        return {}

    result: dict[str, dict] = {}
    with geoip2.database.Reader(db_path) as reader:
        for ip in set(ips):
            try:
                r = reader.city(ip)
            except Exception:  # private IP, not in DB, IPv6 etc.
                continue
            if r.location.latitude is None:
                continue
            result[ip] = {
                "country": r.country.name or "?",
                "city": r.city.name or "?",
                "lat": r.location.latitude,
                "lon": r.location.longitude,
            }
    return result
