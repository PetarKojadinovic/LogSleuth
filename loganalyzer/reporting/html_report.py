"""Self-contained HTML report (Jinja2) with summary, alerts, charts and attacker map."""
from __future__ import annotations

import html
from collections import Counter
from datetime import datetime

import pandas as pd
from jinja2 import Environment

from detectors.anomaly import rate_series
from models import Alert
from reporting.charts import chart_timeline, chart_top

TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Log analysis report</title>
<style>
 body{font-family:system-ui,sans-serif;margin:0;background:#f4f5f7;color:#1f2937}
 header{background:#111827;color:#fff;padding:24px 40px}
 header h1{margin:0 0 4px;font-size:24px} header p{margin:0;color:#9ca3af}
 main{max-width:1100px;margin:24px auto;padding:0 20px}
 .cards{display:flex;gap:16px;flex-wrap:wrap}
 .card{background:#fff;border-radius:8px;padding:16px 20px;flex:1;min-width:150px;box-shadow:0 1px 3px #0001}
 .card b{display:block;font-size:28px}
 section{background:#fff;border-radius:8px;padding:20px;margin-top:20px;box-shadow:0 1px 3px #0001}
 h2{margin-top:0;font-size:18px}
 table{border-collapse:collapse;width:100%;font-size:14px}
 th,td{text-align:left;padding:8px;border-bottom:1px solid #e5e7eb;vertical-align:top}
 th{background:#f9fafb}
 .sev{padding:2px 8px;border-radius:10px;color:#fff;font-size:12px;font-weight:600}
 .high{background:#dc2626}.medium{background:#f59e0b}.low{background:#6b7280}
 .grid{display:flex;gap:20px;flex-wrap:wrap} img{max-width:100%}
 iframe{width:100%;height:420px;border:0;border-radius:6px}
 .note{color:#6b7280;font-size:14px}
</style></head><body>
<header><h1>Log analysis report</h1>
<p>{{ source }} &middot; type: {{ kind }} &middot; generated {{ generated }}</p></header>
<main>
<div class="cards">
 <div class="card"><b>{{ total }}</b>events parsed</div>
 <div class="card"><b>{{ unique_ips }}</b>unique IPs</div>
 <div class="card"><b>{{ sev.high }}</b>high alerts</div>
 <div class="card"><b>{{ sev.medium }}</b>medium alerts</div>
 <div class="card"><b>{{ sev.low }}</b>low alerts</div>
</div>

<section><h2>Alerts</h2>
{% if alerts %}
<table><tr><th>Severity</th><th>Rule</th><th>IP</th><th>Details</th><th>Count</th><th>First seen</th><th>MITRE ATT&amp;CK</th></tr>
{% for a in alerts %}
<tr><td><span class="sev {{ a.severity }}">{{ a.severity }}</span></td><td>{{ a.rule }}</td>
<td>{{ a.ip }}{% if a.ip in geo %}<br><span class="note">{{ geo[a.ip].city }}, {{ geo[a.ip].country }}</span>{% endif %}</td>
<td>{{ a.description }}</td><td>{{ a.count }}</td><td>{{ a.first_seen }}</td>
<td>{% if a.mitre != '-' %}<a href="https://attack.mitre.org/techniques/{{ a.mitre.replace('.', '/') }}/">{{ a.mitre }}</a>{% else %}-{% endif %}</td></tr>
{% endfor %}</table>
{% else %}<p>No alerts. Nothing suspicious matched the configured thresholds.</p>{% endif %}
</section>

<section><h2>Activity over time</h2>
<img src="data:image/png;base64,{{ timeline }}" alt="timeline">
<p class="note">Red bars are z-score spikes.</p></section>

<section><h2>Top sources</h2><div class="grid">
<img src="data:image/png;base64,{{ top_ips }}" alt="top ips">
<img src="data:image/png;base64,{{ top_second }}" alt="top second">
</div></section>

<section><h2>Attacker map</h2>
{% if map_html %}<iframe srcdoc="{{ map_html }}"></iframe>
{% else %}<p class="note">No GeoIP data. Download GeoLite2-City.mmdb (free MaxMind account) and pass it with <code>--geoip-db</code>.</p>{% endif %}
</section>

<section><h2>MITRE ATT&amp;CK mapping</h2>
<table><tr><th>Technique</th><th>Alerts</th></tr>
{% for t, n in mitre %}<tr><td><a href="https://attack.mitre.org/techniques/{{ t.replace('.', '/') }}/">{{ t }}</a></td><td>{{ n }}</td></tr>{% endfor %}
</table></section>
</main></body></html>
"""


def _build_map(geo: dict, weights: pd.Series) -> str:
    if not geo:
        return ""
    import folium

    m = folium.Map(location=[20, 0], zoom_start=2, tiles="OpenStreetMap")
    for ip, g in geo.items():
        n = int(weights.get(ip, 1))
        folium.CircleMarker(
            [g["lat"], g["lon"]], radius=min(5 + n ** 0.5, 25),
            color="#dc2626", fill=True, fill_opacity=0.6,
            popup=f"{ip} - {g['city']}, {g['country']} ({n} events)",
        ).add_to(m)
    return html.escape(m.get_root().render(), quote=True)


def generate_report(alerts: list[Alert], df: pd.DataFrame, kind: str, cfg: dict,
                    geo: dict, out_path: str, source: str) -> None:
    sev = Counter(a.severity for a in alerts)
    sev_ctx = {k: sev.get(k, 0) for k in ("high", "medium", "low")}

    if kind == "ssh":
        focus = df[df["event"] == "Failed password"]
        a_cfg = cfg["ssh"]["anomaly"]
        timeline_title = "Failed SSH logins over time"
        top_ips = focus["ip"].value_counts()
        top_second = focus["user"].value_counts()
        second_title, second_x = "Most guessed usernames", "attempts"
    else:
        focus = df
        a_cfg = cfg["web"]["anomaly"]
        timeline_title = "Requests over time"
        top_ips = df["ip"].value_counts()
        top_second = df[df["status"].isin([403, 404])]["path"].value_counts()
        second_title, second_x = "Most requested missing/forbidden paths", "requests"

    counts = rate_series(focus, a_cfg["bin"]) if not focus.empty else pd.Series(dtype=int)
    mitre = Counter(a.mitre for a in alerts if a.mitre != "-").most_common()

    template = Environment(autoescape=True).from_string(TEMPLATE)
    out = template.render(
        source=source, kind=kind, generated=datetime.now().strftime("%Y-%m-%d %H:%M"),
        total=len(df), unique_ips=df["ip"].nunique() if not df.empty else 0,
        sev=sev_ctx, alerts=[a.to_dict() | {"mitre": a.mitre} for a in alerts], geo=geo,
        timeline=chart_timeline(counts, timeline_title, a_cfg["zscore"]),
        top_ips=chart_top(top_ips, "Top 10 source IPs", "events"),
        top_second=chart_top(top_second, second_title, second_x),
        map_html=_build_map(geo, top_ips), mitre=mitre,
    )
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(out)
