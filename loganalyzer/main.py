#!/usr/bin/env python3
"""LogAnalyzer - detect brute force, scanning and anomalies in SSH / web logs.

Example:
    python main.py --file sample_logs/auth.log --type ssh --report report.html
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime

import pandas as pd
import yaml

from detectors import anomaly, bruteforce, scanning
from enrichment.geoip import enrich_ips
from models import Alert, sort_alerts
from parsers import apache_parser, ssh_parser


def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def analyze_ssh(df: pd.DataFrame, cfg: dict) -> list[Alert]:
    c = cfg["ssh"]
    alerts = []
    alerts += bruteforce.detect_bruteforce(df, c["bruteforce"])
    alerts += bruteforce.detect_enumeration(df, c["enumeration"])
    alerts += bruteforce.detect_success_after_failures(df, c["success_after_failures"])
    alerts += anomaly.detect_offhours_logins(df, c["offhours"])
    failed = df[df["event"] == "Failed password"]
    alerts += anomaly.detect_rate_spikes(failed, c["anomaly"], "failed SSH logins")
    return sort_alerts(alerts)


def analyze_web(df: pd.DataFrame, cfg: dict) -> list[Alert]:
    c = cfg["web"]
    alerts = []
    alerts += scanning.detect_web_scanning(df, c["scanning"])
    alerts += scanning.detect_attack_patterns(df)
    alerts += scanning.detect_suspicious_ua(df, c["suspicious_ua"])
    alerts += anomaly.detect_rate_spikes(df, c["anomaly"], "web requests")
    return sort_alerts(alerts)


def print_summary(alerts: list[Alert]) -> None:
    print(f"\n{len(alerts)} alert(s)")
    print(f"{'SEV':<7}{'IP':<17}{'RULE':<42}DETAILS")
    for a in alerts:
        print(f"{a.severity.upper():<7}{a.ip:<17}{a.rule:<42}{a.description}")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Log analysis and anomaly detection")
    p.add_argument("--file", required=True, help="path to the log file")
    p.add_argument("--type", required=True, choices=["ssh", "apache"], help="log type")
    p.add_argument("--year", type=int, default=datetime.now().year,
                   help="year of the log (syslog timestamps have none); default: current year")
    p.add_argument("--config", default="config.yaml")
    p.add_argument("--report", help="write an HTML report to this path")
    p.add_argument("--geoip-db", help="path to GeoLite2-City.mmdb (optional)")
    args = p.parse_args(argv)

    cfg = load_config(args.config)
    if args.type == "ssh":
        df = ssh_parser.parse_file(args.file, args.year)
    else:
        df = apache_parser.parse_file(args.file)

    if df.empty:
        print(f"No parsable {args.type} entries found in {args.file}", file=sys.stderr)
        return 1
    print(f"Parsed {len(df)} events from {df['ip'].nunique()} IPs "
          f"({df['ts'].min()} -> {df['ts'].max()})")

    alerts = analyze_ssh(df, cfg) if args.type == "ssh" else analyze_web(df, cfg)
    print_summary(alerts)

    if args.report:
        from reporting.html_report import generate_report
        geo = enrich_ips({a.ip for a in alerts}, args.geoip_db)
        generate_report(alerts, df, "ssh" if args.type == "ssh" else "web",
                        cfg, geo, args.report, args.file)
        print(f"\nReport written to {args.report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
