#!/usr/bin/env python3
"""Generate fake logs with injected attacks, to test the detectors.

    python tools/generate_logs.py --type ssh    --out sample_logs/auth.log
    python tools/generate_logs.py --type apache --out sample_logs/access.log

All IPs come from the documentation ranges (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24), so no real address is ever involved.

Injected attacks (ssh):
  198.51.100.23  brute force on root (120 attempts in ~4 minutes)
  203.0.113.77   username enumeration (40 different usernames)
  203.0.113.99   brute force on 'admin' followed by a SUCCESSFUL login
  192.0.2.10     legitimate user logging in at 03:12 (off-hours)
Injected attacks (apache):
  203.0.113.5    sqlmap: SQLi / XSS / path traversal payloads, traffic spike
  198.51.100.9   nikto-style scan of sensitive paths (many 404s)
  192.0.2.200    curl hammering an API (bulk scripted requests)
"""
from __future__ import annotations

import argparse
import random
from datetime import datetime, timedelta

START = datetime(2026, 10, 10, 0, 0, 0)  # the logs are meant to be parsed with --year 2026

WORDLIST = ["root", "admin", "test", "oracle", "ubuntu", "postgres", "git", "ftp", "user",
            "guest", "pi", "jenkins", "hadoop", "mysql", "tomcat", "nagios", "www", "deploy",
            "support", "webmaster", "info", "mail", "backup", "dev", "demo", "student"] + \
           [f"user{i}" for i in range(14)]


def _ssh_line(dt: datetime, msg: str, rng: random.Random) -> str:
    return f"{dt:%b} {dt.day:>2} {dt:%H:%M:%S} labhost sshd[{rng.randint(1000, 30000)}]: {msg}"


def generate_ssh(seed: int = 42) -> list[str]:
    rng = random.Random(seed)
    events: list[tuple[datetime, str]] = []

    def add(dt, msg):
        events.append((dt, _ssh_line(dt, msg, rng)))

    def port():
        return rng.randint(30000, 60000)

    def fail(dt, ip, user, valid=True):
        if not valid:
            add(dt, f"Invalid user {user} from {ip}")
            add(dt, f"Failed password for invalid user {user} from {ip} port {port()} ssh2")
        else:
            add(dt, f"Failed password for {user} from {ip} port {port()} ssh2")

    # --- normal traffic over 48 hours: business-hour logins and rare typos
    users = {"alice": "192.0.2.10", "bob": "192.0.2.11", "carol": "192.0.2.12"}
    for day in range(2):
        for user, ip in users.items():
            for _ in range(rng.randint(2, 4)):
                dt = START + timedelta(days=day, hours=rng.randint(8, 17),
                                       minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
                if rng.random() < 0.2:
                    fail(dt - timedelta(seconds=5), ip, user)  # a single typo
                add(dt, f"Accepted publickey for {user} from {ip} port {port()} ssh2")
    # --- off-hours legitimate login
    add(START + timedelta(hours=3, minutes=12), f"Accepted password for alice from 192.0.2.10 port {port()} ssh2")

    # --- attack 1: brute force on root
    t = START + timedelta(hours=14)
    for i in range(120):
        fail(t + timedelta(seconds=2 * i), "198.51.100.23", "root")

    # --- attack 2: enumeration, 40 different usernames
    t = START + timedelta(days=1, hours=9)
    for i, name in enumerate(WORDLIST[:40]):
        fail(t + timedelta(seconds=10 * i), "203.0.113.77", name, valid=name in ("root", "admin"))

    # --- attack 3: brute force then success
    t = START + timedelta(days=1, hours=20)
    for i in range(30):
        fail(t + timedelta(seconds=i), "203.0.113.99", "admin")
    add(t + timedelta(seconds=31), f"Accepted password for admin from 203.0.113.99 port {port()} ssh2")

    events.sort(key=lambda e: e[0])
    return [line for _, line in events]


def _apache_line(dt, ip, path, status, ua, method="GET", size=None, rng=None):
    size = size if size is not None else (rng.randint(200, 5000) if rng else 512)
    return (f'{ip} - - [{dt:%d/%b/%Y:%H:%M:%S} +0000] "{method} {path} HTTP/1.1" '
            f'{status} {size} "-" "{ua}"')


def generate_apache(seed: int = 42) -> list[str]:
    rng = random.Random(seed)
    events: list[tuple[datetime, str]] = []
    browser = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"

    def add(dt, ip, path, status, ua, **kw):
        events.append((dt, _apache_line(dt, ip, path, status, ua, rng=rng, **kw)))

    # --- normal traffic over 24 hours, with a few legit 404s
    pages = ["/", "/index.html", "/about", "/products", "/contact", "/blog", "/static/app.css"]
    for _ in range(1500):
        dt = START + timedelta(seconds=rng.randint(0, 86399))
        ip = f"192.0.2.{rng.randint(20, 120)}"
        if rng.random() < 0.02:
            add(dt, ip, "/old-page", 404, browser)
        else:
            add(dt, ip, rng.choice(pages), 200, browser)

    # --- attack 1: sqlmap with injection payloads (also a traffic spike)
    payloads = [
        "/product?id=1%27%20OR%201%3D1--",
        "/product?id=1%20UNION%20SELECT%20username,password%20FROM%20users",
        "/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
        "/download?file=../../etc/passwd",
        "/download?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd",
        "/product?id=1;%20cat%20/etc/passwd",
    ]
    t = START + timedelta(hours=13, minutes=55)
    for i in range(240):
        add(t + timedelta(milliseconds=500 * i), "203.0.113.5",
            payloads[i % len(payloads)], rng.choice([200, 404, 500]), "sqlmap/1.7#stable")

    # --- attack 2: nikto-style scan, lots of 404s on sensitive paths
    scan_paths = ["/.env", "/.git/config", "/phpmyadmin/", "/wp-login.php", "/wp-admin/",
                  "/xmlrpc.php", "/admin/", "/server-status", "/cgi-bin/test.cgi",
                  "/backup.zip", "/config.php", "/login.php"]
    t = START + timedelta(hours=3, minutes=20)
    for i in range(96):
        add(t + timedelta(seconds=i // 2), "198.51.100.9", scan_paths[i % len(scan_paths)],
            404, "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:Port Check)")

    # --- attack 3: curl hammering an API, spread over the day
    for i in range(150):
        add(START + timedelta(minutes=9 * i), "192.0.2.200", "/api/data", 200, "curl/8.4.0")

    events.sort(key=lambda e: e[0])
    return [line for _, line in events]


def main(argv=None) -> None:
    p = argparse.ArgumentParser(description="Generate fake logs with injected attacks")
    p.add_argument("--type", required=True, choices=["ssh", "apache"])
    p.add_argument("--out", required=True)
    p.add_argument("--seed", type=int, default=42)
    args = p.parse_args(argv)
    lines = generate_ssh(args.seed) if args.type == "ssh" else generate_apache(args.seed)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"Wrote {len(lines)} lines to {args.out}")


if __name__ == "__main__":
    main()
