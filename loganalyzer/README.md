# LogAnalyzer

Command-line tool that parses SSH (`auth.log`) and Apache/Nginx (`access.log`) logs, applies
configurable detection rules, and produces an alert list plus a self-contained HTML report
(charts, MITRE ATT&CK mapping, optional attacker map).

```
python main.py --file sample_logs/auth.log --type ssh --year 2026 --report report.html
```

## Install

```
python -m venv .venv && source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

| Option | Meaning |
|---|---|
| `--file` | log file to analyze |
| `--type` | `ssh` or `apache` |
| `--year` | year of an SSH log (syslog timestamps have none; default: current year) |
| `--config` | thresholds file (default `config.yaml`) |
| `--report` | write an HTML report to this path |
| `--geoip-db` | path to `GeoLite2-City.mmdb`, enables locations and the map |

## Architecture

```
loganalyzer/
├── parsers/       ssh_parser.py, apache_parser.py   -> pandas DataFrame
├── detectors/     bruteforce.py, scanning.py, anomaly.py, util.py
├── enrichment/    geoip.py                          (optional GeoLite2)
├── reporting/     charts.py, html_report.py
├── tools/         generate_logs.py                  (fake logs with injected attacks)
├── tests/         pytest
├── sample_logs/
├── config.yaml    all thresholds
├── models.py      Alert dataclass
└── main.py        CLI
```

## Detection rules

| Rule | Logic | MITRE |
|---|---|---|
| SSH brute force | >= N failed logins from one IP in a sliding window of T seconds | T1110.001 |
| Enumeration / spraying | one IP tries >= N distinct usernames | T1110.003 |
| Success after guessing | accepted login from an IP with >= N earlier failures (most critical) | T1110 |
| Off-hours login | accepted login in configured night hours | - |
| Web scanning | many 403/404 from one IP in a window; hits on sensitive paths | T1595 |
| Attack payloads | SQLi, XSS, path traversal, command injection in the URL (decoded twice) | T1190 |
| Suspicious user-agent | sqlmap, nikto, hydra, nmap...; curl and similar only in bulk | T1595 |
| Traffic spikes | time bins with z-score above threshold | - |

## Testing

```
pytest                      # unit + end-to-end tests
python tools/generate_logs.py --type ssh    --out sample_logs/auth.log
python tools/generate_logs.py --type apache --out sample_logs/access.log
python main.py --file sample_logs/auth.log   --type ssh --year 2026 --report report_ssh.html
python main.py --file sample_logs/access.log --type apache          --report report_web.html
```

Real data: the SSH and Apache sets from [Loghub](https://github.com/logpai/loghub)
(Loghub SSH timestamps are from December, pass the matching `--year`).
You can also attack your own Juice Shop / Apache with nmap, nikto or hydra and analyze the logs.

## GeoIP (optional)

Register for a free MaxMind account, download `GeoLite2-City.mmdb`, then add
`--geoip-db /path/to/GeoLite2-City.mmdb`. Without it the report simply omits the map.

## Limitations

- IPv4 only for SSH; IPv6 addresses in `auth.log` are not parsed.
- Detection is per source IP: attackers behind NAT can cause false positives, and a distributed
  attack that stays under the threshold on each IP is missed.
- Syslog has no year; a log spanning more than one year boundary is not handled.
- z-score spike detection needs enough time bins (`min_bins`) and is skewed by very large spikes.
- Only password / publickey SSH events are parsed; other sshd messages are ignored.
- Thresholds in `config.yaml` are sensible defaults, not tuned for your environment.
