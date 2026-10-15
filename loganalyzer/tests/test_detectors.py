from datetime import datetime, timedelta

import pandas as pd

from detectors import anomaly, bruteforce, scanning

T0 = datetime(2026, 10, 10, 12, 0, 0)


def ssh_df(rows):
    """rows: (seconds_offset, event, user, ip)"""
    df = pd.DataFrame(
        [(T0 + timedelta(seconds=s), e, u, ip) for s, e, u, ip in rows],
        columns=["ts", "event", "user", "ip"],
    )
    return df.sort_values("ts").reset_index(drop=True)


def web_df(rows):
    """rows: (seconds_offset, ip, path, status, ua)"""
    df = pd.DataFrame(
        [(T0 + timedelta(seconds=s), ip, "GET", p, st, 100, "-", ua) for s, ip, p, st, ua in rows],
        columns=["ts", "ip", "method", "path", "status", "size", "referer", "ua"],
    )
    return df.sort_values("ts").reset_index(drop=True)


BF = {"max_attempts": 5, "window_seconds": 60}
ENUM = {"min_distinct_users": 5}
SAF = {"min_failures": 5, "lookback_minutes": 60}


# ---------------------------------------------------------------- SSH
def test_bruteforce_detected():
    df = ssh_df([(i, "Failed password", "root", "1.1.1.1") for i in range(5)])
    alerts = bruteforce.detect_bruteforce(df, BF)
    assert len(alerts) == 1
    assert alerts[0].ip == "1.1.1.1" and alerts[0].mitre == "T1110.001"
    assert alerts[0].severity == "medium"


def test_bruteforce_below_threshold_not_detected():
    df = ssh_df([(i, "Failed password", "root", "1.1.1.1") for i in range(4)])
    assert bruteforce.detect_bruteforce(df, BF) == []


def test_bruteforce_respects_sliding_window():
    # 5 failures, but never more than 3 inside any 60 s window
    df = ssh_df([(i * 30, "Failed password", "root", "1.1.1.1") for i in range(5)])
    assert bruteforce.detect_bruteforce(df, BF) == []


def test_bruteforce_high_severity_and_per_ip():
    rows = [(i, "Failed password", "root", "1.1.1.1") for i in range(20)]
    rows += [(i, "Failed password", "root", "2.2.2.2") for i in range(2)]
    alerts = bruteforce.detect_bruteforce(ssh_df(rows), BF)
    assert [a.ip for a in alerts] == ["1.1.1.1"]
    assert alerts[0].severity == "high"


def test_enumeration_detected():
    users = ["a", "b", "c", "d", "e", "f"]
    df = ssh_df([(i, "Failed password", u, "1.1.1.1") for i, u in enumerate(users)])
    alerts = bruteforce.detect_enumeration(df, ENUM)
    assert len(alerts) == 1 and alerts[0].mitre == "T1110.003"


def test_enumeration_same_user_not_detected():
    df = ssh_df([(i, "Failed password", "root", "1.1.1.1") for i in range(10)])
    assert bruteforce.detect_enumeration(df, ENUM) == []


def test_success_after_failures_detected():
    rows = [(i, "Failed password", "admin", "1.1.1.1") for i in range(6)]
    rows.append((10, "Accepted password", "admin", "1.1.1.1"))
    alerts = bruteforce.detect_success_after_failures(ssh_df(rows), SAF)
    assert len(alerts) == 1
    assert alerts[0].severity == "high" and alerts[0].count == 6


def test_success_without_prior_failures_ignored():
    df = ssh_df([(0, "Accepted publickey", "alice", "9.9.9.9")])
    assert bruteforce.detect_success_after_failures(df, SAF) == []


def test_success_from_different_ip_ignored():
    rows = [(i, "Failed password", "admin", "1.1.1.1") for i in range(6)]
    rows.append((10, "Accepted password", "admin", "2.2.2.2"))
    assert bruteforce.detect_success_after_failures(ssh_df(rows), SAF) == []


def test_success_outside_lookback_ignored():
    rows = [(i, "Failed password", "admin", "1.1.1.1") for i in range(6)]
    rows.append((3 * 3600, "Accepted password", "admin", "1.1.1.1"))
    assert bruteforce.detect_success_after_failures(ssh_df(rows), SAF) == []


def test_offhours_login():
    cfg = {"hours": [0, 1, 2, 3, 4, 5]}
    night = pd.DataFrame(
        [(datetime(2026, 10, 10, 3, 12), "Accepted password", "alice", "1.1.1.1"),
         (datetime(2026, 10, 10, 14, 0), "Accepted password", "bob", "2.2.2.2")],
        columns=["ts", "event", "user", "ip"])
    alerts = anomaly.detect_offhours_logins(night, cfg)
    assert [a.ip for a in alerts] == ["1.1.1.1"]


# ---------------------------------------------------------------- web
SCAN = {"max_errors": 15, "window_seconds": 60,
        "sensitive_paths": ["/.env", "/phpmyadmin", "/wp-login.php"]}
UA = {"tools": ["sqlmap", "nikto"], "bulk_tools": ["curl"], "bulk_min": 100}


def test_web_scanning_many_404():
    df = web_df([(i, "1.1.1.1", f"/x{i}", 404, "Mozilla") for i in range(20)])
    alerts = scanning.detect_web_scanning(df, SCAN)
    assert any(a.rule.startswith("Web scanning") and a.ip == "1.1.1.1" for a in alerts)


def test_web_few_404_not_flagged():
    df = web_df([(i, "1.1.1.1", f"/x{i}", 404, "Mozilla") for i in range(5)])
    assert scanning.detect_web_scanning(df, SCAN) == []


def test_sensitive_path_single_hit_is_low():
    df = web_df([(0, "1.1.1.1", "/.env", 404, "Mozilla")])
    alerts = scanning.detect_web_scanning(df, SCAN)
    assert len(alerts) == 1 and alerts[0].severity == "low"


def test_attack_patterns_detected():
    paths = [
        "/p?id=1%27%20OR%201%3D1--",
        "/p?id=1%20UNION%20SELECT%20a,b%20FROM%20t",
        "/s?q=%3Cscript%3Ealert(1)%3C/script%3E",
        "/d?f=../../etc/passwd",
        "/d?f=%252e%252e%252fetc%252fpasswd",
    ]
    df = web_df([(i, "6.6.6.6", p, 200, "Mozilla") for i, p in enumerate(paths)])
    alerts = scanning.detect_attack_patterns(df)
    assert len(alerts) == 1
    assert alerts[0].count == 5 and alerts[0].severity == "high" and alerts[0].mitre == "T1190"


def test_clean_urls_not_flagged_as_attacks():
    df = web_df([(0, "1.1.1.1", "/products?id=42&sort=price", 200, "Mozilla"),
                 (1, "1.1.1.1", "/blog/how-to-select-a-union", 200, "Mozilla")])
    assert scanning.detect_attack_patterns(df) == []


def test_suspicious_user_agent_tool():
    df = web_df([(0, "1.1.1.1", "/", 200, "sqlmap/1.7"), (1, "2.2.2.2", "/", 200, "Mozilla")])
    alerts = scanning.detect_suspicious_ua(df, UA)
    assert [a.ip for a in alerts] == ["1.1.1.1"]


def test_curl_only_flagged_in_bulk():
    few = web_df([(i, "1.1.1.1", "/", 200, "curl/8.0") for i in range(10)])
    many = web_df([(i, "1.1.1.1", "/", 200, "curl/8.0") for i in range(120)])
    assert scanning.detect_suspicious_ua(few, UA) == []
    assert len(scanning.detect_suspicious_ua(many, UA)) == 1


# ---------------------------------------------------------------- anomaly
SPIKE = {"bin": "1min", "zscore": 3.0, "min_bins": 10}


def test_rate_spike_detected():
    rows = [(m * 60, "1.1.1.1", "/", 200, "Mozilla") for m in range(60)]
    rows += [(30 * 60 + 1 + i * 0.1, "9.9.9.9", "/", 200, "Mozilla") for i in range(100)]
    alerts = anomaly.detect_rate_spikes(web_df(rows), SPIKE, "web")
    assert len(alerts) == 1
    assert alerts[0].ip == "9.9.9.9"


def test_flat_traffic_has_no_spike():
    rows = [(m * 60, "1.1.1.1", "/", 200, "Mozilla") for m in range(60)]
    assert anomaly.detect_rate_spikes(web_df(rows), SPIKE, "web") == []


def test_too_few_bins_no_spike():
    rows = [(0, "1.1.1.1", "/", 200, "Mozilla")] * 50
    assert anomaly.detect_rate_spikes(web_df(rows), SPIKE, "web") == []
