from datetime import datetime

from parsers import apache_parser, ssh_parser

LOGHUB_FAIL_INVALID = ("Dec 10 06:55:46 LabSZ sshd[24200]: Failed password for invalid user "
                       "webmaster from 173.234.31.186 port 38926 ssh2")
FAIL_VALID = "Dec 10 06:56:00 LabSZ sshd[24201]: Failed password for root from 10.0.0.5 port 22 ssh2"
INVALID_USER = "Dec 10 06:55:45 LabSZ sshd[24200]: Invalid user webmaster from 173.234.31.186"
ACCEPTED = "Dec 10 07:00:00 LabSZ sshd[24300]: Accepted password for alice from 10.0.0.6 port 5000 ssh2"
NOISE = "Dec 10 06:55:46 LabSZ sshd[24200]: pam_unix(sshd:auth): check pass; user unknown"


def test_ssh_failed_password_invalid_user():
    df = ssh_parser.parse_lines([LOGHUB_FAIL_INVALID], year=2026)
    assert len(df) == 1
    row = df.iloc[0]
    assert row["event"] == "Failed password"
    assert row["user"] == "webmaster"
    assert row["ip"] == "173.234.31.186"
    assert row["ts"] == datetime(2026, 12, 10, 6, 55, 46)


def test_ssh_all_event_types_and_noise_skipped():
    df = ssh_parser.parse_lines([NOISE, INVALID_USER, FAIL_VALID, ACCEPTED], year=2026)
    assert list(df["event"]) == ["Invalid user", "Failed password", "Accepted password"]
    assert list(df["user"]) == ["webmaster", "root", "alice"]


def test_ssh_padded_day():
    line = "Oct  5 01:02:03 host sshd[1]: Failed password for bob from 1.2.3.4 port 1 ssh2"
    df = ssh_parser.parse_lines([line], year=2026)
    assert df.iloc[0]["ts"] == datetime(2026, 10, 5, 1, 2, 3)


def test_ssh_year_rollover():
    lines = [
        "Dec 31 23:59:59 h sshd[1]: Failed password for a from 1.1.1.1 port 1 ssh2",
        "Jan  1 00:00:01 h sshd[1]: Failed password for a from 1.1.1.1 port 1 ssh2",
    ]
    df = ssh_parser.parse_lines(lines, year=2026)
    assert df["ts"].iloc[0].year == 2026
    assert df["ts"].iloc[1].year == 2027


def test_ssh_empty_input_gives_empty_frame_with_columns():
    df = ssh_parser.parse_lines(["garbage"], year=2026)
    assert df.empty
    assert list(df.columns) == ssh_parser.COLUMNS


APACHE = ('203.0.113.5 - - [10/Oct/2026:13:55:36 +0200] "GET /wp-login.php HTTP/1.1" '
          '404 512 "-" "sqlmap/1.7"')


def test_apache_combined_line_and_utc_conversion():
    df = apache_parser.parse_lines([APACHE])
    row = df.iloc[0]
    assert row["ip"] == "203.0.113.5"
    assert row["method"] == "GET"
    assert row["path"] == "/wp-login.php"
    assert row["status"] == 404
    assert row["size"] == 512
    assert row["ua"] == "sqlmap/1.7"
    assert row["ts"] == datetime(2026, 10, 10, 11, 55, 36)  # +0200 -> UTC


def test_apache_dash_size_and_malformed_lines():
    ok = '1.2.3.4 - - [10/Oct/2026:13:55:36 +0000] "GET / HTTP/1.1" 304 - "-" "Mozilla"'
    bad = '1.2.3.4 - - [10/Oct/2026:13:55:36 +0000] "-" 408 - "-" "-"'
    df = apache_parser.parse_lines([ok, bad, "not a log line"])
    assert len(df) == 1
    assert df.iloc[0]["size"] == 0
