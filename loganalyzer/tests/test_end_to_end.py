from pathlib import Path

import main as cli
from tools.generate_logs import generate_apache, generate_ssh

CONFIG = str(Path(__file__).resolve().parent.parent / "config.yaml")


def _run(tmp_path, kind, lines, extra=()):
    log = tmp_path / f"{kind}.log"
    log.write_text("\n".join(lines) + "\n")
    report = tmp_path / "report.html"
    rc = cli.main(["--file", str(log), "--type", kind, "--year", "2026",
                   "--config", CONFIG, "--report", str(report), *extra])
    assert rc == 0
    return report.read_text(encoding="utf-8")


def test_ssh_end_to_end_finds_injected_attacks(tmp_path):
    html = _run(tmp_path, "ssh", generate_ssh())
    assert "198.51.100.23" in html                       # brute force on root
    assert "203.0.113.77" in html                        # enumeration
    assert "Successful login after brute force" in html  # 203.0.113.99
    assert "Off-hours login" in html
    assert "T1110.001" in html and "T1110.003" in html


def test_ssh_legit_users_not_flagged(tmp_path):
    html = _run(tmp_path, "ssh", generate_ssh())
    # bob and carol only mistype once in a while: must never be reported as attackers
    assert "192.0.2.11" not in html.split("<h2>Activity over time</h2>")[0]
    assert "192.0.2.12" not in html.split("<h2>Activity over time</h2>")[0]


def test_apache_end_to_end_finds_injected_attacks(tmp_path):
    html = _run(tmp_path, "apache", generate_apache())
    assert "Attack payload in URL" in html and "203.0.113.5" in html
    assert "Attack tool user-agent" in html
    assert "198.51.100.9" in html                        # nikto scan
    assert "Bulk scripted requests" in html              # 192.0.2.200 curl
    assert "Traffic spike" in html


def test_empty_log_returns_error(tmp_path):
    log = tmp_path / "empty.log"
    log.write_text("nothing useful here\n")
    assert cli.main(["--file", str(log), "--type", "ssh", "--config", CONFIG]) == 1
