from datetime import datetime, timedelta
from pathlib import Path

import detector

SAMPLES = Path(__file__).resolve().parent.parent / "brute-force-detector" / "samples"


def _ev(seconds, ip="203.0.113.10", user="root", success=False):
    base = datetime(2026, 1, 1, 12, 0, 0)
    return detector.AuthEvent(base + timedelta(seconds=seconds), ip, user, success, "ssh")


def test_sliding_window_counts_burst():
    ts = [datetime(2026, 1, 1) + timedelta(seconds=s) for s in (0, 10, 20, 30, 200, 205)]
    assert detector.max_events_in_window(ts, 60) == 4


def test_brute_force_medium():
    events = [_ev(i) for i in range(10)]
    alerts = detector.detect(events, threshold=5, window=60)
    assert len(alerts) == 1
    assert alerts[0].severity == "MEDIUM"
    assert alerts[0].technique == "T1110.001"


def test_below_threshold_no_alert():
    events = [_ev(i * 120) for i in range(4)]
    assert detector.detect(events, threshold=5, window=60) == []


def test_password_spraying_high():
    events = [_ev(i * 30, user=f"user{i}") for i in range(6)]
    alerts = detector.detect(events, threshold=50, window=60, spray_users=5)
    assert alerts[0].severity == "HIGH"
    assert alerts[0].technique == "T1110.003"


def test_success_after_failures_is_critical():
    events = [_ev(i) for i in range(8)] + [_ev(9, success=True)]
    alert = detector.detect(events)[0]
    assert alert.severity == "CRITICAL"
    assert alert.compromised_users == ["root"]


def test_auth_log_sample():
    events = detector.parse_auth_log(SAMPLES / "auth.log", 2026)
    alerts = {a.source_ip: a for a in detector.detect(events)}
    assert alerts["203.0.113.45"].severity == "CRITICAL"
    assert alerts["198.51.100.23"].severity == "HIGH"
    assert alerts["192.168.56.101"].severity == "MEDIUM"
    assert "192.168.56.1" not in alerts  # erro de digitação legítimo não alerta


def test_windows_csv_sample():
    events = detector.parse_windows_csv(SAMPLES / "windows_security.csv")
    alerts = {a.source_ip: a for a in detector.detect(events)}
    assert alerts["192.168.56.102"].compromised_users == ["helpdesk"]
    assert alerts["192.168.56.101"].severity == "MEDIUM"
