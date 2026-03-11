from datetime import datetime
from src.alerts.notifier import AlertNotifier
from src.analyzer.threat_analyzer import ThreatEvent


def make_event(
    threat_type="ddos",
    severity="high",
    src_ip="1.2.3.4",
    description="DDoS detected"
):
    return ThreatEvent(
        threat_type=threat_type,
        severity=severity,
        src_ip=src_ip,
        description=description,
        timestamp=datetime(2024, 1, 1, 12, 0, 0),
        details={"count": 100},
    )


def test_should_filter_low_severity():
    notifier = AlertNotifier({
        "enabled": True,
        "min_severity": "high"
    })

    assert notifier._should_alert(make_event(severity="low")) is False
    assert notifier._should_alert(make_event(severity="high")) is True
    assert notifier._should_alert(make_event(severity="critical")) is True


def test_format_message_contains_fields():
    notifier = AlertNotifier({"enabled": True})
    msg = notifier._format_message([make_event()])

    assert "SOC Threat Alert" in msg
    assert "ddos" in msg
    assert "high" in msg
    assert "1.2.3.4" in msg


def test_duplicate_detection():
    notifier = AlertNotifier({
        "enabled": True,
        "dedup_seconds": 300
    })
    event = make_event()

    assert notifier._is_duplicate(event) is False
    notifier._mark_sent(event)
    assert notifier._is_duplicate(event) is True
