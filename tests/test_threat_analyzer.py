"""
Tests for Threat Analyzer detectors
Run with: pytest tests/ -v
"""

import pytest
from datetime import datetime, timedelta
from src.analyzer.threat_analyzer import (
    ThreatAnalyzer, LogEntry,
    DDoSDetector, PortScanDetector, BruteForceDetector, AnomalyDetector,
)


def make_entry(src_ip="1.2.3.4", dst_port=80, status_code=200,
               bytes_sent=512, offset_seconds=0):
    return LogEntry(
        timestamp=datetime(2024, 1, 1, 12, 0, 0) + timedelta(seconds=offset_seconds),
        src_ip=src_ip,
        dst_ip="10.0.0.1",
        dst_port=dst_port,
        protocol="TCP",
        status_code=status_code,
        bytes_sent=bytes_sent,
    )


# ── DDoS ──────────────────────────────────────────────────────────────────────

class TestDDoSDetector:
    def test_no_threat_below_threshold(self):
        d = DDoSDetector(threshold=10, window_seconds=60)
        for i in range(9):
            assert d.analyze(make_entry(offset_seconds=i)) is None

    def test_triggers_at_threshold(self):
        d = DDoSDetector(threshold=10, window_seconds=60)
        event = None
        for i in range(10):
            event = d.analyze(make_entry(offset_seconds=i))
        assert event is not None
        assert event.threat_type == "ddos"
        assert event.severity in ("high", "critical")

    def test_sliding_window_resets(self):
        d = DDoSDetector(threshold=5, window_seconds=10)
        # 5 requests in window → triggers
        for i in range(5):
            d.analyze(make_entry(offset_seconds=i))
        # 70 seconds later, same IP — window should have cleared
        event = d.analyze(make_entry(offset_seconds=70))
        assert event is None

    def test_critical_severity_at_double_threshold(self):
        d = DDoSDetector(threshold=10, window_seconds=60)
        event = None
        for i in range(20):
            event = d.analyze(make_entry(offset_seconds=i))
        assert event.severity == "critical"


# ── Port Scan ─────────────────────────────────────────────────────────────────

class TestPortScanDetector:
    def test_no_threat_few_ports(self):
        d = PortScanDetector(unique_port_threshold=5, window_seconds=30)
        for port in [80, 443, 8080]:
            assert d.analyze(make_entry(dst_port=port)) is None

    def test_triggers_on_many_unique_ports(self):
        d = PortScanDetector(unique_port_threshold=5, window_seconds=30)
        event = None
        for port in range(1000, 1006):
            event = d.analyze(make_entry(dst_port=port, offset_seconds=0))
        assert event is not None
        assert event.threat_type == "port_scan"
        assert len(event.details["unique_ports"]) >= 5

    def test_different_ips_dont_interfere(self):
        d = PortScanDetector(unique_port_threshold=3, window_seconds=30)
        for port in range(1000, 1004):
            d.analyze(make_entry(src_ip="9.9.9.9", dst_port=port))
        # Different IP should NOT trigger
        result = d.analyze(make_entry(src_ip="5.5.5.5", dst_port=9999))
        assert result is None


# ── Brute Force ───────────────────────────────────────────────────────────────

class TestBruteForceDetector:
    def test_no_trigger_on_success(self):
        d = BruteForceDetector(failure_threshold=5, window_seconds=60)
        for i in range(10):
            assert d.analyze(make_entry(dst_port=22, status_code=200, offset_seconds=i)) is None

    def test_triggers_on_auth_failures(self):
        d = BruteForceDetector(failure_threshold=5, window_seconds=60)
        event = None
        for i in range(5):
            event = d.analyze(make_entry(dst_port=22, status_code=401, offset_seconds=i))
        assert event is not None
        assert event.threat_type == "brute_force"

    def test_ignores_non_watched_port(self):
        d = BruteForceDetector(failure_threshold=3, window_seconds=60, watched_ports=(22,))
        for i in range(5):
            result = d.analyze(make_entry(dst_port=9999, status_code=401, offset_seconds=i))
        assert result is None


# ── Anomaly ───────────────────────────────────────────────────────────────────

class TestAnomalyDetector:
    def test_large_payload_triggers(self):
        d = AnomalyDetector(large_payload_bytes=1000)
        event = d.analyze(make_entry(bytes_sent=5000))
        assert event is not None
        assert event.threat_type == "anomaly"

    def test_external_ip_on_db_port_triggers(self):
        d = AnomalyDetector()
        # 8.8.8.8 is external; 3306 is MySQL
        entry = make_entry(src_ip="8.8.8.8", dst_port=3306)
        event = d.analyze(entry)
        assert event is not None
        assert "internal service" in event.description

    def test_internal_ip_on_db_port_no_trigger(self):
        d = AnomalyDetector()
        entry = make_entry(src_ip="192.168.1.50", dst_port=3306)
        event = d.analyze(entry)
        assert event is None


# ── Full Analyzer ─────────────────────────────────────────────────────────────

class TestThreatAnalyzer:
    def test_empty_log_returns_no_threats(self):
        ta = ThreatAnalyzer()
        assert ta.analyze_batch([]) == []

    def test_summary_reflects_detected_threats(self):
        ta = ThreatAnalyzer(config={"ddos_threshold": 5, "ddos_window": 60})
        for i in range(5):
            ta.analyze(make_entry(offset_seconds=i))
        summary = ta.get_summary()
        assert "ddos" in summary

    def test_clear_threat_log(self):
        ta = ThreatAnalyzer(config={"ddos_threshold": 3, "ddos_window": 60})
        for i in range(3):
            ta.analyze(make_entry(offset_seconds=i))
        assert len(ta.threat_log) > 0
        ta.threat_log.clear()
        assert len(ta.threat_log) == 0