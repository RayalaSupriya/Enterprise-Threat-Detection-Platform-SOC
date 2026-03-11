"""
Threat Analyzer Engine
Detects: DDoS attacks, port scans, brute force, anomalous traffic
"""

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Optional
import ipaddress
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────

@dataclass
class LogEntry:
    timestamp: datetime
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    status_code: Optional[int] = None
    bytes_sent: int = 0
    method: Optional[str] = None
    path: Optional[str] = None


@dataclass
class ThreatEvent:
    threat_type: str          # "ddos", "port_scan", "brute_force", "anomaly"
    severity: str             # "low", "medium", "high", "critical"
    src_ip: str
    description: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    details: dict = field(default_factory=dict)

    def to_dict(self):
        return {
            "threat_type": self.threat_type,
            "severity": self.severity,
            "src_ip": self.src_ip,
            "description": self.description,
            "timestamp": self.timestamp.isoformat(),
            "details": self.details,
        }


# ─────────────────────────────────────────────
# Threat Detection Rules
# ─────────────────────────────────────────────

class DDoSDetector:
    """
    Detects DDoS by counting requests per IP in a sliding time window.
    Triggers if an IP exceeds `threshold` requests within `window_seconds`.
    """

    def __init__(self, threshold: int = 100, window_seconds: int = 60):
        self.threshold = threshold
        self.window_seconds = window_seconds
        # ip -> deque of timestamps
        self._buckets: dict[str, deque] = defaultdict(deque)

    def analyze(self, entry: LogEntry) -> Optional[ThreatEvent]:
        now = entry.timestamp
        cutoff = now - timedelta(seconds=self.window_seconds)
        bucket = self._buckets[entry.src_ip]

        # Evict old entries
        while bucket and bucket[0] < cutoff:
            bucket.popleft()

        bucket.append(now)
        req_count = len(bucket)

        if req_count >= self.threshold:
            severity = "critical" if req_count >= self.threshold * 2 else "high"
            return ThreatEvent(
                threat_type="ddos",
                severity=severity,
                src_ip=entry.src_ip,
                description=f"DDoS detected: {req_count} requests in {self.window_seconds}s",
                timestamp=now,
                details={"request_count": req_count, "window_seconds": self.window_seconds},
            )
        return None


class PortScanDetector:
    """
    Detects port scans: single IP hitting many distinct ports in a short window.
    """

    def __init__(self, unique_port_threshold: int = 15, window_seconds: int = 30):
        self.unique_port_threshold = unique_port_threshold
        self.window_seconds = window_seconds
        # ip -> list of (timestamp, port)
        self._activity: dict[str, deque] = defaultdict(deque)

    def analyze(self, entry: LogEntry) -> Optional[ThreatEvent]:
        now = entry.timestamp
        cutoff = now - timedelta(seconds=self.window_seconds)
        activity = self._activity[entry.src_ip]

        # Evict old entries
        while activity and activity[0][0] < cutoff:
            activity.popleft()

        activity.append((now, entry.dst_port))
        unique_ports = {p for _, p in activity}

        if len(unique_ports) >= self.unique_port_threshold:
            return ThreatEvent(
                threat_type="port_scan",
                severity="high",
                src_ip=entry.src_ip,
                description=f"Port scan detected: {len(unique_ports)} unique ports in {self.window_seconds}s",
                timestamp=now,
                details={"unique_ports": sorted(unique_ports), "window_seconds": self.window_seconds},
            )
        return None


class BruteForceDetector:
    """
    Detects brute-force login attempts: many 401/403 responses from same IP.
    """

    def __init__(self, failure_threshold: int = 10, window_seconds: int = 60,
                 watched_ports: tuple = (22, 80, 443, 8080, 3306)):
        self.failure_threshold = failure_threshold
        self.window_seconds = window_seconds
        self.watched_ports = set(watched_ports)
        self._failures: dict[str, deque] = defaultdict(deque)

    def analyze(self, entry: LogEntry) -> Optional[ThreatEvent]:
        if entry.dst_port not in self.watched_ports:
            return None
        if entry.status_code not in (401, 403):
            return None

        now = entry.timestamp
        cutoff = now - timedelta(seconds=self.window_seconds)
        failures = self._failures[entry.src_ip]

        while failures and failures[0] < cutoff:
            failures.popleft()

        failures.append(now)
        failure_count = len(failures)

        if failure_count >= self.failure_threshold:
            severity = "critical" if failure_count >= self.failure_threshold * 3 else "high"
            return ThreatEvent(
                threat_type="brute_force",
                severity=severity,
                src_ip=entry.src_ip,
                description=f"Brute-force detected: {failure_count} auth failures on port {entry.dst_port}",
                timestamp=now,
                details={
                    "failure_count": failure_count,
                    "target_port": entry.dst_port,
                    "window_seconds": self.window_seconds,
                },
            )
        return None


class AnomalyDetector:
    """
    Simple statistical anomaly detector.
    Flags IPs sending unusually large payloads or from private/bogon ranges
    hitting public services.
    """

    PRIVATE_RANGES = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    ]

    def __init__(self, large_payload_bytes: int = 5_000_000):
        self.large_payload_bytes = large_payload_bytes
        self._byte_history: dict[str, deque] = defaultdict(lambda: deque(maxlen=100))

    def _is_private(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in self.PRIVATE_RANGES)
        except ValueError:
            return False

    def analyze(self, entry: LogEntry) -> Optional[ThreatEvent]:
        # Large payload anomaly
        if entry.bytes_sent >= self.large_payload_bytes:
            return ThreatEvent(
                threat_type="anomaly",
                severity="medium",
                src_ip=entry.src_ip,
                description=f"Unusually large payload: {entry.bytes_sent:,} bytes from {entry.src_ip}",
                timestamp=entry.timestamp,
                details={"bytes_sent": entry.bytes_sent, "threshold": self.large_payload_bytes},
            )

        # Suspicious: external IP hitting internal-only destination on DB port
        INTERNAL_PORTS = {3306, 5432, 27017, 6379, 9200}
        if not self._is_private(entry.src_ip) and entry.dst_port in INTERNAL_PORTS:
            return ThreatEvent(
                threat_type="anomaly",
                severity="high",
                src_ip=entry.src_ip,
                description=f"External IP accessing internal service port {entry.dst_port}",
                timestamp=entry.timestamp,
                details={"dst_port": entry.dst_port},
            )

        return None


# ─────────────────────────────────────────────
# Main Analyzer (combines all detectors)
# ─────────────────────────────────────────────

class ThreatAnalyzer:
    """
    Orchestrates all detectors. Feed log entries one at a time via `analyze()`.
    Returns a list of ThreatEvents (empty if no threats found).
    """

    def __init__(self, config: dict = None):
        cfg = config or {}
        self.detectors = [
            DDoSDetector(
                threshold=cfg.get("ddos_threshold", 100),
                window_seconds=cfg.get("ddos_window", 60),
            ),
            PortScanDetector(
                unique_port_threshold=cfg.get("portscan_threshold", 15),
                window_seconds=cfg.get("portscan_window", 30),
            ),
            BruteForceDetector(
                failure_threshold=cfg.get("bruteforce_threshold", 10),
                window_seconds=cfg.get("bruteforce_window", 60),
            ),
            AnomalyDetector(
                large_payload_bytes=cfg.get("large_payload_bytes", 5_000_000),
            ),
        ]
        self.threat_log: List[ThreatEvent] = []

    def analyze(self, entry: LogEntry) -> List[ThreatEvent]:
        """Process a single log entry through all detectors."""
        detected = []
        for detector in self.detectors:
            event = detector.analyze(entry)
            if event:
                detected.append(event)
                self.threat_log.append(event)
                logger.warning(
                    "[%s] %s | %s | %s",
                    event.severity.upper(),
                    event.threat_type,
                    event.src_ip,
                    event.description,
                )
        return detected

    def analyze_batch(self, entries: List[LogEntry]) -> List[ThreatEvent]:
        """Process a list of log entries."""
        all_events = []
        for entry in entries:
            all_events.extend(self.analyze(entry))
        return all_events

    def get_summary(self) -> dict:
        """Return aggregated threat summary."""
        summary = defaultdict(lambda: defaultdict(int))
        for event in self.threat_log:
            summary[event.threat_type][event.severity] += 1
        return {k: dict(v) for k, v in summary.items()}