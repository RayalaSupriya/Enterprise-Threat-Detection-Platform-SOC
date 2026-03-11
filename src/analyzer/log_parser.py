"""
Log Parser
Converts raw log lines (Apache/Nginx/syslog) into LogEntry objects.
"""

import re
from datetime import datetime
from typing import Optional, List
from .threat_analyzer import LogEntry


# Apache/Nginx Combined Log Format
# 192.168.1.1 - - [10/Mar/2024:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 1234
APACHE_PATTERN = re.compile(
    r'(?P<src_ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" '
    r'(?P<status>\d{3}) (?P<bytes>\d+|-)'
)

# Generic: timestamp src_ip dst_ip dst_port protocol bytes
GENERIC_PATTERN = re.compile(
    r'(?P<time>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}) '
    r'(?P<src_ip>\S+) (?P<dst_ip>\S+) (?P<port>\d+) '
    r'(?P<proto>\w+) (?P<bytes>\d+)'
)

APACHE_TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"
ISO_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"
ISO_SPACE_FORMAT = "%Y-%m-%d %H:%M:%S"


def _parse_time(raw: str) -> datetime:
    for fmt in (APACHE_TIME_FORMAT, ISO_TIME_FORMAT, ISO_SPACE_FORMAT):
        try:
            return datetime.strptime(raw.strip(), fmt).replace(tzinfo=None)
        except ValueError:
            continue
    raise ValueError(f"Cannot parse timestamp: {raw!r}")


def parse_apache_line(line: str, dst_ip: str = "0.0.0.0", dst_port: int = 80) -> Optional[LogEntry]:
    m = APACHE_PATTERN.match(line.strip())
    if not m:
        return None
    return LogEntry(
        timestamp=_parse_time(m.group("time")),
        src_ip=m.group("src_ip"),
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol="HTTP",
        status_code=int(m.group("status")),
        bytes_sent=int(m.group("bytes")) if m.group("bytes") != "-" else 0,
        method=m.group("method"),
        path=m.group("path"),
    )


def parse_generic_line(line: str) -> Optional[LogEntry]:
    m = GENERIC_PATTERN.match(line.strip())
    if not m:
        return None
    return LogEntry(
        timestamp=_parse_time(m.group("time")),
        src_ip=m.group("src_ip"),
        dst_ip=m.group("dst_ip"),
        dst_port=int(m.group("port")),
        protocol=m.group("proto"),
        bytes_sent=int(m.group("bytes")),
    )


def parse_log_file(filepath: str) -> List[LogEntry]:
    """Auto-detect format and parse an entire log file."""
    entries = []
    errors = 0
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = parse_apache_line(line) or parse_generic_line(line)
            if entry:
                entries.append(entry)
            else:
                errors += 1

    if errors:
        import logging
        logging.getLogger(__name__).debug("Skipped %d unparseable lines in %s", errors, filepath)
    return entries