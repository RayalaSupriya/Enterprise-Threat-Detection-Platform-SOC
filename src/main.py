"""
FastAPI — Threat Detection API
Endpoints:
  POST /analyze/entry    — analyze a single log entry (JSON)
  POST /analyze/batch    — analyze multiple entries
  POST /analyze/file     — upload a raw log file
  GET  /threats          — list all detected threats
  GET  /threats/summary  — aggregated counts by type/severity
  DELETE /threats        — clear the in-memory threat log
"""

from fastapi import FastAPI, UploadFile, File, HTTPException
from src.alerts.notifier import AlertNotifier
from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime
import tempfile, os

from src.analyzer.threat_analyzer import ThreatAnalyzer, LogEntry, ThreatEvent
from src.analyzer.log_parser import parse_log_file
from config.settings import load_config

app = FastAPI(
    title="Enterprise Threat Detection API",
    description="SOC threat analyzer — detects DDoS, port scans, brute-force, and anomalies.",
    version="1.0.0",
)

# Global analyzer instance (loaded once at startup)
_config = load_config()
analyzer = ThreatAnalyzer(config=_config.get("analyzer", {}))
notifier = AlertNotifier(config=_config.get("alerting", {}))


# ─────────────────────────────────────────────
# Request / Response schemas
# ─────────────────────────────────────────────

class LogEntryRequest(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str = "TCP"
    status_code: Optional[int] = None
    bytes_sent: int = 0
    method: Optional[str] = None
    path: Optional[str] = None


class ThreatResponse(BaseModel):
    threat_type: str
    severity: str
    src_ip: str
    description: str
    timestamp: datetime
    details: dict


# ─────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────

@app.get("/health")
def health_check():
    return {"status": "ok", "service": "threat-analyzer"}


@app.post("/analyze/entry", response_model=List[ThreatResponse])
def analyze_entry(entry: LogEntryRequest):
    """Analyze a single log entry and return any detected threats."""
    log = LogEntry(
        timestamp=entry.timestamp,
        src_ip=entry.src_ip,
        dst_ip=entry.dst_ip,
        dst_port=entry.dst_port,
        protocol=entry.protocol,
        status_code=entry.status_code,
        bytes_sent=entry.bytes_sent,
        method=entry.method,
        path=entry.path,
    )
    events = analyzer.analyze(log)
    notifier.send_alerts(events)
    return [ThreatResponse(**e.to_dict()) for e in events]



@app.post("/analyze/batch", response_model=List[ThreatResponse])
def analyze_batch(entries: List[LogEntryRequest]):
    """Analyze a batch of log entries."""
    logs = [
        LogEntry(
            timestamp=e.timestamp,
            src_ip=e.src_ip,
            dst_ip=e.dst_ip,
            dst_port=e.dst_port,
            protocol=e.protocol,
            status_code=e.status_code,
            bytes_sent=e.bytes_sent,
            method=e.method,
            path=e.path,
        )
        for e in entries
    ]
    events = analyzer.analyze_batch(logs)
    notifier.send_alerts(events)
    return [ThreatResponse(**e.to_dict()) for e in events]



@app.post("/analyze/file", response_model=List[ThreatResponse])
async def analyze_file(file: UploadFile = File(...)):
    """Upload a raw log file (Apache/Nginx/generic) and analyze it."""
    if file.content_type not in ("text/plain", "application/octet-stream", None):
        raise HTTPException(status_code=400, detail="Only plain text log files are accepted.")

    # Write upload to a temp file, parse, then clean up
    suffix = os.path.splitext(file.filename or "log.txt")[1] or ".txt"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(await file.read())
        tmp_path = tmp.name

    try:
        entries = parse_log_file(tmp_path)
    finally:
        os.unlink(tmp_path)

    if not entries:
        raise HTTPException(status_code=422, detail="No parseable log entries found in file.")

    events = analyzer.analyze_batch(entries)
    notifier.send_alerts(events)
    return [ThreatResponse(**e.to_dict()) for e in events]



@app.get("/threats", response_model=List[ThreatResponse])
def list_threats(
    severity: Optional[str] = None,
    threat_type: Optional[str] = None,
    limit: int = 100,
):
    """Return stored threat events, optionally filtered by severity or type."""
    events = analyzer.threat_log
    if severity:
        events = [e for e in events if e.severity == severity]
    if threat_type:
        events = [e for e in events if e.threat_type == threat_type]
    return [ThreatResponse(**e.to_dict()) for e in events[-limit:]]


@app.get("/threats/summary")
def threats_summary():
    """Aggregated threat counts grouped by type and severity."""
    return {
        "total": len(analyzer.threat_log),
        "by_type": analyzer.get_summary(),
    }


@app.delete("/threats")
def clear_threats():
    global analyzer, notifier
    analyzer = ThreatAnalyzer(config=_config.get("analyzer", {}))
    notifier = AlertNotifier(config=_config.get("alerting", {}))
    return {"message": "Threat log and detector state cleared."}
