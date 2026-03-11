# Enterprise Threat Detection & Alerting Platform

A production-grade Security Operations Center (SOC) threat detection system that simulates real-world security monitoring workflows. This platform ingests logs, detects suspicious activity, correlates security events, and automatically alerts security teams to emerging threats.

## Overview

This project demonstrates practical SOC analyst and detection engineering expertise by implementing a complete threat detection pipeline aligned with MITRE ATT&CK frameworks. The platform analyzes network and application logs to identify common attack patterns including DDoS attacks, port scans, brute-force attempts, and anomalous traffic behavior.

### What You Get

The system exposes a FastAPI-based REST API that allows security teams to:
- Ingest logs in multiple formats
- Detect threats in real time
- Trigger automated alerts via Slack or email
- Query detected threats and generate reports
- Manage threat event history

## Key Features

### Log Ingestion & Parsing

The platform supports multiple log formats out of the box:
- Apache and Nginx access logs
- Generic network logs  
- Security monitoring events

All logs are parsed into structured objects before being processed through the detection engine.

### Threat Detection Engine

The system identifies several common attack patterns found in real-world environments:

#### DDoS Detection
Flags excessive requests originating from a single IP address within a configurable time window.

#### Port Scan Detection
Identifies suspicious attempts to scan multiple ports from the same source host.

#### Brute Force Attack Detection
Detects repeated authentication failures targeting sensitive services like SSH, web authentication endpoints, and database services.

#### Traffic Anomaly Detection
Catches suspicious activity patterns such as:
- Unusually large data transfers
- External IPs attempting to access internal database ports

### Alerting System

Detected threats automatically trigger alerts through your preferred channels:
- **Slack Webhooks** — Real-time notifications to security channels
- **Email Notifications** — Direct alerts to analyst inboxes

Each alert includes:
- Threat classification and severity level
- Source IP and target information
- Detailed description of the detected activity
- Precise timestamp and detection context

Alert behavior is fully configurable via `config/config.json` or the REST API.

## Detection Architecture

```
Log Sources
    ↓
Log Parser
    ↓
Threat Analyzer
  • DDoS Detector
  • Port Scan Detector
  • Brute Force Detector
  • Anomaly Detector
    ↓
Threat Events
    ↓
Alert Notifier
  • Slack Alerts
  • Email Alerts
    ↓
SOC Monitoring API
```

## Project Structure

```
Enterprise-Threat-Detection-Platform-SOC/
├── config/
│   ├── config.json
│   └── settings.py
├── src/
│   ├── main.py
│   └── analyzer/
│       ├── log_parser.py
│       └── threat_analyzer.py
│   └── alerts/
│       └── notifier.py
├── tests/
│   ├── test_threat_analyzer.py
│   └── test_notifier.py
├── requirements.txt
└── README.md
```

## Getting Started

### Installation

Clone the repository:

```bash
git clone https://github.com/RayalaSupriya/Enterprise-Threat-Detection-Platform-SOC.git
cd Enterprise-Threat-Detection-Platform-SOC
```

Install dependencies:

```bash
pip install -r requirements.txt
```

### Running the Platform

Start the FastAPI server:

```bash
uvicorn src.main:app --reload
```

The API will be available at:
```
http://127.0.0.1:8000
```

View interactive API documentation (Swagger UI):
```
http://127.0.0.1:8000/docs
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Service health check |
| `/analyze/entry` | POST | Analyze a single log entry |
| `/analyze/batch` | POST | Analyze multiple log entries at once |
| `/analyze/file` | POST | Upload and analyze log files |
| `/threats` | GET | Retrieve all detected threat events |
| `/threats/summary` | GET | View aggregated threat statistics |
| `/threats` | DELETE | Reset threat history |

### Example: Analyzing a Single Log Entry

**Request:**
```bash
POST /analyze/entry
Content-Type: application/json

{
  "timestamp": "2024-01-01T12:00:00",
  "src_ip": "8.8.8.8",
  "dst_ip": "10.0.0.1",
  "dst_port": 3306,
  "protocol": "TCP",
  "status_code": 200,
  "bytes_sent": 1200
}
```

**Response:**
```json
[
  {
    "threat_type": "anomaly",
    "severity": "high",
    "src_ip": "8.8.8.8",
    "description": "External IP accessing internal service port 3306",
    "timestamp": "2024-01-01T12:00:00",
    "details": {
      "dst_port": 3306
    }
  }
]
```

## Configuration

Detection thresholds and alert behavior are configured in `config/config.json`. Adjust these settings to match your security posture and environment:

```json
{
  "analyzer": {
    "ddos_threshold": 100,
    "ddos_window": 60,
    "portscan_threshold": 15,
    "portscan_window": 30,
    "bruteforce_threshold": 10,
    "bruteforce_window": 60,
    "large_payload_bytes": 5000000
  },
  "alerting": {
    "enabled": true,
    "min_severity": "high"
  }
}
```

### Configuration Parameters

- **ddos_threshold** — Number of requests that trigger DDoS detection
- **ddos_window** — Time window in seconds for DDoS analysis
- **portscan_threshold** — Number of unique ports that indicate scanning
- **portscan_window** — Time window in seconds for port scan detection
- **bruteforce_threshold** — Number of failed attempts that trigger alert
- **bruteforce_window** — Time window in seconds for brute force analysis
- **large_payload_bytes** — Byte threshold for anomalous data transfer detection
- **alerting.enabled** — Enable/disable alert notifications
- **alerting.min_severity** — Minimum severity level to trigger alerts

## Testing

Run the full test suite to validate detection logic:

```bash
pytest tests/ -v
```

Expected output:
```
19 passed in 0.22s
```

The test suite validates:
- DDoS detection accuracy
- Port scan pattern recognition
- Brute force detection logic
- Anomaly detection thresholds
- Alert filtering and deduplication
- Notifier functionality

## Use Cases

This platform is ideal for:
- **SOC Training & Simulation** — Practice threat detection workflows
- **Log-Based Intrusion Detection** — Monitor network and application logs
- **Detection Engineering** — Develop and test custom detection rules
- **SIEM Rule Development** — Build and validate detection logic
- **Portfolio Demonstrations** — Showcase security engineering skills

## Roadmap

Potential future enhancements include:

- Real-time SOC dashboard with threat visualization
- SIEM integrations (Splunk, Elastic, Azure Sentinel)
- Kafka-based log ingestion pipeline for high-volume environments
- Machine learning-based anomaly detection
- Automated incident response playbooks
- Cloud log ingestion (AWS CloudWatch, Azure Monitor)
- Integration with threat intelligence feeds

## Technologies Used

- **FastAPI** — High-performance REST API framework
- **Python** — Core application language
- **Pytest** — Comprehensive test coverage
- **MITRE ATT&CK** — Industry-standard threat framework

## Author

**Supriya Rayala**  
Master of Science in Computer Science (Cybersecurity)  
Kent State University


## License

This project is open source and available under the MIT License.


