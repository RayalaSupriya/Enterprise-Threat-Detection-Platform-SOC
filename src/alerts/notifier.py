import logging
import os
import smtplib
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List

import requests

from src.analyzer.threat_analyzer import ThreatEvent

logger = logging.getLogger(__name__)


class AlertNotifier:
    SEVERITY_ORDER = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }

    def __init__(self, config: dict = None):
        cfg = config or {}
        self.enabled = cfg.get("enabled", False)
        self.min_severity = cfg.get("min_severity", "high").lower()
        self.dedup_seconds = cfg.get("dedup_seconds", 300)
        self.slack_cfg = cfg.get("slack", {})
        self.email_cfg = cfg.get("email", {})
        self._recent_alerts = {}

    def send_alerts(self, events: List[ThreatEvent]) -> None:
        if not self.enabled or not events:
            return

        filtered = [e for e in events if self._should_alert(e)]
        if not filtered:
            logger.info("No events met minimum severity for alerting.")
            return

        deduped = [e for e in filtered if not self._is_duplicate(e)]
        if not deduped:
            logger.info("All events were suppressed by deduplication.")
            return

        message = self._format_message(deduped)

        if self.slack_cfg.get("enabled", False):
            self._send_slack(message)

        if self.email_cfg.get("enabled", False):
            self._send_email(deduped, message)

        for event in deduped:
            self._mark_sent(event)

    def _should_alert(self, event: ThreatEvent) -> bool:
        event_rank = self.SEVERITY_ORDER.get(event.severity.lower(), 0)
        min_rank = self.SEVERITY_ORDER.get(self.min_severity, 3)
        return event_rank >= min_rank

    def _event_key(self, event: ThreatEvent) -> str:
        return f"{event.threat_type}:{event.src_ip}:{event.severity}:{event.description}"

    def _is_duplicate(self, event: ThreatEvent) -> bool:
        key = self._event_key(event)
        last_sent = self._recent_alerts.get(key)
        if last_sent is None:
            return False
        return (time.time() - last_sent) < self.dedup_seconds

    def _mark_sent(self, event: ThreatEvent) -> None:
        self._recent_alerts[self._event_key(event)] = time.time()

    def _format_message(self, events: List[ThreatEvent]) -> str:
        lines = ["SOC Threat Alert", ""]
        for idx, event in enumerate(events, start=1):
            lines.extend([
                f"Threat #{idx}",
                f"Type: {event.threat_type}",
                f"Severity: {event.severity}",
                f"Source IP: {event.src_ip}",
                f"Description: {event.description}",
                f"Timestamp: {event.timestamp.isoformat()}",
                f"Details: {event.details}",
                "-" * 50,
            ])
        return "\n".join(lines)

    def _send_slack(self, message: str) -> None:
        webhook_url = self.slack_cfg.get("webhook_url") or os.getenv("SOC_SLACK_WEBHOOK")
        if not webhook_url:
            logger.warning("Slack alerting enabled but webhook URL is missing.")
            return

        try:
            response = requests.post(webhook_url, json={"text": message}, timeout=10)
            response.raise_for_status()
            logger.info("Slack alert sent successfully.")
        except requests.RequestException as exc:
            logger.exception("Failed to send Slack alert: %s", exc)

    def _send_email(self, events: List[ThreatEvent], message: str) -> None:
        smtp_server = self.email_cfg.get("smtp_server")
        smtp_port = self.email_cfg.get("smtp_port", 587)
        sender_email = self.email_cfg.get("sender_email")
        sender_password = self.email_cfg.get("sender_password") or os.getenv("SOC_EMAIL_PASSWORD")
        recipients = self.email_cfg.get("recipient_emails", [])

        if not all([smtp_server, smtp_port, sender_email, sender_password, recipients]):
            logger.warning("Email alerting enabled but configuration is incomplete.")
            return

        try:
            subject = f"[SOC ALERT] {len(events)} threat(s) detected"

            msg = MIMEMultipart()
            msg["From"] = sender_email
            msg["To"] = ", ".join(recipients)
            msg["Subject"] = subject
            msg.attach(MIMEText(message, "plain"))

            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(sender_email, sender_password)
                server.sendmail(sender_email, recipients, msg.as_string())

            logger.info("Email alert sent successfully.")
        except Exception as exc:
            logger.exception("Failed to send email alert: %s", exc)
