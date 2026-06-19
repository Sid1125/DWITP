from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

try:
    import httpx
except ImportError:
    httpx = None

SLACK_WEBHOOK_URL = os.environ.get("NOTIFIER_SLACK_WEBHOOK_URL", "")


def _notify_stderr(event_type: str, details: dict) -> None:
    msg = json.dumps({
        "notifier": "stderr",
        "event": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "details": details,
    })
    print(msg, file=sys.stderr)


def _notify_slack(event_type: str, details: dict) -> None:
    if not SLACK_WEBHOOK_URL:
        raise RuntimeError("SLACK_WEBHOOK_URL not configured")
    if httpx is None:
        raise RuntimeError("httpx not available for Slack notification")
    payload = {
        "text": f"*DWITP CRITICAL: {event_type}*\n```{json.dumps(details, indent=2, default=str)}```",
    }
    with httpx.Client(timeout=10.0) as client:
        response = client.post(SLACK_WEBHOOK_URL, json=payload)
        response.raise_for_status()


def notify_critical(event_type: str, details: dict) -> None:
    _notify_stderr(event_type, details)
    if SLACK_WEBHOOK_URL:
        try:
            _notify_slack(event_type, details)
        except Exception as e:
            _notify_stderr("slack_notify_failed", {"error": str(e)})
