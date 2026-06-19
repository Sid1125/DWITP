"""DWITP classification stage — worker / plumbing.

The Ollama LLM classifier was removed: it was the pipeline's biggest bottleneck
(a blocking /api/generate call of up to 120s PER PAGE, four replicas deep, behind
a 4GB model). It sat on the critical path between `analysis.ready` and `ai.output`
and dominated the crawl→report latency.

This module is the queue worker: it consumes `analysis.ready`, runs each record
through the offline rule-lexicon engine in `classifier.classify()` (no network, no
model — sub-millisecond, deterministic), and publishes the same `ai.output` envelope
db_writer already expects. Findings keep flowing; the dashboard keeps populating.

The classification decision lives entirely in `classifier.classify()` — the seam the
engine plugs into. This file owns the queue plumbing, PI-campaign guardrails, the
manual kill switch, and the Telegram passthrough, all engine-agnostic.
"""
from __future__ import annotations

import json
import os
import socket
import sys

from src.ai_layer.classifier import classify
from src.common.queue import QueueClient
from src.common.security import (
    HIGH_RISK_CATEGORIES,
    IMMEDIATE_ESCALATION_CATEGORIES,
    QUARANTINE_CATEGORIES,
    audit_log,
    confidence_label,
    map_to_mitre_attack,
)

PI_CAMPAIGN_THRESHOLD = int(os.environ.get("PI_CAMPAIGN_THRESHOLD", "5"))
_pi_incidents_per_source: dict[str, int] = {}
# Global operator kill switch (manual, via the Admin Panel control.ai exchange).
# Stays global: it is an emergency stop for ALL sources. Retained even though the
# LLM is gone — it now halts the deterministic classifier just the same.
_ai_disabled: bool = False
# Automatic PI-campaign quarantine, tracked PER SOURCE. A source that crosses the
# threshold is skipped on its own so one poisoned/noisy source no longer disables
# classification of every other source. In-memory: a restart implies a deliberate
# operator action and comes back up clean.
_disabled_sources: set[str] = set()

CONTROL_EXCHANGE = "control.ai"
_control_queue_name = f"control.ai.{socket.gethostname()}"


def check_control_messages(client: QueueClient) -> None:
    global _ai_disabled
    client.bind_fanout_queue(CONTROL_EXCHANGE, _control_queue_name)
    for msg in client.poll_queue(_control_queue_name):
        action = msg.get("action")
        if action == "disable" and not _ai_disabled:
            _ai_disabled = True
            audit_log("ai_disabled_manual", {"by": msg.get("by", "unknown")}, severity="CRITICAL")
        elif action == "enable" and _ai_disabled:
            _ai_disabled = False
            audit_log("ai_enabled_manual", {"by": msg.get("by", "unknown")})


def handle_finding(finding: dict) -> None:
    category = finding.get("classification", {}).get("category", "unknown")
    risk_score = finding.get("risk_score", 0.5)
    requires_review = False

    if category in HIGH_RISK_CATEGORIES:
        requires_review = True
        audit_log("high_risk_finding_requiring_review", {
            "finding_id": finding.get("record_id"),
            "category": category,
        }, severity="WARNING")

    if category in IMMEDIATE_ESCALATION_CATEGORIES:
        requires_review = True
        audit_log("immediate_escalation_required", {
            "finding_id": finding.get("record_id"),
            "category": category,
            "note": "Route to legal counsel / law enforcement liaison — do not handle as routine review.",
        }, severity="CRITICAL")

    if risk_score > 0.8:
        requires_review = True
        audit_log("high_risk_source_requiring_review", {
            "finding_id": finding.get("record_id"),
            "risk_score": risk_score,
        }, severity="WARNING")

    finding["requires_human_review"] = requires_review


def process_analysis_result(message: dict, client: QueueClient) -> None:
    global _ai_disabled

    check_control_messages(client)
    # Manual operator kill switch — global hard stop for every source.
    if _ai_disabled:
        audit_log("ai_disabled_skip", {"record_id": message.get("record_id", "unknown")}, severity="WARNING")
        return

    source = message.get("source", "unknown")

    # Automatic PI-campaign quarantine is per source: a source already tripped is
    # skipped, but classification of every other source keeps running.
    if source in _disabled_sources:
        audit_log("pi_campaign_skipped", {
            "record_id": message.get("record_id", "unknown"),
            "source": source,
        }, severity="WARNING")
        return

    pi_raw = message.get("injection_patterns_detected", 0)
    pi_count = len(pi_raw) if isinstance(pi_raw, list) else int(pi_raw)

    if pi_count > 0:
        _pi_incidents_per_source[source] = _pi_incidents_per_source.get(source, 0) + pi_count
        audit_log("pi_incident_tracked", {
            "source": source,
            "patterns": pi_count,
            "total": _pi_incidents_per_source[source],
        }, severity="WARNING")

    total_pi = _pi_incidents_per_source.get(source, 0)
    if total_pi >= 3:
        audit_log("source_degraded_poisoning", {
            "source": source,
            "pi_incidents": total_pi,
        }, severity="CRITICAL")

    if total_pi >= PI_CAMPAIGN_THRESHOLD:
        _disabled_sources.add(source)
        audit_log("source_disabled_pi_campaign", {
            "source": source,
            "total_pi_incidents": total_pi,
            "threshold": PI_CAMPAIGN_THRESHOLD,
        }, severity="CRITICAL")
        audit_log("pi_campaign_skipped", {
            "record_id": message.get("record_id", "unknown"),
            "source": source,
        }, severity="WARNING")
        return

    full_content = message.get("content_sanitized", json.dumps(message))
    record_id = message.get("record_id", "unknown")
    # raw_text is the original crawled HTML threaded through the pipeline for storage.
    raw_text_original = message.get("raw_text", full_content)
    entities = message.get("entities", {}) or {}

    result = classify(full_content, entities)
    result["confidence_label"] = confidence_label(result["confidence"])
    mitre_ttps = map_to_mitre_attack(result["category"])

    classification = {
        "record_id": record_id,
        "source": source,
        "url": message.get("url", ""),
        "sha256": message.get("sha256", ""),
        "risk_score": message.get("risk_score", 0.5),
        "injection_patterns_detected": pi_count,
        "source_degraded": total_pi >= 3,
        "classification": result,
        "mitre_ttps": mitre_ttps,
        "raw_content": raw_text_original,  # original crawled HTML (not the sanitized version)
    }

    # Telegram passthrough (INTEL-002): the `tg` block + sanitized text let
    # db_writer persist the message to telegram_messages and build the actor graph.
    if message.get("platform"):
        classification["platform"] = message["platform"]
    if message.get("tg"):
        classification["tg"] = message["tg"]
        classification["content_sanitized"] = full_content

    # Defense in depth (TG-G4): for a quarantine category (CSAM), strip page content
    # from the envelope so it never even transits the queue. db_writer still sees the
    # category and quarantines/escalates on metadata alone; no content is persisted.
    if result["category"] in QUARANTINE_CATEGORIES:
        classification["raw_content"] = "[REDACTED — quarantine category]"
        classification.pop("content_sanitized", None)

    handle_finding(classification)
    client.publish("ai.output", classification)

    audit_log("classification_complete", {
        "record_id": record_id,
        "category": result["category"],
        "confidence": result["confidence"],
        "engine": "rule-lexicon",
    })


def main() -> None:
    print("DWITP classification stage started — rule-lexicon engine (offline, deterministic)")
    client = QueueClient()
    try:
        client.consume_with_retry("analysis.ready", lambda msg: process_analysis_result(msg, client))
    except KeyboardInterrupt:
        print("Classification stage stopped by operator")
        sys.exit(0)
    finally:
        client.close()


if __name__ == "__main__":
    main()
