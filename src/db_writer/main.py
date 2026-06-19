from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

import psycopg2
import yaml
from opensearchpy import OpenSearch
from neo4j import GraphDatabase

from src.common.queue import QueueClient
from src.common.security import (
    HIGH_RISK_CATEGORIES,
    QUARANTINE_CATEGORIES,
    audit_log,
    compute_intelligence_confidence,
    confidence_label,
)

_POSTGRES_PASSWORD = os.environ.get("POSTGRES_PASSWORD")
if not _POSTGRES_PASSWORD:
    print("FATAL: POSTGRES_PASSWORD environment variable is required.")
    sys.exit(1)

_pg_sslcert = os.environ.get('PGSSLCERT', '')
_pg_sslkey = os.environ.get('PGSSLKEY', '')
POSTGRES_DSN_PARTS = [
    f"host={os.environ.get('POSTGRES_HOST', 'postgres')}",
    f"port={os.environ.get('POSTGRES_PORT', '5432')}",
    f"dbname={os.environ.get('POSTGRES_DB', 'dwitp')}",
    f"user={os.environ.get('POSTGRES_USER', 'dwitp')}",
    f"password={_POSTGRES_PASSWORD}",
    f"sslmode={os.environ.get('POSTGRES_SSLMODE', 'require')}",
    f"sslrootcert={os.environ.get('PGSSLROOTCERT', '/etc/dwitp/tls/ca/ca.crt')}",
]
if _pg_sslcert:
    POSTGRES_DSN_PARTS.append(f"sslcert={_pg_sslcert}")
if _pg_sslkey:
    POSTGRES_DSN_PARTS.append(f"sslkey={_pg_sslkey}")
POSTGRES_DSN = " ".join(POSTGRES_DSN_PARTS)

_OPENSEARCH_PASSWORD = os.environ.get("OPENSEARCH_PASSWORD")
if not _OPENSEARCH_PASSWORD:
    print("FATAL: OPENSEARCH_PASSWORD environment variable is required.")
    sys.exit(1)

OPENSEARCH_HOST = os.environ.get("OPENSEARCH_HOST", "opensearch")
OPENSEARCH_PORT = os.environ.get("OPENSEARCH_PORT", "9200")
OPENSEARCH_USER = os.environ.get("OPENSEARCH_USER", "admin")
OPENSEARCH_PASSWORD = _OPENSEARCH_PASSWORD
# OpenSearch runs with the security plugin disabled (plain HTTP). Configurable so
# a TLS-enabled deployment can flip this back to "https".
OPENSEARCH_SCHEME = os.environ.get("OPENSEARCH_SCHEME", "http")

_NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD")
if not _NEO4J_PASSWORD:
    print("FATAL: NEO4J_PASSWORD environment variable is required.")
    sys.exit(1)

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt+ssc://neo4j:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = _NEO4J_PASSWORD
NEO4J_TLS_CA = os.environ.get("NEO4J_TLS_CA", "/etc/dwitp/tls/ca/ca.crt")


def _get_source_reliability(cur, source: str) -> float:
    cur.execute("SELECT reliability_score FROM source_reputation WHERE source_name = %s", (source,))
    row = cur.fetchone()
    return float(row[0]) if row else 0.5


def _count_corroborating_sources(cur, record: dict) -> int:
    """Count distinct other sources reporting the same category with at least one
    overlapping entity value. corroborating_sources == 0 keeps a finding UNCONFIRMED
    regardless of how confident the model claims to be — a single source's hallucination
    shouldn't be indistinguishable from a verified, cross-corroborated finding."""
    category = record["classification"]["category"]
    source = record.get("source", "")
    entities = record["classification"].get("entities", {}) or {}
    if not entities:
        return 0

    cur.execute(
        """SELECT DISTINCT f.source, c.entities
           FROM intelligence_findings f
           JOIN classifications c ON c.record_id = f.record_id
           WHERE f.category = %s AND f.source != %s""",
        (category, source),
    )
    own_values = {str(v).lower() for v in entities.values() if not isinstance(v, dict)}
    corroborating_sources: set[str] = set()
    for other_source, other_entities in cur.fetchall():
        other_values = {str(v).lower() for v in (other_entities or {}).values() if not isinstance(v, dict)}
        if own_values & other_values:
            corroborating_sources.add(other_source)
    return len(corroborating_sources)


def write_to_postgres(record: dict) -> bool:
    """Persist a classified record. Returns False (and writes nothing) when the
    page content has already been stored, identified by sha256. The crawler
    dedups by URL, but identical content can still arrive via a different URL or
    a re-fetched listing page; this content-hash guard stops the same page from
    producing duplicate classifications and findings."""
    conn = psycopg2.connect(POSTGRES_DSN)
    try:
        with conn.cursor() as cur:
            sha256 = record.get("sha256", "")
            if sha256:
                cur.execute("SELECT 1 FROM raw_evidence WHERE sha256 = %s LIMIT 1", (sha256,))
                if cur.fetchone():
                    audit_log("duplicate_content_skipped", {
                        "record_id": record.get("record_id", ""),
                        "sha256": sha256,
                        "url": record.get("url", ""),
                    })
                    return False

            raw_text = record.get("raw_content", record.get("classification", {}).get("summary", ""))
            cur.execute(
                """INSERT INTO raw_evidence (record_id, sha256, source, url, raw_text, size_bytes)
                   VALUES (%s, %s, %s, %s, %s, %s)
                   ON CONFLICT DO NOTHING""",
                (
                    record["record_id"],
                    sha256,
                    record.get("source", ""),
                    record.get("url", ""),
                    raw_text,
                    len(raw_text),
                ),
            )

            cur.execute(
                """INSERT INTO classifications (record_id, category, confidence, entities, summary)
                   VALUES (%s, %s, %s, %s, %s)
                   ON CONFLICT DO NOTHING""",
                (
                    record["record_id"],
                    record["classification"]["category"],
                    record["classification"]["confidence"],
                    json.dumps(record["classification"].get("entities", {})),
                    record["classification"]["summary"][:500],
                ),
            )

            if record["classification"]["category"] in HIGH_RISK_CATEGORIES:
                reliability = _get_source_reliability(cur, record.get("source", ""))
                corroborating = _count_corroborating_sources(cur, record)
                calibrated_confidence = compute_intelligence_confidence(
                    record["classification"]["confidence"],
                    reliability,
                    corroborating,
                    1.0,
                )
                confidence_level = "UNCONFIRMED" if corroborating == 0 else confidence_label(calibrated_confidence)

                cur.execute(
                    """INSERT INTO intelligence_findings
                       (record_id, category, confidence, source, summary, requires_human_review,
                        corroborating_sources, confidence_level)
                       VALUES (%s, %s, %s, %s, %s, TRUE, %s, %s)
                       ON CONFLICT DO NOTHING""",
                    (
                        record["record_id"],
                        record["classification"]["category"],
                        calibrated_confidence,
                        record.get("source", ""),
                        record["classification"]["summary"][:500],
                        corroborating,
                        confidence_level,
                    ),
                )
            conn.commit()
    finally:
        conn.close()
    return True


def index_to_opensearch(record: dict) -> None:
    try:
        es = OpenSearch(
            hosts=[{"host": OPENSEARCH_HOST, "port": int(OPENSEARCH_PORT)}],
            http_auth=(OPENSEARCH_USER, OPENSEARCH_PASSWORD),
            use_ssl=(OPENSEARCH_SCHEME == "https"),
            verify_certs=False,
        )
        es.index(
            index="dwitp-classifications",
            id=record["record_id"],
            body={
                "record_id": record["record_id"],
                "category": record["classification"]["category"],
                "confidence": record["classification"]["confidence"],
                "summary": record["classification"]["summary"],
                "entities": record["classification"].get("entities", {}),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )
    except Exception as e:
        audit_log("opensearch_index_error", {"record_id": record["record_id"], "error": str(e)}, severity="ERROR")


def update_neo4j_graph(record: dict) -> None:
    try:
        # The bolt+ssc:// URI scheme already selects TLS with self-signed-cert
        # trust; passing a separate trust=/encrypted= config is invalid in the
        # neo4j 5.x driver (raises "Unexpected config keys: trust") and was why
        # every graph write silently failed.
        driver = GraphDatabase.driver(
            NEO4J_URI,
            auth=(NEO4J_USER, NEO4J_PASSWORD),
        )
        with driver.session() as session:
            session.run(
                """MERGE (c:Classification {record_id: $record_id})
                   SET c.category = $category,
                       c.confidence = $confidence,
                       c.summary = $summary,
                       c.timestamp = datetime()""",
                record_id=record["record_id"],
                category=record["classification"]["category"],
                confidence=record["classification"]["confidence"],
                summary=record["classification"]["summary"][:500],
            )
        driver.close()
    except Exception as e:
        audit_log("neo4j_update_error", {"record_id": record["record_id"], "error": str(e)}, severity="ERROR")


def _update_source_reputation(record: dict) -> None:
    source = record.get("source", "")
    if not source:
        return

    is_degraded = record.get("source_degraded", False)
    pi_raw = record.get("injection_patterns_detected", 0)
    pi_count = len(pi_raw) if isinstance(pi_raw, list) else int(pi_raw)

    try:
        conn = psycopg2.connect(POSTGRES_DSN)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO source_reputation (source_name, poisoning_incidents, status, updated_at)
                       VALUES (%s, %s, %s, NOW())
                       ON CONFLICT (source_name) DO UPDATE SET
                           poisoning_incidents = source_reputation.poisoning_incidents + EXCLUDED.poisoning_incidents,
                           status = CASE
                               WHEN source_reputation.poisoning_incidents + EXCLUDED.poisoning_incidents >= 3 THEN 'degraded'
                               ELSE source_reputation.status
                           END,
                           updated_at = NOW()""",
                    (source, pi_count, "degraded" if is_degraded else "active"),
                )
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        audit_log("source_reputation_update_error", {
            "source": source,
            "error": str(e),
        }, severity="ERROR")


def write_telegram_message(record: dict) -> bool:
    """Persist a Telegram message on its natural key (group, message). Returns
    False when the message was already stored (dedup), True on first insert. Also
    upserts a minimal telegram_actors row so the actor table has data before the
    SNA job (graph_analytics) runs. INTEL-002 / T1.4."""
    tg = record.get("tg", {}) or {}
    gid, mid = tg.get("group_id"), tg.get("message_id")
    if gid is None or mid is None:
        return False
    cls = record.get("classification", {}) or {}
    sent_at = tg.get("sent_at") or datetime.now(timezone.utc).isoformat()
    text = record.get("content_sanitized", record.get("raw_content", ""))
    conn = psycopg2.connect(POSTGRES_DSN)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO telegram_messages
                   (tg_group_id, tg_message_id, sender_id, sender_handle, sent_at,
                    text_sanitized, reply_to_msg_id, mentions, forward_from_id,
                    category, confidence)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                   ON CONFLICT (tg_group_id, tg_message_id) DO NOTHING""",
                (
                    gid, mid, tg.get("sender_id"), tg.get("sender_handle"), sent_at,
                    text, tg.get("reply_to_msg_id"), json.dumps(tg.get("mentions", [])),
                    tg.get("forward_from_id"), cls.get("category"), cls.get("confidence"),
                ),
            )
            if cur.rowcount == 0:
                conn.commit()
                return False
            sender_id = tg.get("sender_id")
            if sender_id is not None:
                cur.execute(
                    """INSERT INTO telegram_actors
                       (tg_user_id, handle, first_seen, last_seen, message_count)
                       VALUES (%s,%s,%s,%s,1)
                       ON CONFLICT (tg_user_id) DO UPDATE SET
                           handle = COALESCE(EXCLUDED.handle, telegram_actors.handle),
                           last_seen = GREATEST(
                               COALESCE(telegram_actors.last_seen, EXCLUDED.last_seen),
                               EXCLUDED.last_seen),
                           message_count = telegram_actors.message_count + 1,
                           updated_at = NOW()""",
                    (sender_id, tg.get("sender_handle"), sent_at, sent_at),
                )
            conn.commit()
    finally:
        conn.close()
    return True


def update_telegram_graph(record: dict) -> None:
    """Upsert the actor interaction graph in Neo4j: Actor/Group/Message nodes,
    MEMBER_OF / POSTED / IN, and weighted REPLIED_TO / MENTIONED edges. The reply
    edge is best-effort — it links only if the replied-to message is already
    ingested. INTEL-002 / T2.2."""
    tg = record.get("tg", {}) or {}
    gid, mid, sender_id = tg.get("group_id"), tg.get("message_id"), tg.get("sender_id")
    if gid is None or mid is None or sender_id is None:
        return  # need an identifiable author to attribute the message
    cls = record.get("classification", {}) or {}
    msg_key = f"{gid}:{mid}"
    try:
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        with driver.session() as session:
            session.run(
                """MERGE (g:Group {group_id: $gid})
                   MERGE (a:Actor {user_id: $sender_id})
                     ON CREATE SET a.first_seen = datetime()
                   SET a.handle = $handle, a.last_seen = datetime()
                   MERGE (a)-[:MEMBER_OF]->(g)
                   MERGE (m:Message {msg_id: $msg_key})
                     SET m.ts = $ts, m.category = $category
                   MERGE (a)-[:POSTED]->(m)
                   MERGE (m)-[:IN]->(g)""",
                gid=gid, sender_id=sender_id, handle=tg.get("sender_handle"),
                msg_key=msg_key, ts=tg.get("sent_at"), category=cls.get("category"),
            )
            reply_to = tg.get("reply_to_msg_id")
            if reply_to is not None:
                session.run(
                    """MATCH (target:Actor)-[:POSTED]->(:Message {msg_id: $reply_key})
                       MATCH (a:Actor {user_id: $sender_id})
                       WHERE target <> a
                       MERGE (a)-[r:REPLIED_TO]->(target)
                         ON CREATE SET r.count = 1
                         ON MATCH SET r.count = r.count + 1""",
                    reply_key=f"{gid}:{reply_to}", sender_id=sender_id,
                )
            for handle in (tg.get("mentions") or []):
                h = handle if str(handle).startswith("@") else "@" + str(handle)
                session.run(
                    """MATCH (a:Actor {user_id: $sender_id})
                       MERGE (b:Actor {handle: $handle})
                       MERGE (a)-[r:MENTIONED]->(b)
                         ON CREATE SET r.count = 1
                         ON MATCH SET r.count = r.count + 1""",
                    sender_id=sender_id, handle=h,
                )
        driver.close()
    except Exception as e:
        audit_log("neo4j_telegram_update_error",
                  {"record_id": record.get("record_id", ""), "error": str(e)}, severity="ERROR")


def quarantine_and_escalate(record: dict) -> None:
    """TG-G4 / IR-001: a quarantine-category hit (CSAM) must NOT be retained. Persist
    NOTHING — no raw_evidence, no classification, no finding. Emit a CRITICAL audit
    event (which fans out to the notifier) carrying only non-content metadata for the
    law-enforcement escalation, then drop the record."""
    category = record.get("classification", {}).get("category", "")
    audit_log("quarantine_no_retain", {
        "record_id": record.get("record_id", ""),
        "source": record.get("source", ""),
        "url": record.get("url", ""),          # locator for LE escalation — not content
        "category": category,
        "action": "content_discarded_not_retained",
        "note": "Detected quarantine-category content — escalate to NCMEC / LE liaison "
                "per IR-001. Content was dropped and never written to any store.",
    }, severity="CRITICAL")


def process_classification(record: dict) -> None:
    source = record.get("source", "")
    if source in ("dnmx", "mail2tor"):
        return

    # Quarantine gate (TG-G4): intercept no-retain categories BEFORE any persistence
    # path (web OR telegram). Content is dropped; only a CRITICAL escalation is logged.
    if record.get("classification", {}).get("category") in QUARANTINE_CATEGORIES:
        quarantine_and_escalate(record)
        return

    # Telegram messages go to their own ledger + actor graph (natural-key dedup on
    # group+message), NOT the sha256/raw_evidence web path. INTEL-002.
    if record.get("platform") == "telegram" and record.get("tg"):
        if not write_telegram_message(record):
            return
        update_telegram_graph(record)
        _update_source_reputation(record)
        audit_log("telegram_message_persisted", {
            "record_id": record.get("record_id", ""),
            "group_id": record["tg"].get("group_id"),
            "message_id": record["tg"].get("message_id"),
        })
        return

    if not write_to_postgres(record):
        # Duplicate content (same sha256 already stored) — don't index, graph,
        # or re-score reputation off a page we've already accounted for.
        return
    index_to_opensearch(record)
    update_neo4j_graph(record)
    _update_source_reputation(record)

    audit_log("classification_persisted", {
        "record_id": record["record_id"],
        "category": record["classification"]["category"],
    })


def process_discovered_candidate(record: dict) -> None:
    url = record.get("url", "")
    discovered_from = record.get("discovered_from", "")
    if not url:
        return

    conn = psycopg2.connect(POSTGRES_DSN)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO candidate_sources (url, discovered_from)
                   VALUES (%s, %s)
                   ON CONFLICT (url) DO NOTHING""",
                (url, discovered_from),
            )
            conn.commit()
    finally:
        conn.close()

    audit_log("candidate_source_discovered", {"url": url, "discovered_from": discovered_from})


SOURCES_YAML = os.environ.get("SOURCES_YAML", "/app/config/sources.yaml")


def init_source_registry() -> None:
    if not os.path.isfile(SOURCES_YAML):
        audit_log("source_registry_init_skipped", {"reason": "sources.yaml not found", "path": SOURCES_YAML},
                   severity="WARNING")
        return
    try:
        with open(SOURCES_YAML, "r") as f:
            data = yaml.safe_load(f)
    except Exception as e:
        audit_log("source_registry_init_error", {"error": str(e)}, severity="ERROR")
        return

    sources = data.get("sources", [])
    if not sources:
        return

    conn = psycopg2.connect(POSTGRES_DSN)
    try:
        with conn.cursor() as cur:
            for src in sources:
                cur.execute(
                    """INSERT INTO source_registry (name, url, category, approved_by, approved_date, active)
                       VALUES (%s, %s, %s, %s, %s, %s)
                       ON CONFLICT (name) DO NOTHING""",
                    (
                        src.get("source_id", ""),
                        src.get("url", ""),
                        src.get("category", ""),
                        src.get("approved_by", ""),
                        src.get("approved_date", datetime.now(timezone.utc).strftime("%Y-%m-%d")),
                        src.get("status") == "approved",
                    ),
                )
            conn.commit()
            audit_log("source_registry_init", {"count": len(sources)})
    finally:
        conn.close()


def main() -> None:
    print("DWITP DB Writer started — waiting for ai.output and discovery.candidate messages")
    init_source_registry()
    client = QueueClient()
    try:
        client.consume_multi_with_retry([
            ("ai.output", process_classification),
            ("discovery.candidate", process_discovered_candidate),
        ])
    except KeyboardInterrupt:
        print("DB Writer stopped by operator")
        sys.exit(0)
    finally:
        client.close()


if __name__ == "__main__":
    main()
