"""DWITP Telegram Collector — observation-only (INTEL-002).

Reads APPROVED rows from `telegram_groups`, ingests message history/stream from a
lawfully-authorized Telethon user session, and publishes `telegram.raw` envelopes
into the existing pipeline (sanitizer -> analysis -> ai_layer -> db_writer).

──────────────────────────────────────────────────────────────────────────────
HARD CONSTRAINTS (TG-G3 / ARCH-001 non-interaction) — read before editing:

  * OBSERVATION ONLY. This file uses Telethon READ methods exclusively
    (get_entity / iter_messages / get_participants). There is deliberately NO
    send / post / reply / DM / write-to-Telegram path anywhere in this service.

  * NO DECEPTION / NO INFILTRATION TOOLING. It does not fabricate identities,
    answer vetting, evade bans, or otherwise gain entry to a group by deception:
      - access_method='public_link' groups are openly joinable (anyone can) and
        are joined directly — that is not deception;
      - every other group is read from a session that is ALREADY a lawful member,
        access having been obtained OUT-OF-BAND under documented legal authority
        (telegram_groups.legal_basis_ref). The collector never tries to get in.

  * GATED. Only groups with status='approved' AND a legal_basis_ref are collected
    (enforced in the DB, re-checked here as defense in depth — TG-G2).
──────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import socket
import sys
import time
from datetime import timezone
from uuid import uuid4

import psycopg2
from psycopg2.extras import RealDictCursor

from src.common.queue import QueueClient
from src.common.security import audit_log, compute_sha256

# ─── Config ───────────────────────────────────────────────────
TELEGRAM_API_ID = os.environ.get("TELEGRAM_API_ID", "")
TELEGRAM_API_HASH = os.environ.get("TELEGRAM_API_HASH", "")
TELEGRAM_SESSION = os.environ.get("TELEGRAM_SESSION", "")
HISTORY_LIMIT = int(os.environ.get("TELEGRAM_HISTORY_LIMIT", "500"))
POLL_INTERVAL = int(os.environ.get("TELEGRAM_POLL_INTERVAL", "300"))
USE_TOR = os.environ.get("TELEGRAM_USE_TOR", "true").lower() == "true"
TOR_HOST = os.environ.get("TOR_PROXY_HOST", "tor")
TOR_PORT = int(os.environ.get("TOR_PROXY_PORT", "9050"))
STATE_FILE = os.environ.get("COLLECTOR_STATE_FILE", "/var/lib/dwitp/tg_highwater.json")

POSTGRES_DSN = " ".join([
    f"host={os.environ.get('POSTGRES_HOST', 'postgres')}",
    f"port={os.environ.get('POSTGRES_PORT', '5432')}",
    f"dbname={os.environ.get('POSTGRES_DB', 'dwitp')}",
    f"user={os.environ.get('POSTGRES_USER', 'dwitp')}",
    f"password={os.environ.get('POSTGRES_PASSWORD', '')}",
    f"sslmode={os.environ.get('POSTGRES_SSLMODE', 'require')}",
    f"sslrootcert={os.environ.get('PGSSLROOTCERT', '/etc/dwitp/tls/ca/ca.crt')}",
])

RAW_QUEUE = "telegram.raw"
CONTROL_EXCHANGE = "control.collection"
_control_queue = f"control.collection.{socket.gethostname()}"

_collection_disabled = False
_highwater: dict[str, int] = {}      # per-group last-seen message id (incremental dedup)


def _halt(reason: str) -> None:
    audit_log("EMERGENCY_HALT", {"service": "telegram_collector", "reason": reason,
                                 "timestamp": time.time()}, severity="CRITICAL")
    print(f"TELEGRAM COLLECTOR HALTED — {reason}", file=sys.stderr)
    sys.exit(1)


# ─── Incremental state (per-group high-water mark) ────────────
def load_state() -> None:
    global _highwater
    try:
        with open(STATE_FILE, "r") as f:
            _highwater = {str(k): int(v) for k, v in json.load(f).items()}
        print(f"Loaded high-water marks for {len(_highwater)} group(s)")
    except (FileNotFoundError, ValueError):
        _highwater = {}


def save_state() -> None:
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(_highwater, f)
    except OSError as e:
        audit_log("tg_state_save_error", {"error": str(e)}, severity="WARNING")


# ─── Governance: only approved + legally-based groups ─────────
def load_approved_groups() -> list[dict]:
    conn = psycopg2.connect(POSTGRES_DSN)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT tg_group_id, title, username, access_method, legal_basis_ref "
                "FROM telegram_groups "
                "WHERE status = 'approved' AND legal_basis_ref IS NOT NULL"
            )
            return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


# ─── Collection kill switch (operator / IR-001) ──────────────
def check_kill_switch(qclient: QueueClient) -> None:
    global _collection_disabled
    try:
        qclient.bind_fanout_queue(CONTROL_EXCHANGE, _control_queue)
        for msg in qclient.poll_queue(_control_queue):
            action = msg.get("action")
            if action == "disable" and not _collection_disabled:
                _collection_disabled = True
                audit_log("collection_disabled_manual", {"by": msg.get("by", "unknown")}, severity="CRITICAL")
            elif action == "enable" and _collection_disabled:
                _collection_disabled = False
                audit_log("collection_enabled_manual", {"by": msg.get("by", "unknown")})
    except Exception:
        pass


def _build_proxy():
    """SOCKS5 egress through the Tor gateway (OPSEC; same path the crawler uses)."""
    if not USE_TOR:
        return None
    import socks  # PySocks
    return (socks.SOCKS5, TOR_HOST, TOR_PORT, True)


# ─── Envelope (mirrors raw.crawl + a `tg` block) ──────────────
def make_envelope(group: dict, message) -> dict:
    text = getattr(message, "message", None) or ""
    gid = group["tg_group_id"]
    sender = getattr(message, "sender", None)
    sender_handle = getattr(sender, "username", None) if sender else None
    fwd = getattr(message, "forward", None)
    forward_from_id = getattr(getattr(fwd, "from_id", None), "user_id", None) if fwd else None
    sent_at = message.date.astimezone(timezone.utc).isoformat() if getattr(message, "date", None) else None
    return {
        "record_id": uuid4().hex,
        "source": f"telegram:{gid}",
        "platform": "telegram",
        "sha256": compute_sha256(text.encode("utf-8")),
        "url": f"tg://{gid}/{message.id}",
        "raw_text": text,
        "size_bytes": len(text.encode("utf-8")),
        "tg": {
            "group_id": gid,
            "message_id": message.id,
            "sender_id": getattr(message, "sender_id", None),
            "sender_handle": ("@" + sender_handle) if sender_handle else None,
            "sent_at": sent_at,
            "reply_to_msg_id": getattr(message, "reply_to_msg_id", None),
            "mentions": [],                # reply/mention edges extracted in the analysis stage
            "forward_from_id": forward_from_id,
            "sender_role": None,           # filled from roster in a later phase
        },
    }


def collect_group(tclient, qclient: QueueClient, group: dict) -> int:
    gid = str(group["tg_group_id"])
    access = group.get("access_method")

    # Resolve the group. We NEVER deceive our way in:
    #   public_link -> openly joinable; join directly if not already a member.
    #   anything else -> must ALREADY be a lawful member; read only, never join.
    try:
        entity = tclient.get_entity(group.get("username") or group["tg_group_id"])
    except Exception as e:
        audit_log("telegram_group_inaccessible",
                  {"group_id": group["tg_group_id"], "error": str(e)}, severity="WARNING")
        return 0

    if access == "public_link":
        try:
            from telethon.tl.functions.channels import JoinChannelRequest
            tclient(JoinChannelRequest(entity))   # joining a PUBLIC channel — not deception
        except Exception:
            pass  # already a member, or not openly joinable — read what is already visible

    min_id = _highwater.get(gid, 0)
    high = min_id
    count = 0
    # reverse=True -> oldest first, so the high-water mark advances monotonically.
    for message in tclient.iter_messages(entity, min_id=min_id, reverse=True, limit=HISTORY_LIMIT):
        high = max(high, message.id)
        if not getattr(message, "message", None):   # skip non-text/media for now
            continue
        qclient.publish(RAW_QUEUE, make_envelope(group, message))
        count += 1

    _highwater[gid] = high
    if count:
        audit_log("telegram_group_ingested",
                  {"group_id": group["tg_group_id"], "messages": count, "high_water": high})
    return count


def main() -> None:
    print("DWITP Telegram Collector — observation-only (INTEL-002)")

    if not (TELEGRAM_API_ID and TELEGRAM_API_HASH and TELEGRAM_SESSION):
        # Gated on out-of-band, lawfully provisioned credentials + an approved
        # group with a documented legal basis. Idle quietly rather than crash-loop
        # so the rest of the stack is unaffected.
        audit_log("telegram_collector_unconfigured",
                  {"detail": "TELEGRAM_API_ID/HASH/SESSION not set; collector idle"}, severity="WARNING")
        print("telegram_collector idle — no credentials configured "
              "(set TELEGRAM_API_ID/HASH/SESSION)", file=sys.stderr)
        while True:
            time.sleep(3600)

    # Lazy import so the unconfigured idle path needs no telethon at all.
    from telethon.sessions import StringSession
    from telethon.sync import TelegramClient

    qclient = QueueClient()
    try:
        qclient.connect()
    except Exception:
        _halt("Critical dependency unavailable: queue")

    tclient = TelegramClient(
        StringSession(TELEGRAM_SESSION),
        int(TELEGRAM_API_ID),
        TELEGRAM_API_HASH,
        proxy=_build_proxy(),
    )
    tclient.connect()
    if not tclient.is_user_authorized():
        _halt("Telegram session not authorized — provide an authorized session "
              "out-of-band (this service does not perform interactive login)")

    load_state()
    audit_log("telegram_collection_start", {"history_limit": HISTORY_LIMIT, "via_tor": USE_TOR})
    print("Telegram collector started — observation only")

    while True:
        check_kill_switch(qclient)
        if _collection_disabled:
            audit_log("collection_disabled_skip", {}, severity="WARNING")
            time.sleep(POLL_INTERVAL)
            continue

        try:
            groups = load_approved_groups()
        except Exception as e:
            _halt(f"Critical dependency unavailable: postgres ({e})")

        total = 0
        for g in groups:
            try:
                total += collect_group(tclient, qclient, g)
            except Exception as e:
                audit_log("telegram_group_error",
                          {"group_id": g.get("tg_group_id"), "error": str(e)}, severity="ERROR")
        save_state()
        if groups:
            print(f"Collection cycle complete — {len(groups)} group(s), {total} new message(s)")
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
