from __future__ import annotations

import sys

from src.common.queue import QueueClient
from src.common.security import injection_gateway, normalize_text, safe_parse


def process_raw_record(message: dict, client: QueueClient) -> None:
    record_id = message.get("record_id", "unknown")
    source = message.get("source", "unknown")
    raw_text = message.get("raw_text", "")

    parsed = safe_parse(raw_text)
    safe_text = str(parsed)

    sanitized_text, detected = injection_gateway(safe_text, record_id, source)
    sanitized_text = normalize_text(sanitized_text)

    sanitized_record = {
        "record_id": record_id,
        "source": source,
        "url": message.get("url", ""),
        "sha256": message.get("sha256", ""),
        "collected_at": message.get("timestamp_utc", ""),
        "raw_text": message.get("raw_text", ""),  # original crawled HTML — passed through for storage
        "content_sanitized": sanitized_text,
        "injection_patterns_detected": detected,
        "risk_score": message.get("risk_score", 0.5),
        "sanitized_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
    }

    # Telegram records (telegram.raw) carry a platform marker + a `tg` block that
    # must survive to db_writer. Pass them through untouched (INTEL-002).
    if message.get("platform"):
        sanitized_record["platform"] = message["platform"]
    if message.get("tg"):
        sanitized_record["tg"] = message["tg"]

    client.publish("sanitized", sanitized_record)


def main() -> None:
    print("DWITP Sanitizer started — waiting for raw.crawl / telegram.raw messages")
    client = QueueClient()
    cb = lambda msg: process_raw_record(msg, client)
    try:
        client.consume_multi_with_retry([("raw.crawl", cb), ("telegram.raw", cb)])
    except KeyboardInterrupt:
        print("Sanitizer stopped by operator")
        sys.exit(0)
    finally:
        client.close()


if __name__ == "__main__":
    main()
