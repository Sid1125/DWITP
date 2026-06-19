from __future__ import annotations

import os
import re
import sys

import spacy

from src.common.queue import QueueClient

SPACY_MODEL = os.environ.get("SPACY_MODEL", "en_core_web_sm")

try:
    nlp = spacy.load(SPACY_MODEL)
except OSError:
    print(f"Downloading spaCy model: {SPACY_MODEL}")
    spacy.cli.download(SPACY_MODEL)
    nlp = spacy.load(SPACY_MODEL)


CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
BTC_PATTERN = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
XMR_PATTERN = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")
ETH_PATTERN = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
DOMAIN_PATTERN = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PGP_PATTERN = re.compile(r"-----BEGIN PGP (?:PUBLIC|PRIVATE) KEY BLOCK-----[\s\S]+?-----END PGP (?:PUBLIC|PRIVATE) KEY BLOCK-----")
TELEGRAM_PATTERN = re.compile(r"@(\w{5,32})\b")
JABBER_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.(?:jabber|xmpp)\b", re.IGNORECASE)
ONION_PATTERN = re.compile(r"\b[a-z2-7]{16,}\.onion\b", re.IGNORECASE)


def extract_entities(text: str) -> dict:
    entities = {
        "cves": list(set(CVE_PATTERN.findall(text))),
        "btc_addresses": list(set(BTC_PATTERN.findall(text))),
        "xmr_addresses": list(set(XMR_PATTERN.findall(text))),
        "eth_addresses": list(set(ETH_PATTERN.findall(text))),
        "email_addresses": [],
        "domains": [],
        "ip_addresses": [],
        "pgp_fingerprints": [],
        "telegram_handles": list(set(TELEGRAM_PATTERN.findall(text))),
        "jabber_ids": list(set(JABBER_PATTERN.findall(text))),
        "onion_addresses": list(set(ONION_PATTERN.findall(text))),
    }

    email_matches = EMAIL_PATTERN.findall(text)
    for email in set(email_matches):
        entities["email_addresses"].append({
            "address": email,
            "domain": email.split("@")[1] if "@" in email else "",
        })

    domain_matches = DOMAIN_PATTERN.findall(text)
    email_domains = {e["domain"] for e in entities["email_addresses"]}
    for domain in set(domain_matches):
        if domain not in email_domains:
            parts = domain.rsplit(".", 1)
            tld = parts[1] if len(parts) == 2 and len(parts[1]) >= 2 else ""
            entities["domains"].append({"domain": domain, "tld": tld})

    ip_matches = IP_PATTERN.findall(text)
    for ip in set(ip_matches):
        if all(0 <= int(octet) <= 255 for octet in ip.split(".")):
            entities["ip_addresses"].append(ip)

    pgp_matches = PGP_PATTERN.findall(text)
    for pgp_block in pgp_matches:
        entities["pgp_fingerprints"].append({
            "fingerprint": __import__("hashlib").sha256(pgp_block.encode()).hexdigest()[:40],
            "block_length": len(pgp_block),
        })

    doc = nlp(text[:100000])
    for ent in doc.ents:
        if ent.label_ == "PERSON" and len(ent.text) > 3:
            if "persons" not in entities:
                entities["persons"] = []
            if ent.text not in [p.get("name") for p in entities.get("persons", [])]:
                entities.setdefault("persons", []).append({"name": ent.text})

    return entities


def process_sanitized_record(message: dict, client: QueueClient) -> None:
    content = message.get("content_sanitized", "")
    record_id = message.get("record_id", "unknown")
    source = message.get("source", "unknown")

    entities = extract_entities(content)

    analysis_result = {
        "record_id": record_id,
        "source": source,
        "url": message.get("url", ""),
        "sha256": message.get("sha256", ""),
        "title": "",
        "author": None,
        "timestamp_posted": message.get("collected_at"),
        "entities": entities,
        "raw_text": message.get("raw_text", ""),  # original crawled HTML — passed through for storage
        "content_sanitized": content,
        "risk_score": message.get("risk_score", 0.5),
        "injection_patterns_detected": message.get("injection_patterns_detected", 0),
        "has_intelligence": len(entities.get("cves", [])) > 0
            or len(entities.get("btc_addresses", [])) > 0
            or len(entities.get("email_addresses", [])) > 0,
    }

    # Telegram passthrough + edge enrichment (INTEL-002 / T2.1): promote the
    # @handles extracted from the message text into the `tg` block's mention edges.
    if message.get("platform"):
        analysis_result["platform"] = message["platform"]
    tg = message.get("tg")
    if tg:
        tg = dict(tg)
        tg["mentions"] = entities.get("telegram_handles", [])
        analysis_result["tg"] = tg

    client.publish("analysis.ready", analysis_result)

    onion_urls = entities.get("onion_addresses", [])
    if onion_urls:
        for onion_url in onion_urls:
            from src.common.models import DiscoveredCandidate
            candidate = DiscoveredCandidate(
                url=f"http://{onion_url}",
                discovered_from=source,
            )
            client.publish("discovery.candidate", candidate.model_dump())


def main() -> None:
    print("DWITP Analysis layer started — waiting for sanitized messages")
    client = QueueClient()
    try:
        client.consume_with_retry("sanitized", lambda msg: process_sanitized_record(msg, client))
    except KeyboardInterrupt:
        print("Analysis stopped by operator")
        sys.exit(0)
    finally:
        client.close()


if __name__ == "__main__":
    main()
