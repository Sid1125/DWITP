from __future__ import annotations

import hashlib
import hmac
import html
import inspect
import json
import logging
import os
import random
import re
import secrets
import socket
import time
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from urllib.parse import urlparse

try:
    import ipaddress
except ImportError:
    ipaddress = None  # type: ignore[assignment]

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None  # type: ignore[assignment,misc]

AUDIT_LOG_PATH = os.environ.get("DWITP_AUDIT_LOG", "/var/log/dwitp/audit.log")
_AUDIT_ENCRYPTION_KEY = os.environ.get("AUDIT_ENCRYPTION_KEY", "")
if not _AUDIT_ENCRYPTION_KEY:
    import sys
    print("FATAL: AUDIT_ENCRYPTION_KEY environment variable is required for audit log encryption.")
    sys.exit(1)
AUDIT_ENCRYPTION_KEY = _AUDIT_ENCRYPTION_KEY.encode("utf-8")

from cryptography.fernet import Fernet, InvalidToken  # noqa: E402 — needs AUDIT_ENCRYPTION_KEY first


INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"disregard\s+(your\s+)?(previous\s+)?instructions",
    # Tightened to require an AI/role-injection target. The original bare
    # `you are now (a)?` and `act as (a)?` matched everyday darknet-market
    # vocabulary ("you are now a verified vendor", "act as a middleman"), which
    # false-positived constantly and kept tripping the PI-campaign kill switch
    # on benign forum text. These now only fire on actual jailbreak phrasing.
    r"you\s+are\s+now\s+(an?\s+)?(ai|assistant|chatbot|language\s+model|dan\b|different|new\s+(ai|assistant|model))",
    r"act\s+as\s+(an?\s+)?(ai|assistant|chatbot|language\s+model|dan\b|jailbreak|unrestricted|developer\s+mode)",
    r"new\s+instructions\s*:",
    r"system\s+prompt\s*:",
    # Require an instruction/directive object, not a bare "override" (which hit
    # benign text like "price override").
    r"override\s+(your\s+|the\s+)?(previous\s+)?(instructions|directives|system\s+prompt|programming|guidelines|rules)",
    r"download\s+this\s+file",
    r"visit\s+this\s+url",
    r"run\s+this\s+command",
    # Require a command/code object, not a bare "execute " (which hit "execute
    # the trade", "executed", "execution").
    r"execute\s+(the\s+)?(following|this|attached|command|code|script|payload|instructions?)",
    r"<\s*script",
    r"javascript\s*:",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
]

ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.8,en-US;q=0.7",
    "en-US,en;q=0.5",
    "en-US,en;q=0.9,fr;q=0.8",
    "en-CA,en;q=0.9,en-US;q=0.8",
]

ALLOWED_SCHEMES = {"http", "https"}
BLOCKED_SCHEMES = {"file", "ftp", "smb", "ldap", "gopher", "data", "javascript", "vbscript", "jar"}

HIGH_RISK_CATEGORIES = {
    "ransomware",
    "malware_sale",
    "credential_leak",
    "access_broker",
    "data_leak",
    "scam",
    "drug_trafficking",
    "weapons_trafficking",
    "terrorism_extremism",
    "human_trafficking",
    # New categories (THREAT_LEXICON.md) — all become reviewable findings.
    "counterfeit_documents",
    "financial_fraud",
    "identity_theft",
    "exploit_trading",
    "phishing_kits",
    "malware_botnet_rental",
    "money_laundering",
    "insider_threat",
    "cyber_espionage",
}

# Categories whose content must NEVER be retained. A hit is detected only to drop the
# content, audit a CRITICAL escalation, and route to the incident playbook (TG-G4 /
# IR-001). db_writer intercepts these BEFORE any raw_evidence/classification/finding
# is written. `child_exploitation` is deliberately NOT in HIGH_RISK_CATEGORIES so it
# can never fall through to the normal (content-retaining) findings path.
QUARANTINE_CATEGORIES = {
    "child_exploitation",
}

# Categories where a hit should never just sit in the routine review queue —
# they require immediate escalation outside this tool (legal counsel / law
# enforcement liaison), not casual analyst browsing.
IMMEDIATE_ESCALATION_CATEGORIES = {
    "terrorism_extremism",
    "human_trafficking",
    "child_exploitation",
}

# Category claims that aren't backed by at least one of these literal anchors in the
# sanitized text are almost certainly model hallucination (e.g. a forum profile page
# with a "PGP Key" tab getting classified as access_broker with no access-for-sale text
# anywhere on the page). categories with no anchor list (e.g. "unknown") are unconstrained.
CATEGORY_ANCHORS: dict[str, list[str]] = {
    "ransomware": [r"ransom", r"encrypt(ed|ion)?", r"decrypt(or|ion)?", r"leak\s*site", r"negotiat"],
    "malware_sale": [r"malware", r"stealer", r"\brat\b", r"crypter", r"loader", r"trojan", r"botnet"],
    "credential_leak": [r"password", r"login\s*:", r"@\S+:\S+", r"combo\s*list", r"dump"],
    "access_broker": [r"\brdp\b", r"\bvpn\b", r"domain\s*admin", r"shell\s*access", r"initial\s*access",
                       r"network\s*access", r"\bvps\b", r"citrix", r"remote\s*desktop"],
    "data_leak": [r"breach", r"leaked?\s*(data|documents?|database)", r"confidential", r"exfiltrat"],
    "scam": [r"\bscam\b", r"phishing", r"counterfeit", r"stolen"],
    "drug_trafficking": [r"\b(cocaine|heroin|fentanyl|mdma|lsd|meth(amphetamine)?|ketamine|cannabis|"
                          r"marijuana|weed|opioid|narcotic)s?\b", r"\bgrams?\b.*\$", r"shipping\s*(usa|worldwide|stealth)"],
    "weapons_trafficking": [r"\b(firearms?|pistols?|rifles?|handguns?|ammo|ammunition|explosives?|grenades?)\b",
                             r"\bglock\b", r"\bak[\s-]?47\b", r"untraceable\s*weapon"],
    "terrorism_extremism": [r"\b(jihad|attack\s*plan|manifesto|martyrdom|extremist|radicali[sz]ation)\b",
                             r"bomb\s*making", r"recruit(ment|ing)?\s*for", r"caliphate"],
    "human_trafficking": [r"\b(trafficking|smuggl(e|ing)|forced\s*labor|debt\s*bondage)\b",
                           r"\bescort\b.*\b(minor|underage)\b", r"sell(ing)?\s*(a\s*)?(girl|boy|woman|person)\b"],
}


def category_is_grounded(category: str, text: str) -> bool:
    anchors = CATEGORY_ANCHORS.get(category)
    if not anchors:
        return True
    lower_text = text.lower()
    return any(re.search(pattern, lower_text, re.IGNORECASE) for pattern in anchors)


def quote_is_grounded(quote: str, text: str) -> bool:
    """General-purpose anti-hallucination check, independent of category: the model must
    point to a literal snippet of the source page that backs its classification. Unlike
    CATEGORY_ANCHORS (a fixed keyword list per known category), this works for any page,
    any category, any future category — if the model can't quote something real, its
    classification isn't grounded in the page, regardless of how it's phrased.
    """
    quote = re.sub(r"\s+", " ", quote).strip().lower()
    if len(quote) < 8:
        return False
    normalized_text = re.sub(r"\s+", " ", text).strip().lower()
    return quote in normalized_text


# Curated anchors for the keyword-grounded FALLBACK classifier (distinct from
# CATEGORY_ANCHORS, which only *validates* an LLM claim). These are deliberately
# narrow: only specific, high-harm vocabulary that does NOT appear in ordinary
# forum chrome. Generic categories (credential_leak/access_broker/data_leak/scam)
# are intentionally excluded — their vocabulary ("password", "login:", "dump",
# "vpn") matches login forms and nav on every page and produces pure noise. Order
# is priority: when a page matches several, the most urgent category wins.
FALLBACK_ANCHORS: "dict[str, list[str]]" = {
    "terrorism_extremism": [r"\bjihad", r"\bmartyrdom\b", r"\bcaliphate\b", r"\bmanifesto\b",
                             r"bomb\s*making", r"attack\s*plan", r"extremist\s*recruit"],
    "human_trafficking": [r"human\s*trafficking", r"sex\s*trafficking", r"forced\s*labou?r",
                           r"debt\s*bondage", r"sell(ing)?\s*(a\s*)?(girl|boy|woman|child|person)\b"],
    "weapons_trafficking": [r"\b(firearms?|pistols?|rifles?|handguns?|ammunition|\bammo\b|"
                             r"explosives?|grenades?)\b", r"\bglock\b", r"\bak[\s-]?47\b",
                             r"untraceable\s*weapon"],
    "ransomware": [r"ransomware", r"ransom\s*note", r"\bdecryptor\b", r"leak\s*site",
                    r"ransomware[\s-]*as[\s-]*a[\s-]*service\b"],
    "malware_sale": [r"\bstealer\b", r"\binfostealer\b", r"\bbotnet\b", r"\bcrypter\b",
                      r"\btrojan\b", r"\bkeylogger\b", r"\bransomware\s*builder\b"],
    "drug_trafficking": [r"\b(cocaine|heroin|fentanyl|mdma|\blsd\b|ketamine|cannabis|"
                          r"methamphetamine|\bmeth\b|opioids?|narcotics?|adderall|xanax|"
                          r"oxycodone|oxycontin)\b"],
}


def infer_category_from_anchors(text: str, anchors: "dict[str, list[str]] | None" = None) -> "tuple[str, list[str]] | None":
    """Keyword-grounded fallback classifier.

    When the LLM cannot place a page (returns 'unknown'), scan the literal page
    text for specific high-harm vocabulary. A match means the page genuinely
    *contains* the category's terms (cocaine, glock, infostealer, ...), so
    flagging it for human review is grounded in the page — not invented by the
    model.

    `anchors` defaults to FALLBACK_ANCHORS (curated strong terms). The dict is
    evaluated in priority order: the first category with any match wins, so a page
    mentioning both weapons and drugs surfaces as the more urgent weapons hit.
    Returns (category, matched_patterns) or None.
    """
    if anchors is None:
        anchors = FALLBACK_ANCHORS
    lower_text = text.lower()
    for category, patterns in anchors.items():
        matched = [p for p in patterns if re.search(p, lower_text, re.IGNORECASE)]
        if matched:
            return (category, matched)
    return None

TOR_PROXY = {
    "http": "socks5h://127.0.0.1:9050",
    "https": "socks5h://127.0.0.1:9050",
}

MAX_PAGE_SIZE_BYTES = 5 * 1024 * 1024
MAX_CRAWL_DEPTH = 5
MAX_REDIRECTS = 3
REQUEST_TIMEOUT_SEC = 30
MAX_PAGES_PER_SITE_PER_HOUR = 100


def _get_fernet() -> Fernet:
    return Fernet(AUDIT_ENCRYPTION_KEY)


def encrypt_log_entry(entry: dict[str, object]) -> str:
    plaintext = json.dumps(entry).encode("utf-8")
    return _get_fernet().encrypt(plaintext).decode("utf-8")


def decrypt_log_entry(line: str) -> dict[str, object]:
    try:
        plaintext = _get_fernet().decrypt(line.encode("utf-8"))
        return json.loads(plaintext)
    except InvalidToken:
        return json.loads(line)


_audit_logger: logging.Logger | None = None


def reset_audit_logger() -> None:
    global _audit_logger
    logger = logging.getLogger("dwitp.audit")
    for h in logger.handlers[:]:
        h.close()
        logger.removeHandler(h)
    _audit_logger = None


def _get_audit_logger() -> logging.Logger:
    global _audit_logger
    if _audit_logger is not None:
        return _audit_logger

    logger = logging.getLogger("dwitp.audit")
    logger.handlers.clear()
    logger.setLevel(logging.INFO)

    os.makedirs(os.path.dirname(AUDIT_LOG_PATH), exist_ok=True)
    handler = RotatingFileHandler(AUDIT_LOG_PATH, maxBytes=10 * 1024 * 1024, backupCount=5)
    handler.setLevel(logging.INFO)

    class EncryptedFormatter(logging.Formatter):
        def format(self, record: logging.LogRecord) -> str:
            return record.getMessage()

    handler.setFormatter(EncryptedFormatter())
    logger.addHandler(handler)
    _audit_logger = logger
    return logger


def audit_log(event_type: str, details: dict[str, object], severity: str = "INFO", component: str = "") -> None:
    if not component:
        frame = inspect.currentframe()
        if frame:
            frame = frame.f_back
            mod = inspect.getmodule(frame)
            if mod:
                component = mod.__name__

    entry = {
        "event": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "severity": severity,
        "component": component,
        "details": details,
    }
    encrypted = encrypt_log_entry(entry)
    _get_audit_logger().info(encrypted)

    if severity == "CRITICAL":
        try:
            from src.common.notifier import notify_critical
            notify_critical(event_type, details)
        except Exception:
            pass


PRIVATE_RANGES_V4 = [
    ("127.0.0.0", "127.255.255.255"),
    ("10.0.0.0", "10.255.255.255"),
    ("172.16.0.0", "172.31.255.255"),
    ("192.168.0.0", "192.168.255.255"),
    ("169.254.0.0", "169.254.255.255"),
    ("0.0.0.0", "0.255.255.255"),
]

PRIVATE_RANGES_V6 = [
    ("::1", "::1"),
    ("fc00::", "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
    ("fe80::", "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
]


def _is_private_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    if isinstance(addr, ipaddress.IPv4Address):
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast:
            return True
        return any(
            ipaddress.IPv4Address(start) <= addr <= ipaddress.IPv4Address(end)
            for start, end in PRIVATE_RANGES_V4
        )

    if isinstance(addr, ipaddress.IPv6Address):
        if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_private:
            return True
        return any(
            ipaddress.IPv6Address(start) <= addr <= ipaddress.IPv6Address(end)
            for start, end in PRIVATE_RANGES_V6
        )

    return False


def validate_url(url: str, allow_onion: bool = True) -> bool:
    parsed = urlparse(url)

    if not parsed.hostname:
        raise ValueError("URL has no hostname")

    if parsed.scheme in BLOCKED_SCHEMES:
        raise ValueError(f"Blocked scheme: {parsed.scheme}")

    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ValueError(f"Unknown scheme: {parsed.scheme}")

    hostname = parsed.hostname

    if hostname.endswith(".onion"):
        if not allow_onion:
            raise ValueError(".onion URLs not allowed: {hostname}")
        return True

    if ipaddress is None:
        raise ImportError("ipaddress module required for URL validation")

    try:
        resolved = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        raise ValueError(f"DNS resolution failed for {hostname}: {e}") from e

    seen = set()
    for _, _, _, _, sockaddr in resolved:
        ip_str = str(sockaddr[0])
        if ip_str in seen:
            continue
        seen.add(ip_str)

        if _is_private_ip(ip_str):
            raise ValueError(f"SSRF blocked: {hostname} resolves to private IP {ip_str}")

    if not seen:
        raise ValueError(f"No addresses resolved for {hostname}")

    return True


REDIRECT_STATUSES = {301, 302, 303, 307, 308}


CONFIDENCE_LEVELS = {
    "LOW": (0.0, 0.49),
    "MEDIUM": (0.5, 0.79),
    "HIGH": (0.8, 1.0),
}


def confidence_label(score: float) -> str:
    if score < 0.5:
        return "LOW"
    if score < 0.8:
        return "MEDIUM"
    return "HIGH"


def normalize_text(text: str) -> str:
    text = html.unescape(text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def sanitize_for_llm(raw_content: str) -> str:
    text = html.unescape(raw_content)
    text = re.sub(r"<script[^>]*>.*?</script>", "", text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<style[^>]*>.*?</style>", "", text, flags=re.DOTALL | re.IGNORECASE)
    # Strip Dread / forum div-level chrome (matched before general tag stripping)
    text = re.sub(r'<div class="jsWarning">.*?</div>', "", text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<div class="no_auth">.*?</div>', "", text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<[^>]+>", "", text)
    # Strip the Dread JS-enabled warning that appears as plain text in authenticated sessions
    # (not wrapped in jsWarning div when cookies are set, so the div-level strip above misses it)
    text = re.sub(
        r"Warning!?\s*You have JavaScript enabled[^.!]*[.!]?\s*Please disable it\s*immediately!?",
        "",
        text,
        flags=re.IGNORECASE,
    )
    # Strip leftover boilerplate fragments that form-stripping in safe_parse may not have caught
    # (e.g. plain-text "Rotate Reset Next" from CAPTCHA widgets, "Stay logged in" etc.)
    text = re.sub(r"\b(Rotate|Reset|I am not a bot|Stay logged in|Night mode|Canary)\b", "", text, flags=re.IGNORECASE)
    # Profile-card and forum-footer chrome that survives as plain text even after
    # class/id-based stripping in safe_parse (e.g. "Joined 10 hours ago", "1 points",
    # link-farm footers like "What is dread? Harm Reduction Fundraising Advertise...").
    text = re.sub(r"\bJoined\s+\d+\s+(minutes?|hours?|days?|weeks?|months?|years?)\s+ago\b", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\bCreated\s+\d+\s+(minutes?|hours?|days?|weeks?|months?|years?)\s+ago\b", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\b\d+\s+(points|posts|comments|subscribers)\b", "", text, flags=re.IGNORECASE)
    text = re.sub(
        r"\b(What is \w+\?|Harm Reduction|Fundraising|Advertise here|Advertise|Contact us|Site rules|"
        r"Donate|Privacy|Dreadiquette|Market Standards|Top Donators)\b",
        "", text, flags=re.IGNORECASE,
    )
    text = re.sub(r"https?://\S+", "[URL REDACTED]", text)
    text = re.sub(r"[a-z2-7]{16,}\.onion\S*", "[ONION REDACTED]", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:2000]


def injection_gateway(text: str, record_id: str, source: str) -> tuple[str, list[str]]:
    text = html.unescape(text)
    detected: list[str] = []
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            detected.append(pattern)
            text = re.sub(pattern, "[CONTENT REDACTED]", text, flags=re.IGNORECASE)

    if detected:
        audit_log("prompt_injection_detected", {
            "source": source,
            "record_id": record_id,
            "patterns": detected,
        }, severity="WARNING")

    return text, detected


def compute_intelligence_confidence(
    ai_raw_score: float,
    source_reputation: float,
    corroborating_sources: int,
    historical_accuracy: float,
) -> float:
    cross_source_factor = min(1.0, 0.5 + (corroborating_sources * 0.25))
    confidence = ai_raw_score * source_reputation * cross_source_factor * historical_accuracy
    return round(min(confidence, 1.0), 3)


MITRE_ATTACK_CATEGORY_MAP: dict[str, list[str]] = {
    "ransomware": ["T1486"],
    "malware_sale": ["T1059"],
    "credential_leak": ["T1003"],
    "access_broker": ["T1078"],
    "scam": ["T1566"],
    "data_leak": ["T1003"],
}

# Entity-based ATT&CK mapping is not yet implemented.
# Future work: map entities (e.g., CVE IDs, email addresses,
# cryptocurrency wallets) to techniques via context-aware analysis.
# Naive one-to-one entity→technique mappings were removed because
# they were not defensible (e.g., a BTC address does not imply T1078).


def map_to_mitre_attack(category: str) -> list[str]:
    return list(MITRE_ATTACK_CATEGORY_MAP.get(category, []))


# Many forum/market sites (e.g. Dread) implement chrome — sidebars, profile tabs, login
# boxes, footer link farms — as plain <div>/<ul> elements rather than semantic
# nav/header/footer tags, so tag-name stripping alone misses them. Catch those by
# class/id substring instead.
BOILERPLATE_CLASS_MARKERS = [
    "sidebar", "footer", "header", "navbar", "nav-", "profile-nav", "profile-tab",
    "login", "menu", "breadcrumb", "pagination", "cookie", "banner", "advert",
    "share-buttons", "social-links", "captcha", "no_auth", "jswarning",
]


def _has_boilerplate_marker(tag) -> bool:
    attrs = " ".join(tag.get("class", []) or []) + " " + str(tag.get("id", ""))
    attrs = attrs.lower()
    return any(marker in attrs for marker in BOILERPLATE_CLASS_MARKERS)


def safe_parse(html_content: str) -> BeautifulSoup:
    if BeautifulSoup is None:
        raise ImportError("beautifulsoup4 is required for safe_parse")

    soup = BeautifulSoup(html_content, "lxml")
    for tag in soup.find_all([
        # Media / external references
        "img", "script", "iframe", "video", "audio", "object", "embed", "link", "source",
        # Page chrome — navigation, headers, footers are boilerplate, not intelligence content
        "nav", "header", "footer", "noscript",
        # Form elements — login/search forms inject labels like "Username" / "Password"
        # that confuse the LLM into classifying login pages as credential leaks or phishing.
        # Stripping here keeps them out of content_sanitized (what the LLM sees) while
        # leaving the original raw_text untouched for the finding detail iframe.
        "form", "input", "button", "label", "select", "textarea",
    ]):
        tag.decompose()

    for tag in soup.find_all(True):
        if tag.parent is None:
            continue
        if _has_boilerplate_marker(tag):
            tag.decompose()

    return soup


def randomized_headers() -> dict[str, str]:
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept-Language": random.choice(ACCEPT_LANGUAGES),
        "Accept-Encoding": "gzip, deflate",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Connection": "keep-alive",
    }


def jittered_delay(base: float = 3.0, spread: float = 2.5) -> None:
    time.sleep(base + random.uniform(0, spread))


def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


PBKDF2_ITERATIONS = 260_000


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algo, iterations_str, salt, hex_digest = stored_hash.split("$")
        if algo != "pbkdf2_sha256":
            return False
        iterations = int(iterations_str)
    except ValueError:
        return False
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), iterations)
    return hmac.compare_digest(digest.hex(), hex_digest)
