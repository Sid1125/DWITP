from __future__ import annotations

import os
import socket
import sys
import time
import urllib.parse
import warnings

import requests
import yaml
from bs4 import BeautifulSoup

from src.common.models import CrawlTarget
from src.common.queue import QueueClient
from src.common.security import (
    MAX_PAGE_SIZE_BYTES,
    MAX_REDIRECTS,
    REDIRECT_STATUSES,
    REQUEST_TIMEOUT_SEC,
    audit_log,
    compute_sha256,
    jittered_delay,
    randomized_headers,
    validate_url,
)

warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

TOR_HOST = os.environ.get("TOR_PROXY_HOST", "tor")
TOR_PORT = int(os.environ.get("TOR_PROXY_PORT", "9050"))
TOR_CONTROL_PORT = int(os.environ.get("TOR_CONTROL_PORT", "9051"))
TOR_CONTROL_PASSWORD = os.environ.get("TOR_CONTROL_PASSWORD", "")
TOR_HOST_IP = socket.gethostbyname(TOR_HOST)
SOURCES_CONFIG = os.environ.get("SOURCES_CONFIG", "/app/config/sources.yaml")
CRAWLER_IDENTITY = os.environ.get("CRAWLER_IDENTITY", "crawler-01")
CIRCUIT_ROTATION_INTERVAL = int(os.environ.get("CIRCUIT_ROTATION_INTERVAL", "15"))
MIN_CONTENT_LENGTH = int(os.environ.get("MIN_CONTENT_LENGTH", "200"))
SEEN_URLS_FILE = os.environ.get("SEEN_URLS_FILE", "/var/log/dwitp/seen_urls.txt")
DREAD_COOKIES_FILE = os.environ.get("DREAD_COOKIES_FILE", "/var/log/dwitp/dread_cookies.txt")

DREAD_USERNAME = os.environ.get("DREAD_USERNAME", "")
DREAD_PASSWORD = os.environ.get("DREAD_PASSWORD", "")

PROXY = {
    "http": f"socks5h://{TOR_HOST}:{TOR_PORT}",
    "https": f"socks5h://{TOR_HOST}:{TOR_PORT}",
}

_requests_since_circuit_rotation = 0
_publish_buffer: list[dict] = []
_seen_urls: set[str] = set()


def load_seen_urls() -> None:
    global _seen_urls
    try:
        with open(SEEN_URLS_FILE, "r") as f:
            _seen_urls = {line.strip() for line in f if line.strip()}
        print(f"Loaded {len(_seen_urls)} previously seen URLs")
    except FileNotFoundError:
        _seen_urls = set()


def save_seen_urls() -> None:
    try:
        with open(SEEN_URLS_FILE, "w") as f:
            for url in sorted(_seen_urls):
                f.write(url + "\n")
        print(f"Saved {len(_seen_urls)} seen URLs to disk")
    except OSError as e:
        audit_log("seen_urls_save_error", {"error": str(e)}, severity="WARNING")


def load_dread_cookies(session: requests.Session) -> bool:
    try:
        with open(DREAD_COOKIES_FILE, "r") as f:
            count = 0
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("\t")
                if len(parts) >= 7:
                    domain, _, path, secure, expires, name, value = parts[:7]
                    # Netscape format uses expires=0 for a SESSION cookie (no expiry).
                    # Passing 0 through sets epoch 1970, which the cookiejar treats as
                    # already-expired and never sends — silently dropping Dread's
                    # `dread` session cookie so every fetch came back a login wall.
                    # Map 0 (and any non-positive) to None = session cookie.
                    exp = int(expires) if expires.isdigit() else 0
                    session.cookies.set(
                        name=name,
                        value=value,
                        domain=domain,
                        path=path,
                        secure=secure.lower() == "true",
                        expires=exp if exp > 0 else None,
                    )
                    count += 1
        if count > 0:
            print(f"Loaded {count} dread cookies")
            return True
    except FileNotFoundError:
        pass
    except Exception as e:
        audit_log("dread_cookies_load_error", {"error": str(e)}, severity="WARNING")
    return False


def dread_login(session: requests.Session, target: CrawlTarget) -> bool:
    if not DREAD_USERNAME or not DREAD_PASSWORD:
        return False
    try:
        resp = session.post(
            target.url.rstrip("/") + "/auth/login/noload",
            data={"username": DREAD_USERNAME, "password": DREAD_PASSWORD},
            proxies=PROXY,
            timeout=REQUEST_TIMEOUT_SEC,
            allow_redirects=False,
        )
        if resp.status_code in (302, 303, 307, 308):
            audit_log("dread_login_redirect", {"location": resp.headers.get("Location", ""), "status": resp.status_code})
            return True
        if "captcha" in resp.text.lower():
            audit_log("dread_login_captcha", {"status": resp.status_code}, severity="WARNING")
            return False
        return False
    except Exception as e:
        audit_log("dread_login_error", {"error": str(e)}, severity="ERROR")
        return False


def flush_publish_buffer(client: QueueClient) -> None:
    if not _publish_buffer:
        return
    remaining: list[dict] = []
    for record in _publish_buffer:
        try:
            client.publish("raw.crawl", record)
        except Exception:
            remaining.append(record)
    _publish_buffer[:] = remaining


def publish_or_buffer(client: QueueClient, queue: str, record: dict) -> None:
    try:
        client.publish(queue, record)
    except Exception as e:
        _publish_buffer.append(record)
        audit_log("queue_publish_buffered", {
            "queue": queue,
            "record_id": record.get("record_id", "unknown"),
            "buffer_size": len(_publish_buffer),
            "error": str(e),
        }, severity="WARNING")


def rotate_tor_circuit() -> None:
    global _requests_since_circuit_rotation
    try:
        from stem import Signal
        from stem.control import Controller

        kwargs = {"port": TOR_CONTROL_PORT, "address": TOR_HOST_IP}
        with Controller.from_port(**kwargs) as controller:
            controller.authenticate(password=TOR_CONTROL_PASSWORD if TOR_CONTROL_PASSWORD else None)
            controller.signal(Signal.NEWNYM)

        _requests_since_circuit_rotation = 0
        audit_log("tor_circuit_rotated", {})
    except ImportError:
        pass
    except Exception as e:
        audit_log("tor_circuit_rotation_failed", {"error": str(e)}, severity="ERROR")


class CrawlerGuard:
    def assert_nominal(self, session: requests.Session) -> None:
        checks = {
            "tor": self._verify_tor_active,
            "queue": self._verify_queue_reachable,
        }
        for name, check in checks.items():
            if not check(session):
                self._halt(f"Critical dependency unavailable: {name}")

    def _verify_tor_active(self, session: requests.Session | None = None) -> bool:
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((TOR_HOST, TOR_PORT))
            sock.close()
            if result != 0:
                audit_log("tor_socket_check_failed", {"host": TOR_HOST, "port": TOR_PORT}, severity="ERROR")
                return False
        except Exception as e:
            audit_log("tor_socket_error", {"error": str(e)}, severity="ERROR")
            return False

        try:
            from stem.control import Controller
            kwargs = {"port": TOR_CONTROL_PORT, "address": TOR_HOST_IP}
            with Controller.from_port(**kwargs) as controller:
                controller.authenticate(password=TOR_CONTROL_PASSWORD if TOR_CONTROL_PASSWORD else None)
        except ImportError:
            pass
        except Exception as e:
            audit_log("tor_stem_check_error", {"error": str(e)}, severity="ERROR")
            return False

        return True

    def _verify_queue_reachable(self, session: requests.Session | None = None) -> bool:
        try:
            client = QueueClient()
            client.connect()
            client.close()
            return True
        except Exception:
            return False

    def _halt(self, reason: str) -> None:
        audit_log("EMERGENCY_HALT", {"reason": reason, "timestamp": time.time()}, severity="CRITICAL")
        print(f"CRAWLER HALTED — {reason}", file=sys.stderr)
        sys.exit(1)


def load_sources() -> list[CrawlTarget]:
    with open(SOURCES_CONFIG, "r") as f:
        data = yaml.safe_load(f)
    return [CrawlTarget(**s) for s in data.get("sources", [])]


def fetch_url(
    session: requests.Session,
    url: str,
    target: CrawlTarget,
) -> tuple[str, bytes, str] | None:
    global _requests_since_circuit_rotation

    try:
        validate_url(url)
    except ValueError as e:
        audit_log("crawl_url_invalid", {"url": url, "error": str(e)}, severity="WARNING")
        return None

    headers = randomized_headers()
    current_url = url
    redirect_count = 0

    while redirect_count <= MAX_REDIRECTS:
        try:
            response = session.get(
                current_url,
                proxies=PROXY,
                headers=headers,
                timeout=REQUEST_TIMEOUT_SEC,
                allow_redirects=False,
                stream=True,
                verify=False,
            )
        except requests.exceptions.RequestException as e:
            audit_log("crawl_error", {"url": current_url, "error": str(e)}, severity="ERROR")
            return None

        if response.status_code in REDIRECT_STATUSES:
            redirect_count += 1
            if redirect_count > MAX_REDIRECTS:
                audit_log("crawl_redirect_limit_exceeded", {
                    "start_url": url, "last_url": current_url, "limit": MAX_REDIRECTS,
                }, severity="WARNING")
                return None
            location = response.headers.get("Location", "")
            if not location:
                audit_log("crawl_redirect_no_location", {"url": current_url}, severity="WARNING")
                return None
            try:
                validate_url(location)
            except ValueError as e:
                audit_log("crawl_redirect_blocked", {
                    "from_url": current_url, "to_url": location, "reason": str(e),
                }, severity="WARNING")
                return None
            audit_log("crawl_redirect", {"from_url": current_url, "to_url": location, "hop": redirect_count})
            current_url = location
            jittered_delay(base=1.0, spread=1.0)
            continue

        if response.status_code != 200:
            audit_log("crawl_non_200", {"url": current_url, "status": response.status_code}, severity="WARNING")
            return None

        content_type = response.headers.get("Content-Type", "")
        if "text" not in content_type and "html" not in content_type and "json" not in content_type:
            audit_log("crawl_binary_skipped", {"url": current_url, "content_type": content_type})
            return None

        content = b""
        for chunk in response.iter_content(1024):
            content += chunk
            if len(content) > MAX_PAGE_SIZE_BYTES:
                audit_log("crawl_size_exceeded", {"url": current_url, "size": len(content)}, severity="WARNING")
                response.close()
                return None

        response.close()
        raw_text = content.decode("utf-8", errors="replace")

        _requests_since_circuit_rotation += 1
        return current_url, content, raw_text

    return None


def extract_links(html: str, base_url: str, target: CrawlTarget) -> list[str]:
    soup = BeautifulSoup(html, "html.parser")
    links: list[str] = []
    parsed_base = urllib.parse.urlparse(base_url)
    base_domain = parsed_base.hostname or ""

    for a_tag in soup.find_all("a", href=True):
        href = a_tag["href"].strip()
        if not href or href.startswith("#") or href.startswith("javascript:"):
            continue
        absolute = urllib.parse.urljoin(base_url, href)
        parsed = urllib.parse.urlparse(absolute)
        if parsed.hostname and parsed.hostname != base_domain:
            continue
        if parsed.scheme not in ("http", "https"):
            continue
        clean = urllib.parse.urldefrag(absolute).url.rstrip("/")
        links.append(clean)

    selector = target.link_selector
    if selector:
        try:
            filtered = []
            for tag in soup.select(selector):
                href = tag.get("href", "")
                if href:
                    absolute = urllib.parse.urljoin(base_url, href)
                    clean = urllib.parse.urldefrag(absolute).url.rstrip("/")
                    if clean not in filtered:
                        filtered.append(clean)
            if filtered:
                links = filtered
        except Exception:
            pass

    seen = set()
    deduped = []
    for link in links:
        if link not in seen:
            seen.add(link)
            deduped.append(link)
    return deduped


def is_queue_page(raw_text: str) -> bool:
    lower = raw_text.lower()
    if "access queue" in lower or "queue" in lower and "redirected" in lower:
        return True
    if "dcap=" in raw_text:
        return True
    if "estimated entry time" in lower:
        return True
    if "assigning session" in lower:
        return True
    return False


def is_login_wall(raw_text: str) -> bool:
    """Detect an unauthenticated login/captcha gate (e.g. Dread) returned in place of
    page content. Publishing such a page feeds the classifier login-form + nav text
    and produces false findings (a board's drug-named sidebar links get read as a
    drug page). Markers are deliberately specific to the gate UI so a real page that
    merely mentions 'login' is not suppressed."""
    lower = raw_text.lower()
    markers = (
        "stay logged in for",            # Dread login form
        "rotate the images",             # Dread captcha challenge
        "enter your username and password",
    )
    return any(m in lower for m in markers)


def handle_queue_if_needed(session: requests.Session, url: str, target: CrawlTarget) -> tuple[str, bytes, str] | None:
    if target.queue_wait_seconds <= 0:
        return None

    result = fetch_url(session, url, target)
    if result is None:
        return None

    final_url, content, raw_text = result
    if not is_queue_page(raw_text):
        return result

    print(f"    {target.source_id}: access queue detected")
    audit_log("crawl_queue_detected", {"source": target.source_id, "url": url})

    retry_url = final_url
    waits = [target.queue_wait_seconds, 5]
    for i, wait in enumerate(waits):
        print(f"    {target.source_id}: waiting {wait}s before retry {i+1}...")
        jittered_delay(base=wait, spread=2.0)

        result_n = fetch_url(session, retry_url, target)
        if result_n is None:
            print(f"    {target.source_id}: retry {i+1} failed")
            continue

        fn_url, fn_content, fn_text = result_n
        if not is_queue_page(fn_text):
            print(f"    {target.source_id}: queue passed on retry {i+1}, got {len(fn_content)} bytes")
            audit_log("crawl_queue_passed", {"source": target.source_id, "url": fn_url, "size": len(fn_content), "retry": i+1})
            return fn_url, fn_content, fn_text

        print(f"    {target.source_id}: still in queue after retry {i+1} ({len(fn_content)} bytes)")

    print(f"    {target.source_id}: queue did not clear, using last response")
    return final_url, content, raw_text


def make_record(target: CrawlTarget, url: str, content: bytes, raw_text: str) -> dict:
    _risk_scores = {"low": 0.3, "medium": 0.6, "high": 0.9}
    sha256 = compute_sha256(content)
    return {
        "record_id": __import__("uuid").uuid4().hex,
        "sha256": sha256,
        "timestamp_utc": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        "source": target.source_id,
        "url": url,
        "raw_text": raw_text,
        "risk_score": _risk_scores.get(target.risk_level, 0.5),
    }


def is_listing_url(url: str, target: CrawlTarget) -> bool:
    """Listing/index pages (forum root + board/community pages) surface new posts
    and must be re-fetched every cycle. They are deliberately NOT added to the
    permanent seen-set, so each cycle re-reads them to discover new content while
    individual post/profile pages stay crawl-once. Within a single cycle the
    per-call `attempted` set still prevents re-fetching them."""
    if url.rstrip("/") == target.url.rstrip("/"):
        return True
    patterns = [p.strip() for p in target.listing_patterns.split(",") if p.strip()]
    return any(p in url for p in patterns)


def crawl_url(
    session: requests.Session,
    target: CrawlTarget,
    client: QueueClient,
) -> int:
    global _seen_urls
    base_url = target.url.rstrip("/")
    to_visit: list[str] = [base_url]
    visited = 0
    attempted = set()

    while to_visit and visited < target.max_pages:
        url = to_visit.pop(0)
        if url in _seen_urls and not (visited == 0 and target.queue_wait_seconds > 0):
            continue
        if url in attempted and not (visited == 0 and target.queue_wait_seconds > 0):
            continue
        attempted.add(url)

        if visited == 0 and target.queue_wait_seconds > 0:
            result = handle_queue_if_needed(session, url, target)
        else:
            result = fetch_url(session, url, target)
        if result is None:
            continue

        final_url, content, raw_text = result

        if final_url in _seen_urls and not (visited == 0 and target.queue_wait_seconds > 0):
            continue

        if len(raw_text) < MIN_CONTENT_LENGTH:
            audit_log("crawl_content_short", {"url": url, "length": len(raw_text)}, severity="DEBUG")
            continue

        # A page is "link-only" — harvested for links but NOT published to the
        # pipeline — when it is either:
        #   * a listing/index page (forum root + board pages): re-fetched every cycle
        #     to find new posts. Publishing it re-classifies the same board endlessly,
        #     which is what floods findings with near-duplicates.
        #   * a login/captcha wall: an unauthenticated fetch of a gated page, which is
        #     a form, not content, and only yields false findings.
        # Content pages (posts/articles) are published and remembered (crawl-once).
        # Listing/login-wall pages are deliberately NOT added to the seen-set: listings
        # must be re-read each cycle, and a gated page should be retried once we hold a
        # valid session.
        link_only = is_listing_url(final_url, target) or is_login_wall(raw_text)
        if not link_only:
            _seen_urls.add(final_url)
            record = make_record(target, final_url, content, raw_text)
            publish_or_buffer(client, "raw.crawl", record)
            visited += 1
            print(f"    {target.source_id}: crawled '{url}' — {len(content)} bytes")
            if visited >= target.max_pages:
                break
        else:
            print(f"    {target.source_id}: '{url}' — link discovery only (listing/login wall)")

        links = extract_links(raw_text, final_url, target)
        added = 0
        for link in links:
            if link not in _seen_urls and link not in to_visit and link not in attempted:
                to_visit.append(link)
                added += 1
        if added:
            print(f"      (+{added} new links)")

    audit_log("crawl_source_complete", {
        "source": target.source_id,
        "pages_crawled": visited,
    })
    return visited


def crawl_loop() -> None:
    global _seen_urls
    guard = CrawlerGuard()
    sources = load_sources()
    active_sources = [s for s in sources if s.status == "approved"]

    print(f"Crawler {CRAWLER_IDENTITY} started — {len(active_sources)} sources")

    session = requests.Session()
    session.verify = False
    guard.assert_nominal(session)

    dread_target = next((s for s in active_sources if s.source_id == "dread"), None)
    if dread_target and not load_dread_cookies(session):
        dread_login(session, dread_target)

    client = QueueClient()
    flush_publish_buffer(client)

    for target in active_sources:
        guard.assert_nominal(session)
        # NOTE: do NOT clear _seen_urls here. The seen-set must persist across
        # cycles so each post/profile page is crawled exactly once; listing pages
        # are exempted in crawl_url so new posts are still discovered every cycle.
        pages = crawl_url(session, target, client)
        print(f"  {target.source_id}: {pages} pages crawled")

        jittered_delay(base=5.0, spread=3.0)

        if _requests_since_circuit_rotation >= CIRCUIT_ROTATION_INTERVAL:
            rotate_tor_circuit()
            jittered_delay(base=10.0, spread=5.0)

    if _publish_buffer:
        audit_log("crawl_buffer_remaining", {"count": len(_publish_buffer)}, severity="WARNING")

    client.close()
    print("Crawl cycle complete")
    time.sleep(60)


def main() -> None:
    print("DWITP Crawler — Phase 1 (requests + BeautifulSoup only)")
    load_seen_urls()

    while True:
        try:
            crawl_loop()
            save_seen_urls()
        except KeyboardInterrupt:
            save_seen_urls()
            print("Crawler stopped by operator")
            sys.exit(0)
        except Exception as e:
            audit_log("crawl_cycle_error", {"error": str(e)}, severity="ERROR")
            print(f"Crawl cycle failed: {e}", file=sys.stderr)
            time.sleep(30)


if __name__ == "__main__":
    main()
