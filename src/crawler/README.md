# Crawler Module

Tor-based crawler that fetches approved `.onion` sources, validates URLs (SSRF protection via `validate_url`), enforces redirect limits (`MAX_REDIRECTS`), rotates Tor circuits via Stem (`rotate_tor_circuit` → `NEWNYM`), and publishes raw evidence to RabbitMQ (`raw.crawl`).

## API

- `crawl_url(session, target)` → `dict | None` — fetch a single target, return record with `record_id`, `sha256`, `timestamp_utc`, `source`, `url`, `raw_text`.
- `crawl_loop()` — load approved sources, iterate with `CrawlerGuard.assert_nominal()` checks, circuit rotation every `CIRCUIT_ROTATION_INTERVAL` requests.
- `rotate_tor_circuit()` — authenticate to Tor control port, send `NEWNYM` signal.
- `CrawlerGuard` — validates Tor socket + bootstrap status and RabbitMQ reachability; calls `_halt()` (→ `sys.exit(1)`) on failure.

## Threat Model

- **Tor failure** → CrawlerGuard halts the process.
- **DNS leak via clearnet fallback** — prevented by `socks5h://` proxy (DNS resolved over Tor).
- **Malicious .onion redirects** — blocked by `validate_url` on every redirect hop.

## Test Coverage

72% (171 stmts, 48 missed). Core logic (crawl_url, CrawlerGuard) tested. Lines 56-59, 64-70, 82-84, 90, 99-101 uncovered (Tor/queue-dependent startup branches).
