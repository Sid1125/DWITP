# Sanitizer Module

Anti-prompt-injection gateway. Consumes `raw.crawl` messages, runs `safe_parse()` to strip `<img>`, `<script>`, `<iframe>` tags (SEC-001 §3.5), runs `injection_gateway()` to detect and redact prompt-injection patterns, and publishes sanitized records to the `sanitized` queue.

## API

- `process_raw_record(message, client)` — parse raw HTML → safe text → detect PI patterns → publish `sanitized` record with `content_sanitized` and `injection_patterns_detected`.

## Threat Model

- **PI bypass via encoding** — mitigated by `html.unescape` before pattern matching.
- **Missed patterns** — requires periodic review and update of injection pattern rules.

## Test Coverage

62% (24 stmts, 9 missed). `safe_parse()` and `injection_gateway` integration tested. Lines 34-42, 46 uncovered (queue consume loop requires live RabbitMQ).
