# Analysis Module

Entity extraction layer using regex patterns (CVE, BTC, XMR, ETH, emails, domains, IPs, PGP, Telegram, Jabber) + spaCy NER for person names. Consumes the `sanitized` queue, publishes `analysis.ready`.

## API

- `extract_entities(text)` → `dict` — returns structured entity sets (`cves`, `btc_addresses`, `xmr_addresses`, `eth_addresses`, `email_addresses`, `domains`, `ip_addresses`, `pgp_fingerprints`, `telegram_handles`, `jabber_ids`, `persons`).
- `process_sanitized_record(message, client)` — extract entities, build analysis result, publish to `analysis.ready`.

## Threat Model

- **Regex DoS via crafted input** — mitigated by size limits enforced upstream in the crawler (`MAX_PAGE_SIZE_BYTES`).
- **spaCy model poisoning** — uses standard `en_core_web_sm` model with no user-supplied training data.

## Test Coverage

Not tested — requires live spaCy model + RabbitMQ. Entity extraction patterns tested indirectly via security tests. Infra-dependent exclusion documented in `pyproject.toml`.
