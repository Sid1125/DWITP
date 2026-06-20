# DWITP — Feature Reference

**DWITP (Dark Web Intelligence & Threat Monitoring Platform)** is a containerized, Tor-based OSINT pipeline. It crawls `.onion` sources (and, under legal authority, Telegram groups), sanitizes and analyzes the content, classifies threats with an offline rule-lexicon engine, stores findings across PostgreSQL / OpenSearch / Neo4j, and presents them through an authenticated FastAPI dashboard.

This document lists what the platform actually does, by area. Items that are stubbed or planned are called out explicitly at the end.

- **Stack:** Python 3.12, Docker Compose, RabbitMQ (TLS), PostgreSQL 16 (mTLS), OpenSearch 2.14, Neo4j 5.20 (bolt+TLS), Tor
- **Topology:** ~13 long-running containers + one-shot init jobs, 3 isolated Docker networks, internal self-signed CA for all service-to-service TLS
- **Pipeline:** `crawler → sanitizer → analysis → classifier (ai_layer) → db_writer → dashboard`, decoupled by RabbitMQ queues

---

## 1. Crawling & Collection

- **Tor-only egress** — every fetch routed through a hardened Tor gateway (SOCKS5 `:9050`, control `:9051`); no clearnet path.
- **Tor circuit rotation** — new identity via Stem `Signal.NEWNYM` every N requests (`CIRCUIT_ROTATION_INTERVAL`, default 15) for OPSEC.
- **Source registry / governance gate** — only sources with `status: approved` in `config/sources.yaml` are crawled; each carries approver, approval date/signature, risk level, and review notes.
- **Authenticated crawling (Dread)** — loads a Netscape-format cookie jar (`config/dread_cookies.txt`); supports a "stay logged in forever" durable session. Cookies are reloaded every crawl cycle (no restart needed). Credential-login fallback POSTs to `/auth/login/noload` (captcha-gated).
- **Login/auth-wall detection** — pages returning a login or captcha gate (e.g. Dread's "stay logged in for" / "rotate the images") are detected and **mined for links only, never published** — so auth walls don't become false findings.
- **Listing vs content separation** — forum index/board pages (`listing_patterns`) are re-fetched each cycle to discover new posts but are **not** published as records (prevents the same board being re-classified into duplicate findings every cycle). Individual post/profile pages are crawled once (persistent seen-set).
- **Access-queue handling** — detects DDoS-Guard / "access queue" interstitials and retries with configurable waits (`queue_wait_seconds`).
- **Link discovery** — extracts same-domain links, with optional CSS `link_selector` per source to focus on posts/profiles.
- **Auto-discovery of new sources** — `.onion` addresses found in content are published to a `discovery.candidate` queue and staged as `candidate_sources` for human review/promotion.
- **Content hygiene** — content-type filtering (text/html/json only), 5 MB max page size with streaming abort, max-3 validated redirects, minimum content length filter.
- **Anti-fingerprinting** — randomized headers (10 user-agent profiles, 5 accept-languages), jittered request delays.
- **Deadman's switch (`CrawlerGuard`)** — halts the crawler immediately if Tor or the queue is unreachable (fail-closed).
- **Publish buffering** — records are buffered and retried if RabbitMQ is briefly unavailable, so transient broker outages don't lose data.
- **Per-page content hashing** — SHA-256 of raw bytes for downstream dedup.

## 2. Sanitization & Prompt-Injection Defense

- **Prompt-injection gateway** — mandatory stage scanning for jailbreak/instruction-override patterns (e.g. "ignore previous instructions", "act as an AI", "system prompt:", "execute this command"); matches are redacted to `[CONTENT REDACTED]` and audit-logged. Patterns are tuned to require a real injection target so darknet-market vocabulary ("act as a middleman") doesn't false-positive.
- **HTML safe-parse** — strips media/external tags (`img/script/iframe/video/audio/object/embed/link`), page chrome (`nav/header/footer`), and form elements (`input/button/label/...`) so login forms aren't misread as credential pages.
- **Boilerplate-class stripping** — removes sidebars, profile tabs, login boxes, captcha widgets, footer link-farms by CSS class/id substring (forum chrome that isn't semantic HTML).
- **Text normalization** — HTML unescape + whitespace collapse.
- **Raw vs sanitized split** — the original HTML is preserved for the evidence view; only the cleaned text reaches the classifier.

## 3. Entity Extraction & Analysis

- **IOC regex extraction** — CVE IDs, BTC / XMR / ETH addresses, emails (+domain), domains (+TLD), IPv4, PGP key blocks (hashed fingerprint), Telegram handles, Jabber/XMPP IDs, `.onion` addresses.
- **Named-entity recognition** — spaCy (`en_core_web_sm`) for PERSON entities.
- **Intelligence flagging** — marks records that carry actionable IOCs (CVEs, wallets, emails).
- **Onion discovery feed** — extracted `.onion` addresses are emitted as discovery candidates.

## 4. Classification Engine (offline rule-lexicon)

> The original Ollama LLM classifier was **removed** as the pipeline's biggest bottleneck (up to 120 s/page). It was replaced with a fast, deterministic, fully-offline engine isolated in `src/ai_layer/classifier.py` (the single `classify()` seam).

- **11-class taxonomy** — `ransomware, malware_sale, credential_leak, access_broker, data_leak, drug_trafficking, weapons_trafficking, terrorism_extremism, human_trafficking, scam, unknown`.
- **Weighted phrase lexicons** — per-category, word-boundary-aware, case-insensitive; unique-phrase-per-doc scoring (rewards breadth of evidence).
- **IOC signal boosts** — entity presence (onion/BTC/XMR/CVE/email/domain/PGP…) adds weighted signal per category.
- **Credential-dump detector** — regex for `email:password` lines boosts `credential_leak`.
- **Negative-context guard** — reference/educational/discussion markers (mkdocs chrome, "operational security", "harm reduction", etc.) subtract a penalty from every category, so a stray keyword in technical prose no longer becomes a finding while real listings survive.
- **Confidence calibration** — exponential mapping `1 − e^(−0.6·score)`, normalized to LOW/MEDIUM/HIGH.
- **Conservative escalation** — `terrorism_extremism` / `human_trafficking` require high confidence or are downgraded to `unknown` (false positives there are costly).
- **Deterministic tie-break** — stable category ordering; identical input → identical output (evidence-grade, explainable).
- **Verbatim evidence quote** — each finding carries an exact substring of the source backing the category (empty for `unknown`).
- **MITRE ATT&CK mapping** — category → technique IDs (e.g. ransomware → T1486).
- **Per-source PI-campaign quarantine** — a source crossing a prompt-injection threshold (default 5 incidents) is auto-disabled on its own, without halting analysis of other sources; degraded at 3.
- **Manual AI kill switch** — operator can disable/enable classification globally via a `control.ai` fanout broadcast (Admin Panel).
- **Sub-millisecond, airgapped** — no model, no network; latency-bounded by a max-chars cap.

## 5. Storage & Data Model

- **PostgreSQL (TLS/mTLS)** — system of record. Key tables: `source_registry`, `raw_evidence` (immutable — `REVOKE UPDATE/DELETE`), `candidate_sources`, `classifications`, `intelligence_findings`, `source_reputation`, `audit_log`, `threat_actors`, plus the Telegram tables (below).
- **Content-hash dedup** — identical page content (same SHA-256) never produces a duplicate finding.
- **Cross-source corroboration** — a finding stays `UNCONFIRMED` until a *different* source reports the same category with an overlapping entity value; calibrated confidence factors in source reputation, corroboration count, and historical accuracy.
- **OpenSearch indexing** — classifications indexed for full-text search.
- **Neo4j graph** — classification nodes; and the full Telegram actor-interaction graph (below).
- **Immutable encrypted audit log** — every security-relevant event is Fernet-encrypted, append-only, rotating; CRITICAL events fan out to the notifier.

## 6. Telegram Group Intelligence (INTEL-002)

> Backend pipeline is implemented and wired end-to-end; the dashboard **Network visualization is not yet built** (see Planned).

- **Observation-only collector** — read-only Telethon user-client (`get_entity` / `iter_messages` / `get_participants`); **no send/post/reply/DM path anywhere**. Egresses through Tor.
- **Strict access governance** — only `telegram_groups` rows with `status='approved'` **and** a `legal_basis_ref` are collected (DB-enforced + re-checked). `access_method` constrained to `public_link / authorized_undercover / cooperating_source / lawful_compulsion`. No infiltration, persona-fabrication, vetting-bypass, or ban-evasion tooling — by design and policy.
- **Incremental ingestion** — per-group high-water mark (last message id) for dedup across polls; state persisted to disk.
- **Collection kill switch** — operator disable/enable via `control.collection` fanout.
- **Idle-safe** — runs harmlessly idle until credentials (`TELEGRAM_API_ID/HASH/SESSION`) are provisioned out-of-band; never performs interactive login.
- **Unified pipeline** — Telegram messages flow through the same sanitizer → analysis → classifier → db_writer path via a `telegram.raw` envelope, persisted to `telegram_messages` (natural-key dedup, UPDATE/DELETE revoked).
- **Actor interaction graph** — Neo4j `Actor/Group/Message` nodes with `MEMBER_OF / POSTED / IN` and weighted `REPLIED_TO / MENTIONED` edges (with handle→user-id resolution for out-of-order mentions).
- **Social Network Analysis (`graph_analytics`)** — periodic in-process networkx job computing PageRank, betweenness, in-reply degree, and Louvain communities (sub-cells); writes `influence_score`, `orchestrator_likelihood`, `cell_id`, and inferred role (leader/lieutenant/operator/peripheral) back to `telegram_actors` and onto Neo4j nodes.
- **"Volume ≠ control" orchestrator detection** — flags quiet brokers (high betweenness + high in-reply + low message volume) above loud hype-men. Honors an `analytics_enabled` pause flag.

## 7. Analyst Dashboard (FastAPI, HTTPS)

- **Operations Overview homepage** — clickable stat cards (open findings, needs-review, findings-24h, active sources, threat actors, pages crawled), a "threat findings by category" bar panel, a pipeline/source-health panel (degraded sources + last-crawl time), and a recent-findings table. 60 s auto-refresh; fault-tolerant queries (one missing table degrades a widget, not the page); conditional Telegram-intel panel.
- **Findings list** — paginated, filterable by review status and category, with category + confidence-level badges.
- **Finding detail** — full record, the verbatim raw-evidence preview, extracted entities, cross-source corroboration, and a one-click human-review action.
- **Crawled pages** — every `raw_evidence` page with its classification joined, filterable by source/category.
- **Search** — query across indexed classifications.
- **Sources** — view source registry + reputation; analysts can *propose* new sources (staged, not activated).
- **Actors** — threat-actor profiles (falls back to deriving actor names from `/u/` URLs when the table is empty).
- **Authentication** — cookie-based sessions (HTTP-only, SameSite=strict, secure), 8 h expiry, PBKDF2-SHA256 password hashing (260k iterations), self-signed HTTPS generated at container start.
- **Rate limiting** — 60 req/min/IP (in-memory).

## 8. Admin Panel (separate login / separation of duties)

- **Distinct admin auth** — separate `ADMIN_USERNAME/PASSWORD`; admin nav is scoped away from analyst views.
- **Candidate-source review** — promote/reject auto-discovered `.onion` candidates.
- **Pending-source approval** — approve/reject analyst-proposed sources; approval appends to `sources.yaml` (the only write path, gated behind admin + a human-reviewed pending row — INV-04).
- **Source registry management** — change source status, reset a source's poisoning reputation.
- **AI kill switch** — disable/enable the classification stage fleet-wide via fanout broadcast.
- **Encrypted audit-log viewer** — decrypts and renders audit events with severity badges.
- **User management** — create users, deactivate/reactivate, change roles, reset passwords.
- **Health endpoint** — `/health` for liveness.

## 9. Security Hardening

- **Container** — non-root (UID 1000) everywhere, `cap_drop: ALL` + granular `cap_add`, `no-new-privileges`, read-only rootfs with tmpfs-only writable paths, per-service CPU/memory limits, seccomp profile reference.
- **Network isolation** — `queue_net` and `db_net` are `internal: true` (no internet); crawler is the only tor↔queue bridge; dashboard is on `db_net` only (can't reach the queue). Static IPs pin services to prevent IP-squat races on host resume.
- **TLS everywhere** — internal 4096-bit CA; per-service certs; RabbitMQ TLS (5671), PostgreSQL mTLS (client-cert required for the `dwitp` user from the db subnet), Neo4j bolt+ssc, dashboard HTTPS.
- **SSRF protection** — `validate_url()` blocks `file/ftp/smb/ldap/gopher/data/javascript/vbscript/jar` schemes, resolves hostnames and blocks private/loopback/link-local IP ranges (`.onion` explicitly allowed).
- **Secret hygiene** — all passwords/keys via required env vars (container fails fast if missing); Telegram and Dread credentials provisioned out-of-band, never committed.
- **Encrypted audit trail** — Fernet-encrypted, append-only, with automatic CRITICAL→notifier escalation.

## 10. Reliability & Operations

- **Resume-proof restart policy** — long-running services use `restart: always` (survives host sleep/resume where `unless-stopped` would not) + static IPs to avoid address-squat races.
- **Reconnecting consumers** — queue consumers auto-reconnect with backoff and escalate to the notifier after max retries.
- **Source reputation tracking** — per-source poisoning-incident counter with `active/degraded/quarantined/retired` status; degraded sources surfaced on the homepage.
- **Critical-event notifier** — pluggable CRITICAL-severity notification hook.
- **Tooling** — `scripts/` for DB init, secret rotation, hash-pinning, healthcheck, setup, and an end-to-end test; CI security gate (`.github/workflows/security-gate.yml`); pinned & hash-locked dependencies.

## 11. Messaging

- **RabbitMQ (TLS, vhost `/dwitp`)** — durable queues: `raw.crawl`, `sanitized`, `analysis.ready`, `ai.output`, `discovery.candidate`, `telegram.raw` (`ai.input` / `classified` reserved).
- **Fanout control exchanges** — `control.ai` (classification kill switch) and `control.collection` (Telegram kill switch) broadcast to every replica.
- **Long-lived connections** — one connection per service lifetime (connection-per-message forbidden), multi-queue consumers, drain/poll helpers.

## 12. Governance & Compliance (docs)

Specification documents shipped in-repo: `ARCH-001` (architecture & non-interaction), `AI-001` (AI governance & safety — AI is analyst, not operator), `DEV-001` (development standard), `INTEL-001` (intelligence requirements), `INTEL-002` (Telegram group intelligence + guardrails TG-G1..G8), `IR-001` (incident-response playbook), and the full `Dwitp_vibe_security_spec.md`.

---

## Planned / Partial / Known Limitations

- **Dashboard Network view — NOT implemented.** A `/network` nav link and a homepage Telegram panel link to it, but the routes/templates don't exist (would 404). The Telegram SNA backend that would feed it *is* built.
- **`discovery.candidate` has no automated consumer** — candidates are staged for manual admin promotion.
- **Telegram collector is idle** until credentials + an approved, legally-based group are provisioned.
- **Seccomp profile** (`python.json`) is a permissive placeholder.
- **OpenSearch security plugin disabled** (`DISABLE_SECURITY_PLUGIN=true`) — plain HTTP within the internal db network.
- **Dashboard rate limiter** is per-process/in-memory (single replica).
- **Classifier precision ceiling** — the rule-lexicon engine is context-limited on prose; precision depends on crawling actual marketplace/listing content rather than reference/discussion pages.
