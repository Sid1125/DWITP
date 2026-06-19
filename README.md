# DWITP — Dark Web Intelligence & Threat Monitoring Platform

A full-stack dark web intelligence pipeline for crawling, analyzing, and classifying content from approved `.onion` sources. Built for security analysts and threat intelligence teams to collect sanitized dark web content, extract entities, classify threats via local LLM, and visualize findings through a secure dashboard.

## Features

- **Dashboard** — Stats overview, recent findings, per-source breakdown, threat category distribution
- **Search** — Full-text search across intelligence findings via OpenSearch, recent findings when no query
- **Network Graph** — Neo4j-based entity relationship graph (planned for graph_analytics service)
- **Tower Map** — N/A (telecom-specific feature, not applicable)
- **Entity Timeline** — Finding detail view with raw evidence rendered via iframe, extracted entities, AI summary, MITRE ATT&CK mapping
- **Charts** — Category distribution, source breakdown, confidence levels
- **Records Table** — Findings list with source/category/confidence/date columns, sortable, clickable to detail
- **AI Insights** — Local Ollama (llama3.2:1b) classification with entity validation, anti-hallucination filtering, PI campaign detection
- **Session Management** — Cookie-based authentication with 8-hour expiry, rate-limited (60 req/min/IP)

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.12+, FastAPI, SQLAlchemy, BeautifulSoup, spaCy, NetworkX |
| Databases | PostgreSQL 16 (primary), OpenSearch 2.14 (full-text search), Neo4j 5.20 (graph) |
| Queue | RabbitMQ 3.13 with mTLS (7 durable queues, competing consumers) |
| AI | Local Ollama API (default: llama3.2:1b, 2K context) |
| Crawler | requests + BeautifulSoup via Tor SOCKS5 proxy |
| Frontend | FastAPI server-side Jinja2 templates, inline HTML/CSS |
| Visualizations | Neo4j graph (planned), embedded iframe for raw evidence rendering |
| Auth | Cookie-based sessions via itsdangerous URLSafeTimedSerializer |
| Infrastructure | Docker Compose (13 containers), 4 isolated networks, internal TLS CA |

## Getting Started

### Prerequisites

- Python 3.12+
- Docker & Docker Compose
- Ollama (optional — for AI classification)
- At least 7.4 GiB RAM (recommended 16 GiB for full stack)

### Installation

```bash
# Clone the repository
git clone https://github.com/Sid1125/DWITP.git
cd DWITP

# Linux
./scripts/setup.sh

# Windows PowerShell
.\scripts\setup.ps1
```

### Configuration

Copy `infra/.env.example` to `infra/.env` and adjust as needed. The setup script auto-generates random secrets.

Key environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql://dwitp:...@postgres:5432/dwitp` | PostgreSQL DSN |
| `AUDIT_ENCRYPTION_KEY` | (auto-generated) | Fernet key for audit log encryption |
| `OLLAMA_MODEL` | `llama3.2:1b` | LLM model for AI classification |
| `AI_MAX_CHARS` | `2000` | Max characters sent to LLM per message |
| `DASHBOARD_USERNAME` | `analyst` | Dashboard login username |
| `DASHBOARD_PASSWORD` | (auto-generated) | Dashboard login password |
| `DREAD_USERNAME` | `""` | Dread forum login (captcha-blocked — use cookie file instead) |

### Running

```bash
cd infra
docker compose -p infra up -d
```

- **Dashboard**: https://localhost:8079
- **API Docs**: (internal — no public API docs endpoint)
- **Default Login**: `analyst` / password from `infra/.env`

### Generating Sample Data

```bash
# Seed the database with sample intelligence findings
docker exec dwitp-db-writer python -c "
from src.common.models import IntelligenceFinding
# See scripts/init-db.sql for schema
"
```

For pipeline testing, inject a synthetic record:

```bash
# Run the end-to-end pipeline test (Linux)
./scripts/e2e_test.sh
```

## Project Structure

```
DWITP/
├── config/
│   ├── sources.yaml              # Approved .onion source registry (human-gated)
│   └── dread_cookies.txt         # Netscape cookie file for dread auth (gitignored)
├── infra/
│   ├── docker-compose.yml        # 13 services, 4 networks, 5 volumes
│   ├── .env                      # All secrets (auto-generated, gitignored)
│   ├── docker/                   # Dockerfiles for each service
│   │   ├── tor/                  # Alpine Tor SOCKS proxy
│   │   ├── tls-init/             # One-shot CA + cert generator
│   │   ├── rabbitmq/             # RabbitMQ with TLS + management
│   │   ├── postgres/             # PostgreSQL 16 with mTLS
│   │   ├── crawler/              # Python crawler (requests + bs4)
│   │   ├── sanitizer/            # Anti-prompt-injection gateway
│   │   ├── analysis/             # spaCy NER + entity extraction
│   │   ├── ai_layer/             # Ollama LLM classifier
│   │   ├── db_writer/            # RabbitMQ consumer → DB writer
│   │   ├── dashboard/            # FastAPI web UI
│   │   ├── neo4j/                # Custom entrypoint for overlay FS
│   │   └── opensearch/           # (uses official image)
│   └── tls/                      # Certificate generation scripts
├── src/
│   ├── common/                   # Shared libraries
│   │   ├── models.py             # 13 Pydantic models (extra="forbid")
│   │   ├── queue.py              # RabbitMQ client (single connection lifetime)
│   │   ├── security.py           # Validation, sanitization, audit, Fernet encryption
│   │   └── notifier.py           # Slack + stderr alerting
│   ├── crawler/main.py           # Tor crawler with circuit rotation (538 lines)
│   ├── sanitizer/main.py         # Injection gateway wrapper (48 lines)
│   ├── analysis/main.py          # Entity extraction via regex + spaCy (136 lines)
│   ├── ai_layer/main.py          # Ollama classification with prompt defense (228 lines)
│   ├── db_writer/main.py         # RabbitMQ consumer → PG/OS/Neo4j (263 lines)
│   └── dashboard/main.py         # FastAPI + embedded Jinja2 templates (958 lines)
├── scripts/
│   ├── setup.sh / setup.ps1      # Bootstrap scripts (env, deps, build)
│   ├── build.ps1                 # Hash-pin + Docker build
│   ├── healthcheck.sh            # 20-point deployment health check
│   ├── e2e_test.sh               # Full pipeline synthetic injection test
│   ├── rotate-secrets.sh/ps1     # IR-12: crawler secret rotation
│   ├── pin-hashes.sh             # pip-compile hash generation
│   └── init-db.sql               # 161 lines — 9 tables, indexes, mTLS config
├── tests/
│   ├── conftest.py               # Test fixtures
│   ├── test_crawler.py
│   ├── test_security.py
│   ├── test_sanitizer.py
│   ├── test_queue.py
│   ├── test_notifier.py
│   └── test_models.py
├── DWITP_context.md              # Session context document (gitignored)
├── AI-001_AI_Governance_and_Safety.md
├── ARCH-001_System_Architecture.md
├── DEV-001_Development_Standard.md
├── Dwitp_vibe_security_spec.md
├── INTEL-001_Intelligence_Requirements.md
└── IR-001_Incident_Response_Playbook.md
```

## Pipeline Architecture

```
.onion Sources
     │
     ▼
┌─────────────┐     ┌──────────────┐     ┌────────────┐
│    Tor      │────▶│   Crawler    │────▶│ Sanitizer  │
│  (SOCKS5)   │     │ (requests+   │     │ (injection │
│  9050/9051  │     │  bs4, auth)  │     │  gateway)  │
└─────────────┘     └──────────────┘     └──────┬─────┘
                                                │ queue: sanitized
                                                ▼
┌─────────────┐     ┌──────────────┐     ┌────────────┐
│   Ollama    │◀────│  AI Layer×2  │◀────│  Analysis  │
│ (llama3.2   │     │ (entity val, │     │ (spaCy NER │
│  :1b)       │     │  PI detect)  │     │  + regex)  │
└─────────────┘     └──────┬───────┘     └────────────┘
                           │ queue: ai.output
                           ▼
┌─────────────┐     ┌──────────────┐     ┌────────────┐
│ PostgreSQL  │◀────│  DB Writer   │────▶│ OpenSearch │
│  (evidence, │     │ (consumer →  │     │ (full-text │
│   findings) │     │  3 DBs)      │     │  search)   │
└─────────────┘     └──────────────┘     └────────────┘
                           │
                           ▼
                    ┌──────────────┐
                    │  Dashboard   │
                    │  (FastAPI +  │
                    │   Jinja2)    │
                    └──────────────┘
```

### Pipeline Stages

| Stage | What it does |
|-------|-------------|
| **Crawler** | Requests + BeautifulSoup via Tor SOCKS5 proxy. Randomized headers, URL validation (SSRF protection), redirect handling (max 3), streaming download (max 5MB). Circuit rotation via Stem `Signal.NEWNYM` every 15 requests. Dread cookie authentication with queue page detection. |
| **Sanitizer** | Consumes `raw.crawl` queue. `safe_parse()` strips img/script/iframe/video/audio/object/embed/link/source. `injection_gateway()` detects 13 prompt-injection patterns. `normalize_text()` unescapes HTML, normalizes whitespace. |
| **Analysis** | Consumes `sanitized` queue. Extracts entities via 11 regex patterns: CVE IDs, BTC/XMR/ETH addresses, email, domains, IPs, PGP key blocks, Telegram handles, Jabber IDs, .onion addresses. Runs spaCy NER for PERSON entities (up to 100K chars). |
| **AI Layer** | 2 competing consumers on `analysis.ready` queue. Sends content to Ollama with system prompt containing SECURITY NOTICE. Classifies into 7 categories (ransomware, malware_sale, credential_leak, access_broker, data_leak, scam, unknown). Validates entities against source text. Detects PI campaigns (auto-disables at threshold). |
| **DB Writer** | Consumes `ai.output` queue. Writes to PostgreSQL (`raw_evidence`, `classifications`, `intelligence_findings`), OpenSearch (`dwitp-classifications` index), Neo4j (Classification graph nodes). Updates `source_reputation` with poisoning tracking. Skips dnmx/mail2tor sources. |
| **Dashboard** | FastAPI + Jinja2 templates. Cookie-based auth (8hr expiry). Rate-limited (60 req/min/IP). HTTPS with self-signed cert. Routes: `/` (stats), `/findings` (list/detail/review), `/search` (OpenSearch), `/sources`, `/actors`, `/health`, `/login`. |

### Message Queues

7 durable queues in RabbitMQ vhost `/dwitp`:

| Queue | Producer | Consumer | Format |
|-------|----------|----------|--------|
| `raw.crawl` | Crawler | Sanitizer | Raw HTML/text with metadata |
| `sanitized` | Sanitizer | Analysis | Sanitized text + injection patterns |
| `analysis.ready` | Analysis | AI Layer (×2) | Entities + sanitized content |
| `ai.input` | — | — | Reserved |
| `ai.output` | AI Layer (×2) | DB Writer | Classification + MITRE TTPs |
| `classified` | — | — | Reserved |
| `discovery.candidate` | Analysis | — | Discovered .onion URLs |

## API Overview

All endpoints except `/health`, `/login`, and `/static/*` require authentication via HttpOnly session cookie.

| Router | Endpoints | Description |
|--------|-----------|-------------|
| `/` | 1 | Dashboard stats overview (KPI cards, category breakdown, recent findings) |
| `/findings` | 4 | List findings, detail view, review action, raw evidence |
| `/search` | 1 | Full-text search via OpenSearch, recent findings when no query |
| `/sources` | 1 | Source registry status, reputation, governance metadata |
| `/actors` | 1 | Threat actors from DB or fallback extraction from `/u/` URLs |
| `/login` | 2 | Login form + POST authentication |
| `/health` | 1 | Health check endpoint |

## Frontend Overview

The dashboard is server-side rendered with FastAPI + Jinja2 templates (not a separate SPA). All CSS is inline in the template HTML (~60KB total across 4 template files).

| Tab | Features |
|-----|----------|
| **Dashboard** | 4 KPI cards (total findings, active sources, high-risk items, pending review), category distribution bar chart, recent findings table |
| **Findings** | Sortable table with source/category/confidence/date, clickable rows navigate to detail view |
| **Finding Detail** | Full finding metadata, raw evidence rendered in iframe (JS/CSS stripped), extracted entities, AI summary, MITRE ATT&CK mapping |
| **Search** | OpenSearch full-text search box, results table with timestamps, recent findings when empty query |
| **Sources** | Source registry table with status, reputation, governance metadata |
| **Actors** | Threat actor profiles, fallback to `/u/` URL extraction when DB table empty |

## AI Insights

The AI Layer connects to a local Ollama instance for content classification:

- **Classification** — Sends sanitized content (max 2000 chars) to Ollama with structured prompt containing category definitions, anti-hallucination instructions, and few-shot examples
- **Entity Validation** — Verifies extracted entity keys/values literally appear in source text; removes hallucinated entities
- **MITRE ATT&CK Mapping** — Category-based: ransomware→T1486, malware_sale→T1059, credential_leak→T1003, access_broker→T1078, scam→T1566, data_leak→T1003
- **PI Campaign Detection** — Tracks injection incidents per source; at threshold (default 5), disables AI processing for that source
- **Human Review Flagging** — HIGH_RISK_CATEGORIES or risk_score > 0.8 triggers `requires_human_review`
- **Default Model**: `llama3.2:1b` (fits ~2-3 GiB RAM). Configurable via `OLLAMA_MODEL` env var.

## Network Topology

```
tor_net (172.20.0.0/24)     queue_net (172.21.0.0/24)     db_net (172.22.0.0/24)      ai_net (172.23.0.0/24)
┌──────────────┐           ┌─────────────────────┐      ┌────────────────────┐      ┌────────────────────┐
│  tor (.2)    │◀──SOCKS──│ crawler (.10)       │      │ postgres (.2)      │      │ ollama (.2)        │
│  crawler(.10)│──socks───│ sanitizer (.11)     │      │ opensearch (.3)    │      │ ai_layer (.10)     │
└──────────────┘           │ analysis (.12)      │      │ neo4j (.4)         │      │ ai_layer_2         │
                           │ ai_layer (.13)      │      │ db_writer (.11)    │      └────────────────────┘
                           │ ai_layer_2 (.15)    │      │ dashboard          │
                           │ db_writer (.14)     │      └────────────────────┘
                           │ rabbitmq (.2)       │
                           └─────────────────────┘
```

- `queue_net` and `db_net` are `internal: true` (no external access)
- Crawler bridges `tor_net` + `queue_net` (the only cross-network service)
- Dashboard is on `db_net` only — cannot reach queue or AI network

## Security Hardening

### Container Level
- **Non-root users** (UID 1000) in every container
- **`cap_drop: ALL`** + granular `cap_add` (CHOWN, DAC_OVERRIDE, SETUID, SETGID, NET_BIND_SERVICE)
- **`no-new-privileges: true`**
- **`read_only: true`** rootfs — writable paths via tmpfs only
- **Seccomp profiles** (python.json is documented placeholder)
- **CPU/memory limits** on every service

### Application Level
- **Prompt injection gateway**: 13 regex patterns, mandatory stage between raw store and AI
- **URL validation**: Blocks file/ftp/smb/ldap/gopher/data/javascript/vbscript/jar schemes, SSRF protection
- **Content-Type filtering**: Only text/html/json allowed in crawler
- **Size limits**: 5MB max page size, streaming download
- **Redirect limits**: Max 3 redirects, all validated
- **Randomized headers**: 10 user-agent profiles, 5 accept-languages
- **Circuit rotation**: Tor circuit changes via Stem every 15 requests
- **Deadman's switch**: CrawlerGuard halts on Tor/queue failure
- **Audit log**: Fernet-encrypted, rotating file handle

### AI Safety
- **System prompt** warns AI content is hostile
- **Entity validation**: Extracted entities must literally appear in source text
- **Pydantic `extra="forbid"`**: Rejects unexpected AI output fields
- **PI campaign detection**: Auto-disables AI for source at threshold
- **No AI tool access**: No shell, no network, no DB writes, no URL fetching

## Database Schema (PostgreSQL)

| Table | Purpose |
|-------|---------|
| `source_registry` | Human-approved sources with governance metadata |
| `raw_evidence` | Immutable crawled content (REVOKE UPDATE/DELETE) |
| `candidate_sources` | Auto-discovered .onion URLs |
| `sanitized_records` | Post-sanitization copy with injection patterns |
| `analysis_results` | Entity extraction output |
| `classifications` | AI classification with MITRE TTPs |
| `intelligence_findings` | Analyst-facing findings |
| `source_reputation` | Per-source reliability scoring |
| `audit_log` | Append-only encrypted events |
| `threat_actors` | Actor profiles with aliases and wallets |

## Testing

```bash
pytest --cov=src --cov-fail-under=85 tests/
```

182 tests, 92.8% coverage (85% threshold). 6 test files covering crawler, security, sanitizer, queue, notifier, and models.

## Governance Documents

| Document | Focus |
|----------|-------|
| `Dwitp_vibe_security_spec.md` | Master security spec — 15 invariants, 1000 lines |
| `ARCH-001_System_Architecture.md` | Pipeline stages, component definitions, tech stack |
| `AI-001_AI_Governance_and_Safety.md` | AI is analyst not operator, forbidden actions, PI policy |
| `DEV-001_Development_Standard.md` | Python 3.12+, type hints, pydantic, security scanners |
| `INTEL-001_Intelligence_Requirements.md` | 7 categories, entity types, MITRE ATT&CK mapping |
| `IR-001_Incident_Response_Playbook.md` | 4 severity levels, response procedures |
