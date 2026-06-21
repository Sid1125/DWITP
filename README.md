# DWITP — Dark Web Intelligence & Threat Monitoring Platform

A containerized, Tor-based OSINT pipeline that crawls approved `.onion` sources (and, under documented legal authority, Telegram groups), sanitizes and analyzes the content, classifies threats with a fast **offline rule-lexicon engine**, stores findings across PostgreSQL / OpenSearch / Neo4j, and presents them through an authenticated dashboard. Built for lawful, evidence-grade investigative use.

> Pipeline: **crawl → sanitize → analyze → classify → store → dashboard**, decoupled by RabbitMQ and isolated across hardened containers with internal TLS.

- Full feature list: [`features.md`](features.md)
- Telegram capability + status: [`TELEGRAM.md`](TELEGRAM.md)
- Classifier lexicon: [`THREAT_LEXICON.md`](THREAT_LEXICON.md)

---

## Architecture at a glance

```
 .onion sources / Telegram
          │  (Tor SOCKS5)
          ▼
   crawler ─raw.crawl→ sanitizer ─sanitized→ analysis ─analysis.ready→ ai_layer
                                                                          │ ai.output
                                                                          ▼
                                                                      db_writer
                                                  ┌───────────────┬───────┴───────┐
                                                  ▼               ▼               ▼
                                             PostgreSQL       OpenSearch        Neo4j
                                                  │                               │
                                                  └────────── dashboard ──────────┘
   telegram_collector ─telegram.raw→ (same pipeline)        graph_analytics → SNA scores
```

**Services (13 long-running + one-shot `tls-init`):** `tor`, `rabbitmq`, `postgres`, `opensearch`, `neo4j`, `crawler`, `sanitizer`, `analysis`, `ai_layer`, `db_writer`, `dashboard`, `telegram_collector`, `graph_analytics`.

**Networks (all internal TLS):** `tor_net` (Tor egress) · `queue_net` (`internal`) · `db_net` (`internal`). The crawler is the only service that bridges Tor and the queue; the dashboard sits on `db_net` only.

**Classification:** an offline, deterministic **rule-lexicon engine** (no LLM, no network) — ~2,000 weighted phrases across 20 threat categories + `unknown`, with prompt-injection guardrails and a CSAM quarantine gate. (The original Ollama LLM stage was removed for being the pipeline bottleneck.)

---

## Prerequisites

| Requirement | Notes |
|---|---|
| **Docker** | Docker Desktop (Windows/macOS, WSL2 backend) or Docker Engine 24+ with the **compose plugin** (`docker compose`, not `docker-compose`). |
| **RAM** | ~**10–12 GiB** free recommended. OpenSearch (2g) + Neo4j (2g) + Postgres (1g) dominate. 8 GiB works but is tight. |
| **Disk** | ~10 GB for images + volumes. |
| **OS** | Linux, macOS, or Windows 11. On Linux, OpenSearch needs `vm.max_map_count=262144` (see Troubleshooting). |
| **OpenSSL** | For secret generation in `setup.sh` (preinstalled on macOS/Linux; Git Bash on Windows). |
| **Git** | To clone the repo. |
| **Python 3.12+** | **Optional** — only to run the test suite locally. Not needed to run the stack. |

You do **not** need to install Python, spaCy, or any service locally to run DWITP — everything runs in containers.

---

## Installation

```bash
git clone https://github.com/Sid1125/DWITP.git
cd DWITP
```

### Option A — scripted (recommended)

The setup script generates `infra/.env` with fresh random secrets (including a valid audit-encryption key), then builds all images.

```bash
# Linux / macOS
./scripts/setup.sh

# Windows PowerShell (run from the repo root)
.\scripts\setup.ps1
```

It prints the generated dashboard password at the end. Re-running keeps an existing `infra/.env` (delete it to regenerate).

### Option B — manual

```bash
cp .env.example infra/.env
# Edit infra/.env: set the REQUIRED secrets and generate AUDIT_ENCRYPTION_KEY:
#   openssl rand -base64 32 | tr '+/' '-_'
cd infra && docker compose build
```

---

## Configuration

All configuration lives in **`infra/.env`** (read by Docker Compose). The required values:

| Variable | Required | Notes |
|---|---|---|
| `POSTGRES_PASSWORD` | ✅ | any strong value |
| `OPENSEARCH_PASSWORD` | ✅ | must be strong (upper+lower+digit+symbol, 8+) |
| `NEO4J_PASSWORD` | ✅ | any strong value |
| `RABBITMQ_PASSWORD` | ✅ | any strong value |
| `DASHBOARD_PASSWORD` | ✅ | analyst login password |
| `DASHBOARD_SECRET_KEY` | ✅ | session signing key |
| `AUDIT_ENCRYPTION_KEY` | ✅ | **must be a valid Fernet key** — every service exits without it. Generate: `openssl rand -base64 32 \| tr '+/' '-_'` or `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | optional | separate Admin Panel login (falls back to the analyst login with a warning) |
| `DREAD_USERNAME` / `DREAD_PASSWORD` | optional | Dread login is captcha-blocked — prefer a cookie file (below) |
| `TELEGRAM_API_ID` / `_HASH` / `_SESSION` | optional | provisioned out-of-band; collector idles until set ([`TELEGRAM.md`](TELEGRAM.md)) |

See [`.env.example`](.env.example) for the full annotated list.

**Sources** are governed in [`config/sources.yaml`](config/sources.yaml) — only entries with `status: approved` are crawled. **Dread authentication** uses a Netscape cookie file at `config/dread_cookies.txt` (export an authenticated session from a Tor browser).

---

## Running

```bash
cd infra
docker compose up -d
```

- **Dashboard:** <https://127.0.0.1:8079> — self-signed cert, so accept the browser warning. Bound to localhost only.
- **Login:** `analyst` / the `DASHBOARD_PASSWORD` from `infra/.env`.

The first start runs the one-shot `tls-init` (generates the internal CA + service certs) before the rest come up. Give OpenSearch/Neo4j a minute to become healthy.

```bash
docker compose ps              # service status
docker compose logs -f         # follow all logs
docker compose logs -f crawler # one service
```

### Verify the deployment

```bash
./scripts/healthcheck.sh         # container + connectivity checks
./scripts/e2e_test.sh --cleanup  # inject a synthetic record through the full pipeline
```

### Stop / reset

```bash
cd infra
docker compose down       # stop (keeps all data volumes)
docker compose down -v    # stop AND delete all data (postgres/opensearch/neo4j/tls)
```

---

## Usage

1. **Open the dashboard** at <https://127.0.0.1:8079> and log in.
2. **Operations Overview** (home) — live stat cards (open findings, needs-review, 24h, sources, actors, pages crawled), threat-findings-by-category, source health, and recent findings. Auto-refreshes every 60s.
3. **Findings** — filter by review status / category; click a finding to see the evidence, extracted entities, cross-source corroboration, and the verbatim quote backing the category; mark reviewed.
4. **Crawled / Search / Sources / Actors** — browse all crawled pages, full-text search, the source registry + reputation, and threat-actor profiles. Analysts can *propose* new sources here.
5. **Admin Panel** (`/admin`, separate login) — approve proposed/discovered sources, manage the registry and users, view the encrypted audit log, and toggle the classification kill switch.

Findings only appear once the crawler has approved sources to fetch and content flows through the pipeline. Watch progress with `docker compose logs -f crawler db_writer`.

---

## Project structure

```
DWITP/
├── config/
│   ├── sources.yaml              # Approved .onion source registry (human-gated)
│   └── dread_cookies.txt         # Dread auth cookies (Netscape format; gitignored)
├── infra/
│   ├── docker-compose.yml        # All services, 3 networks, volumes
│   ├── .env                      # Secrets (generated by setup; gitignored)
│   └── docker/                   # Dockerfiles per service (+ tls-init, tor)
├── src/
│   ├── common/                   # queue (RabbitMQ TLS), security (validation/audit/Fernet), models, notifier
│   ├── crawler/main.py           # Tor crawler: circuit rotation, cookie auth, login-wall/listing handling
│   ├── sanitizer/main.py         # HTML safe-parse + prompt-injection gateway
│   ├── analysis/main.py          # regex IOC extraction + spaCy NER
│   ├── ai_layer/
│   │   ├── classifier.py         # offline rule-lexicon engine (~2k phrases, 20 categories)
│   │   └── main.py               # queue worker: PI quarantine, kill switch, CSAM gate
│   ├── db_writer/main.py         # consumer → Postgres + OpenSearch + Neo4j (+ Telegram path)
│   ├── telegram_collector/main.py# read-only MTProto collector (INTEL-002)
│   ├── graph_analytics/main.py   # SNA scoring over the Telegram actor graph
│   └── dashboard/main.py         # FastAPI + Jinja2 web UI
├── scripts/                      # setup.sh/ps1, build.ps1, healthcheck.sh, e2e_test.sh, init-db.sql, ...
├── tests/                        # pytest suite
├── features.md · TELEGRAM.md · THREAT_LEXICON.md      # capability docs
└── ARCH-001 / AI-001 / DEV-001 / INTEL-001 / INTEL-002 / IR-001 / security spec   # governance
```

---

## Message queues (RabbitMQ, vhost `/dwitp`, TLS)

| Queue | Producer | Consumer |
|---|---|---|
| `raw.crawl` | crawler | sanitizer |
| `sanitized` | sanitizer | analysis |
| `analysis.ready` | analysis | ai_layer |
| `ai.output` | ai_layer | db_writer |
| `telegram.raw` | telegram_collector | sanitizer |
| `discovery.candidate` | analysis | db_writer (staged for admin review) |

Control: `control.ai` and `control.collection` fanout exchanges carry the kill switches.

---

## Security highlights

Non-root containers, `cap_drop: ALL`, read-only rootfs, per-service limits, and `internal` networks; internal CA with RabbitMQ TLS, PostgreSQL **mTLS**, Neo4j bolt+TLS, HTTPS dashboard; SSRF-guarded crawler; a mandatory prompt-injection gateway; an encrypted append-only audit log; per-source PI-campaign quarantine; and a CSAM detect-and-quarantine gate (content dropped, never retained — TG-G4). The AI is an analyst, not an operator: no shell, no network, no autonomous action; all findings require human review. Full detail in [`features.md`](features.md) and the governance docs.

---

## Testing

The test suite runs on the host (Python 3.12+), separate from the containers:

```bash
python3 -m venv .venv && . .venv/bin/activate     # Windows: py -3.12 -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.in
python -m spacy download en_core_web_sm
pytest tests/
```

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| **A service exits immediately / "AUDIT_ENCRYPTION_KEY required"** | `infra/.env` is missing or `AUDIT_ENCRYPTION_KEY` is empty/invalid. Regenerate it as a Fernet key (see Configuration) and `docker compose up -d`. |
| **`docker compose` errors on `${VAR:?err}`** | `infra/.env` doesn't exist or is incomplete. Run the setup script, or `cp .env.example infra/.env` and fill it in. Run compose from the `infra/` directory. |
| **Windows: env vars look garbled / not read** | The `.env` was saved with a BOM. Re-save `infra/.env` as UTF-8 **without BOM** (the setup script does this correctly). |
| **OpenSearch container exits (Linux)** | `sudo sysctl -w vm.max_map_count=262144` (persist in `/etc/sysctl.conf`). |
| **Containers down after laptop sleep/resume** | Services use `restart: always`; if stuck, `cd infra && docker compose up -d` to reconcile. |
| **Dashboard "your connection is not private"** | Expected — it's a self-signed cert. Proceed/accept the warning. |
| **Dashboard not reachable** | It's HTTPS on **8079**, localhost-only: <https://127.0.0.1:8079> (not `http`, not 8080). |
| **No findings appearing** | Ensure a source is `approved` in `config/sources.yaml` and the crawler is running: `docker compose logs -f crawler`. |
| **First build is slow** | Expected — base images + Python deps download once, then cache. |

---

## Governance documents

`ARCH-001` (architecture & non-interaction) · `AI-001` (AI governance) · `DEV-001` (dev standard) · `INTEL-001` (intelligence requirements) · `INTEL-002` (Telegram intelligence + guardrails) · `IR-001` (incident response) · `Dwitp_vibe_security_spec.md` (master security spec).
