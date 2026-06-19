# DWITP — Dark Web Intelligence & Threat Monitoring Platform

Containerized, Tor-based OSINT pipeline that crawls approved `.onion` dark web sources, sanitizes content, extracts entities, classifies via local LLM (Ollama), and presents findings through a FastAPI web dashboard.

## Architecture

```
.onion → Tor → Crawler → Sanitizer → Analysis → AI Layer → DB Writer → Dashboard
                              RabbitMQ message queues throughout
```

| Stage | What it does |
|-------|-------------|
| **Crawler** | Requests + BeautifulSoup, Tor SOCKS5 proxy, circuit rotation, dread cookie auth |
| **Sanitizer** | Prompt injection gateway (13 regex patterns), HTML stripping |
| **Analysis** | spaCy NER + regex entity extraction (CVE, BTC, XMR, email, domains, etc.) |
| **AI Layer** | Ollama LLM classification (llama3.2:1b), MITRE ATT&CK mapping, entity validation |
| **DB Writer** | Persists to PostgreSQL, OpenSearch, Neo4j |
| **Dashboard** | FastAPI web UI with HTTPS, auth, rate limiting, search |

## Stack

- **Runtime**: 13 Docker containers, 4 isolated networks
- **Queue**: RabbitMQ (7 durable queues, mTLS)
- **Databases**: PostgreSQL 16, OpenSearch 2.14, Neo4j 5.20
- **LLM**: Ollama (llama3.2:1b), 2 competing consumers
- **Security**: `read_only` rootfs, `cap_drop: ALL`, non-root users, seccomp, Fernet audit log

## Quick Start

```bash
cd infra

# Generate .env with random secrets, install deps, build images
# (Linux)
./scripts/setup.sh
# (Windows PowerShell)
.\scripts\setup.ps1

# Start all services
docker compose -p infra up -d

# Check health
./scripts/healthcheck.sh
```

## Configuration

- `config/sources.yaml` — Approved `.onion` sources with governance metadata
- `config/dread_cookies.txt` — Netscape-format cookies for authenticated dread access
- `infra/.env` — All secrets (auto-generated, gitignored)
- `infra/docker-compose.yml` — Service definitions, networks, volumes

## Tests

```bash
pytest --cov=src --cov-fail-under=85 tests/
```

182 tests, 92.8% coverage (85% threshold).

## License

UNLICENSED — Internal security tool. See governance documents (`AI-001`, `ARCH-001`, `DEV-001`, `INTEL-001`, `IR-001`) for usage policy.
