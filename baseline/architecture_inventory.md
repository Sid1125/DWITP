# DWITP Baseline Architecture Inventory
**Generated:** 2026-06-08
**Purpose:** Pre-remediation snapshot of all source, config, and infrastructure files.

## Source Code (`src/`)

```
src/
├── common/           # Shared library: models, security, queue
│   ├── __init__.py
│   ├── models.py     # Pydantic data models
│   ├── queue.py      # RabbitMQ connection helpers
│   └── security.py   # Validation, sanitization, anti-PI
├── crawler/          # Tor-based crawler
│   ├── __init__.py
│   └── main.py
├── sanitizer/        # Anti-prompt-injection gateway
│   ├── __init__.py
│   └── main.py
├── analysis/         # spaCy NER + entity extraction
│   ├── __init__.py
│   └── main.py
├── ai_layer/         # Ollama classification
│   ├── __init__.py
│   └── main.py
├── dashboard/        # FastAPI web UI
│   ├── __init__.py
│   └── main.py
└── db_writer/        # Pipeline consumer → storage
    ├── __init__.py
    └── main.py
```

## Infrastructure (`infra/`)

```
infra/
├── docker-compose.yml          # 11 services, 5 internal networks
├── docker/
│   ├── tor/                     # Tor SOCKS proxy
│   │   ├── Dockerfile
│   │   ├── entrypoint.sh
│   │   └── torrc
│   ├── crawler/
│   │   └── Dockerfile
│   ├── sanitizer/
│   │   └── Dockerfile
│   ├── analysis/
│   │   └── Dockerfile
│   ├── ai_layer/
│   │   └── Dockerfile
│   ├── dashboard/
│   │   ├── Dockerfile
│   │   └── entrypoint.sh
│   └── db_writer/
│       └── Dockerfile
└── terraform/
    └── crawler.tf
```

## Configuration (`config/`)

```
config/
├── sources.yaml          # Source registry (hardcoded — to be replaced)
└── seccomp/
    └── crawler.json      # Docker seccomp profile
```

## CI/CD (`.github/`)

```
.github/workflows/
└── security-gate.yml     # Bandit, Semgrep, Trivy, TruffleHog, pip-audit, ruff, mypy
```

## Governance Documents (project root)

```
AI-001_AI_Governance_and_Safety.md
ARCH-001_System_Architecture.md
DEV-001_Development_Standard.md
Dwitp_vibe_security_spec.md
INTEL-001_Intelligence_Requirements.md
IR-001_Incident_Response_Playbook.md
```

## Service Architecture (current)

```
Crawler → [raw.crawl] → Sanitizer → [sanitized] → Analysis → [analysis.ready] → AI Layer → [ai.output] → DB Writer → PostgreSQL + OpenSearch + Neo4j
                                                                                                                     ↑
                                                                                                              Dashboard (read-only)
```

## Networks

| Network | Internal | Services |
|---------|----------|----------|
| tor_net | yes | crawler, tor |
| queue_net | yes | crawler, sanitizer, analysis, ai_layer, db_writer, rabbitmq |
| db_net | yes | dashboard, db_writer, postgres, opensearch, neo4j |
| ai_net | yes | ai_layer, ollama |
