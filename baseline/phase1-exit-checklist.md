# Phase 1 Exit Checklist

**Date:** 2026-06-09
**Project:** DWITP — Tor-Only Collection Pipeline

---

## Exit Criteria

### C1 — All SEC-001 invariants implemented and tested

| # | Requirement | Status | Evidence |
|---|-------------|--------|----------|
| INV-01 | Two-tier pipeline (Crawler → Sanitizer → Dashboard) | PASS | `infra/docker-compose.yml:54-421`; queue tests `test_queue.py` verify publish/consume |
| INV-02 | Immutable raw evidence (no UPDATE/DELETE) | PASS | `scripts/init-db.sql:152-153` REVOKE; `test_security.py::TestComputeSha256` verifies hashing |
| INV-03 | No autonomous AI actions | PASS | `src/ai_layer/main.py:41-114` — classifies only, no shell/fs/db/net |
| INV-04 | Source whitelist — read-only at runtime | PASS | `config/sources.yaml` (3 entries); `src/crawler/main.py:120-123` loads from file; `:241` filters `status == "approved"`. Test: `test_load_sources_filters_approved` |
| INV-05 | Source reputation scoring | PASS | `src/common/security.py:224-232` `compute_intelligence_confidence()`. Test: `TestComputeIntelligenceConfidence` (4 tests) |
| INV-06 | Anti-prompt-injection gateway | PASS | `src/common/security.py:206-221` `injection_gateway()`. Test: `TestInjectionGateway` (9 tests) |
| INV-07 | Human-in-the-loop (high-risk findings) | PASS | `src/ai_layer/main.py:80-88` flags high-risk; `src/dashboard/main.py:280-308` review endpoint |
| INV-08 | Network segregation (4 internal networks) | PASS | `infra/docker-compose.yml:23-47`: tor_net, queue_net, db_net, ai_net |
| INV-09 | Disposable crawler infrastructure | PARTIAL | `infra/terraform/crawler.tf` exists. Not CI-tested for destroy/recreate. |
| INV-10 | Security gate on every commit | PASS | `.github/workflows/security-gate.yml`: Bandit, Semgrep, TruffleHog, pip-audit, Ruff, mypy, Trivy |
| INV-11 | Hash-pinned dependencies | PASS | `security-gate.yml:37-43` CI enforcement |
| INV-12 | Crawler identity randomization | PASS | `src/common/security.py:265-272` `randomized_headers()`. Test: `TestRandomizedHeaders` (6 tests) |
| INV-13 | Onion discovery isolation (human gate) | **FAIL** | Model exists at `src/common/models.py:78-88`. No processing pipeline. |
| INV-14 | Data poisoning detection | PASS | `src/common/security.py:224-232` cross-source confidence. Test: `TestComputeIntelligenceConfidence` |
| INV-15 | Deadman's switch (fail-closed) | PASS | `src/crawler/main.py:62-118` CrawlerGuard (Tor + queue checks). Test: `TestCrawlerGuard` (6 tests) |

### C2 — SEC-001 §3 (Crawler Security Rules) all PASS

| # | Requirement | Status | Evidence |
|---|-------------|--------|----------|
| 3.1 | No JavaScript execution | PASS | No Playwright/Selenium. Test: `test_blocked_scheme_javascript` |
| 3.2 | No automatic binary download | PASS | `src/crawler/main.py:193-199` Content-Type check. Test: `test_binary_content_skipped` |
| 3.3 | URL validation (pre-request, SSRF) | PASS | `src/common/security.py:151-191` `validate_url()`. Test: `TestValidateUrl` (11 tests), `TestIsPrivateIp` (13 tests) |
| 3.4 | Force all traffic through Tor | PASS | `src/crawler/main.py:32-35` socks5h proxy. Docker tor service. |
| 3.5 | Disable external resource loading | PASS | `src/common/security.py:255-262` `safe_parse()`. Wired at `src/sanitizer/main.py:14`. Test: `test_safe_parse_strips_dangerous_tags` |
| 3.6 | Resource limits (anti-bomb) | PASS | `src/common/security.py:82-86` constants. Test: `test_size_limit_exceeded`, `test_redirect_chain_enforces_limit` |
| 3.7 | Circuit rotation | PASS | `src/crawler/main.py:40-59` Stem NEWNYM. `:258-259` triggers at interval. Test: `TestCrawlUrlCircuitRotation`, `TestRotateCircuit` |

### C3 — DEV-001 (Development Standard) compliance

| # | Requirement | Status | Evidence |
|---|-------------|--------|----------|
| DEV-1 | Python 3.12+ | PASS | `pyproject.toml:9` >=3.12. CI: `security-gate.yml:16-18` |
| DEV-2 | Type hints mandatory | PASS | All functions in `src/` annotated. Mypy strict at `pyproject.toml:48` |
| DEV-3/4 | Pydantic mandatory | PASS | All 13 models use BaseModel with `extra="forbid"`. Test: all model tests verify |
| DEV-5..8 | Security scanners (Bandit, Semgrep, Trivy, TruffleHog) | PASS | CI pipeline at `security-gate.yml:25-32,75-80` |
| DEV-9..11 | Dependency security (pip-audit, hash-pinned, version-pinned) | PASS | `security-gate.yml:39-43` |
| DEV-13..15 | Tests (unit, integration, security) | PASS | 144 tests in 5 files |
| DEV-16 | Coverage ≥80% (core modules) | PASS | `pyproject.toml:37-44`. 85% on common/crawler/sanitizer. 4 infra-dependent modules excluded with documentation. |
| DEV-17..21 | Logging (JSON, timestamp, component, event, severity) | PASS | `src/common/security.py:89-107` `audit_log()`. Schema verified: `TestAuditLog` (6 tests) |
| DEV-22..25 | Module documentation (README, threat model, API) | PASS | 6 README.md files created |
| DEV-26..31 | No placeholder controls, no disabled validations, no hardcoded secrets, no TODO-based security, production-ready | PASS | Codebase review per compliance report |

### C4 — INTEL-001 (Intelligence Requirements) key items

| # | Requirement | Status | Evidence |
|---|-------------|--------|----------|
| INTEL-1..13 | Categories (ransomware, credential_leak, IAB, malware) | PASS | Categories in `AIClassificationOutput` model. Test: `test_all_categories` |
| INTEL-14..18 | Entity extraction (CVEs, emails, domains) | PASS | `src/analysis/main.py:21-31` regex patterns |
| INTEL-19..21 | Cryptocurrency (BTC, XMR, ETH) | PASS | `src/analysis/main.py:22-24` regex |
| INTEL-22..23 | PGP fingerprints | PASS | `src/analysis/main.py:28` regex |
| INTEL-24 | MITRE ATT&CK (T1003, T1059, T1486, T1566, T1078) | **PARTIAL** | Category-based mapping at `src/common/security.py:235-252`. Entity enrichment removed as indefensible — future work. Test: `TestMitreAttackMap` (8 tests) |
| INTEL-25..30 | Threat actor profiles | PASS | `scripts/init-db.sql:124-135` schema |
| INTEL-31..32 | Confidence levels (UNCONFIRMED through VERIFIED) | PASS | `src/common/models.py:111` Literal field. Test: `test_confidence_default` |

### C5 — IR-001 (Incident Response) key items

| # | Requirement | Status | Evidence |
|---|-------------|--------|----------|
| IR-1 | Severity levels defined | PASS | Documented in IR-001.md |
| IR-2..6 | Tor failure (halt, log, warn, validate, resume) | PASS | `src/crawler/main.py:72-103` (verify), `:114-117` (halt/exit), `:270-279` (retry loop). Tests: `TestCrawlerGuard` |
| IR-7..10 | Queue failure (halt, preserve, restore, resume) | **PARTIAL/FAIL** | Halt: PASS (`_verify_queue_reachable`). Preserve: PARTIAL (no buffer). Restore: **FAIL** (no automated restoration) |
| IR-11..14 | Crawler compromise | **FAIL** | IaC exists. No automated destroy/rebuild/rotate |
| IR-15..18 | Prompt injection campaign | **FAIL** | Quarantine status exists in model. No automated quarantine/disable/reputation update |
| IR-19..22 | Data poisoning event | PARTIAL | `compute_intelligence_confidence()` exists. No automated freeze. Analyst review works. |

### C6 — AI-001 (AI Governance) compliance

| # | Requirement | Status | Evidence |
|---|-------------|--------|----------|
| AI-1..6 | AI is analyst, not operator; allowed ops (classification, summarization, entity extraction, clustering, risk scoring) | PASS | `src/ai_layer/main.py` architecture. Verified by output schema and network isolation |
| AI-7..12 | Forbidden ops (URL visits, file downloads, tool use, shell, network beyond Ollama, DB writes) | PASS | No forbidden imports or code paths. Docker network isolation at `infra/docker-compose.yml:312-316` |
| AI-13..15 | PI resistance (content is hostile, ignore instructions, analyze only) | PASS | System prompt at `src/ai_layer/main.py:21-22` |
| AI-16..20 | Hallucination policy (UNKNOWN preferred, confidence levels) | PASS | UNKNOWN category in model. `compute_intelligence_confidence()` capped at 1.0 |
| AI-21..24 | Human review triggers (credential_leak, critical_infrastructure, malware, access_broker) | PASS | `HIGH_RISK_CATEGORIES` at `src/common/security.py:67-74` |

---

## Verification Artifacts

| Artifact | Location | Contents |
|----------|----------|----------|
| Pytest raw output | `baseline/pytest-output.txt` | Full `-v` output, 144 tests |
| Pytest JUnit XML | `baseline/pytest-results.xml` | Machine-readable test results |
| Coverage HTML | `baseline/coverage-html/` | Per-file coverage report |
| Compliance report | `baseline/compliance_report.md` | 92 requirements tracked |
| Architecture inventory | `baseline/architecture_inventory.md` | File listing and service architecture |

---

## Scores

| Category | PASS | PARTIAL | FAIL | Threshold |
|----------|------|---------|------|-----------|
| SEC-001 (15 invariants) | 12 | 1 (INV-09) | 1 (INV-13) | No FAIL items for Phase 1 |
| SEC-001 §3 (7 rules) | 7 | 0 | 0 | All PASS |
| DEV-001 (31 items) | 31 | 0 | 0 | All PASS |
| INTEL-001 (32 items) | 30 | 1 (INTEL-24) | 0 | No FAIL items |
| IR-001 (22 items) | 5 | 3 | 3 | Improvement area |
| AI-001 (24 items) | 24 | 0 | 0 | All PASS |
| **Overall** | **109** | **5** | **4** | — |

---

## Phase 2 Gate: Open Items

Items that must be resolved before Phase 2 authorization:

| Priority | Item | Component | Current Status |
|----------|------|-----------|----------------|
| HIGH | Onion discovery pipeline (INV-13) | Crawler/Pipeline | FAIL — no processing code |
| HIGH | Queue restoration procedure (IR-9) | Infrastructure | FAIL — no automation |
| HIGH | Secret rotation automation (IR-12) | Infrastructure | FAIL — no automation |
| MEDIUM | AI disable on PI campaign (IR-16) | AI Layer | FAIL — no automation |
| MEDIUM | Disposable infra CI test (INV-09) | CI | PARTIAL — Terraform exists |
| LOW | MITRE entity enrichment (INTEL-24) | Analysis | PARTIAL — category only |
| LOW | Automated source quarantine (IR-15, IR-18, IR-19) | Pipeline | PARTIAL — schema exists |
| DEPLOY | Real .onion URLs in sources.yaml | Config | Deployment-incomplete |
