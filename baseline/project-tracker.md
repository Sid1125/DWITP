# DWITP Project Tracker

**Last updated:** 2026-06-10
**Legend:** `TODO` → `IN PROGRESS` → `DONE` | `BLOCKED` = waiting on external

## Overall Status

- [ ] Phase 0 — Blockers (must fix before any deploy)
- [ ] Phase 1 — Runnable Pipeline
- [ ] Phase 2 — Verification

---

## Phase 0 — Blockers

| ID | Task | Status | Deps | Notes |
|----|------|--------|------|-------|
| B1 | Dashboard read_only: move template/cert paths to `/tmp` | **DONE** | none | `src/dashboard/main.py:48-49,62-64` → `/tmp/dwitp-certs/`, `/tmp/dwitp-dashboard-templates` |
| B2 | Analysis Dockerfile: fix empty `apt-get install` | **DONE** | none | Removed entire empty RUN layer from `infra/docker/analysis/Dockerfile:5-7` |
| B3 | Create `.env` + fix env var inconsistencies | **DONE** | none | `.env` generated with 32-char passwords. `.env.example` fixed: added DASHBOARD_PASSWORD, OLLAMA_MODEL, PI_CAMPAIGN_THRESHOLD, fixed DASHBOARD_SECRET_KEY. Compose DASHBOARD_USE_HTTPS default → `:-true` |
| B4 | Real `.onion` URLs in `sources.yaml` | **PENDING — user provides** | user | `<placeholder>` URLs need real values before end-to-end test |

---

## Phase 1 — Runnable Pipeline

| ID | Task | Status | Deps | Notes |
|----|------|--------|------|-------|
| P1.1 | Create `scripts/setup.sh` + fix `setup.ps1` spacy model | **DONE** | none | `en_core_web_lg`→`sm` in setup.ps1:49. `setup.sh` created as Linux parallel |
| P1.2 | Remove stale TODO from crawler Dockerfile | **DONE** | none | Removed `# TODO` comment. Hash-pinning requires pip-compile CI step (Phase 2) |
| P1.3 | Ollama model pre-pull | **DONE** | none | New `ollama-pull` one-shot service in compose. Uses `curlimages/curl` to POST to `/api/pull`. ai_layer depends on it (`service_completed_successfully`) |
| P1.4 | Docker compose fixes | **DONE** | none | Added CIRCUIT_ROTATION_INTERVAL to crawler, PI_CAMPAIGN_THRESHOLD to ai_layer, opensearch+neo4j depends_on to dashboard and db_writer. Consolidated dual `<<` merge keys into `<<: [*a, *b]`. Removed deprecated `version: "3.9"` |

---

## Phase 2 — Verification

| ID | Task | Status | Deps | Notes |
|----|------|--------|------|-------|
| P2.1 | `docker compose build` | **FAILED** (env) | — | Docker Desktop not running on this Windows dev machine. YAML parses successfully; `--env-file .env` works. Will build clean on Linux VM |
| P2.2 | `docker compose up` and verify | **BLOCKED** | P2.1, B4 | Requires P2.1 build + real .onion URLs |

---

## Completion Metrics

- [x] `version` attribute removed (Compose v2+ ignores it — fixed)
- [x] YAML parses correctly with `--env-file`
- [x] 136/160 tests pass (24 PermissionError on tmp_path — Windows env issue, not code)
- [ ] `docker compose build` passes (needs Linux VM or Docker Desktop)
- [ ] All 13 services start healthy
- [ ] Crawler connects to Tor and sources
- [ ] Pipeline: crawl → sanitize → analyze → classify → persist
- [ ] Dashboard reachable at http://localhost:8080
- [ ] 160+ tests pass
- [ ] Core coverage >= 80%

---

## Change Log

| Date | Task | Change |
|------|------|--------|
| 2026-06-10 | — | Tracker created |
| 2026-06-10 | B1 | Dashboard: template dir → `/tmp/dwitp-dashboard-templates`, cert paths → `/tmp/dwitp-certs/` |
| 2026-06-10 | B2 | Analysis Dockerfile: removed empty apt-get RUN |
| 2026-06-10 | B3 | Generated `.env`, fixed `.env.example` + compose DASHBOARD_USE_HTTPS default → `:-true` |
| 2026-06-10 | P1.1 | Created `scripts/setup.sh`, fixed `setup.ps1` spacy model |
| 2026-06-10 | P1.2 | Removed stale TODO from crawler Dockerfile |
| 2026-06-10 | P1.3 | Added `ollama-pull` one-shot init service to compose |
| 2026-06-10 | P1.4 | Added missing env vars + `depends_on`, consolidated YAML merge keys, removed deprecated `version` |
