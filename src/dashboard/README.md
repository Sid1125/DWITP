# Dashboard Module

FastAPI web dashboard for analyst workflows. Features: login with signed cookies (itsdangerous), HSTS, findings list, finding detail with review workflow, full-text search via OpenSearch, sources overview, threat actors list. Read-only except login and review.

## API Endpoints

- `POST /login` — authenticate, set `dwitp_session` cookie (8h expiry, httponly, samesite=strict).
- `GET /` — landing page with summary stats.
- `GET /findings` — paginated, filterable by reviewed status and category.
- `GET /finding/{id}` — single finding detail.
- `POST /finding/{id}/review` — approve/dismiss a finding.
- `GET /search?q=` — OpenSearch multi_match search.
- `GET /sources` — source registry table.
- `GET /actors` — threat actors table.

## Threat Model

- **Session hijacking** — mitigated by signed cookies with 8h expiry, httponly, samesite=strict.
- **SQL injection** — parameterized queries via psycopg2.
- **XSS** — Jinja2 auto-escaping enabled by default.
- **CSRF** — cookie-based auth with SameSite=Strict; no unprotected state-changing endpoints.

## Test Coverage

Not tested — requires live PostgreSQL and OpenSearch services. Infra-dependent exclusion documented in `pyproject.toml`.
