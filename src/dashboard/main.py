from __future__ import annotations

import collections
import html
import html.parser
import json
import os
import re
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Literal, Optional

import psycopg2
import psycopg2.extras
import yaml
from opensearchpy import OpenSearch
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from jinja2 import Environment, FileSystemLoader
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from pydantic import BaseModel, Field

from src.common.models import CrawlTarget
from src.common.queue import QueueClient
from src.common.security import (
    AUDIT_LOG_PATH,
    audit_log,
    decrypt_log_entry,
    hash_password,
    validate_url,
    verify_password,
)

_POSTGRES_PASSWORD = os.environ.get("POSTGRES_PASSWORD")
if not _POSTGRES_PASSWORD:
    print("FATAL: POSTGRES_PASSWORD environment variable is required.")
    sys.exit(1)

POSTGRES_DSN = (
    f"host={os.environ.get('POSTGRES_HOST', 'postgres')} "
    f"port={os.environ.get('POSTGRES_PORT', '5432')} "
    f"dbname={os.environ.get('POSTGRES_DB', 'dwitp')} "
    f"user={os.environ.get('POSTGRES_USER', 'dwitp')} "
    f"password={_POSTGRES_PASSWORD} "
    f"sslmode={os.environ.get('POSTGRES_SSLMODE', 'require')} "
    f"sslcert={os.environ.get('PGSSLCERT', '/etc/dwitp/tls/dashboard/dashboard.crt')} "
    f"sslkey={os.environ.get('PGSSLKEY', '/etc/dwitp/tls/dashboard/dashboard.key')} "
    f"sslrootcert={os.environ.get('PGSSLROOTCERT', '/etc/dwitp/tls/ca/ca.crt')}"
)

_OPENSEARCH_PASSWORD = os.environ.get("OPENSEARCH_PASSWORD")
if not _OPENSEARCH_PASSWORD:
    print("FATAL: OPENSEARCH_PASSWORD environment variable is required.")
    sys.exit(1)

OPENSEARCH_HOST = os.environ.get("OPENSEARCH_HOST", "opensearch")
OPENSEARCH_PORT = os.environ.get("OPENSEARCH_PORT", "9200")
OPENSEARCH_USER = os.environ.get("OPENSEARCH_USER", "admin")
OPENSEARCH_PASSWORD = _OPENSEARCH_PASSWORD
# OpenSearch runs with the security plugin disabled (plain HTTP). Configurable so
# a TLS-enabled deployment can flip this back to "https".
OPENSEARCH_SCHEME = os.environ.get("OPENSEARCH_SCHEME", "http")

DASHBOARD_HOST = os.environ.get("DASHBOARD_HOST", "0.0.0.0")
DASHBOARD_PORT = int(os.environ.get("DASHBOARD_PORT", "8080"))
DASHBOARD_SECRET_KEY = os.environ.get("DASHBOARD_SECRET_KEY", "")
DASHBOARD_USERNAME = os.environ.get("DASHBOARD_USERNAME", "analyst")
DASHBOARD_PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "")
DASHBOARD_USE_HTTPS = os.environ.get("DASHBOARD_USE_HTTPS", "true").lower() == "true"
DASHBOARD_HTTPS_CERT = os.environ.get("DASHBOARD_HTTPS_CERT", "/tmp/dwitp-certs/cert.pem")
DASHBOARD_HTTPS_KEY = os.environ.get("DASHBOARD_HTTPS_KEY", "/tmp/dwitp-certs/key.pem")

SESSION_MAX_AGE = 28800  # 8 hours
COOKIE_NAME = "dwitp_session"

if not DASHBOARD_SECRET_KEY or DASHBOARD_SECRET_KEY == "change-me":
    print("WARNING: DASHBOARD_SECRET_KEY not set. Generating ephemeral key — sessions invalidated on restart.")
    DASHBOARD_SECRET_KEY = uuid.uuid4().hex + uuid.uuid4().hex

serializer = URLSafeTimedSerializer(DASHBOARD_SECRET_KEY, salt="dashboard-session")

# ─── Admin Panel — separate sign-off authority ──────────────────────────
# Per INV-04, config/sources.yaml is read-only at runtime and adding a crawl
# target requires explicit human approval — never a runtime API call. The
# main dashboard lets an analyst *propose* a source (pending_sources, never
# crawled). Only the Admin Panel, gated behind its own login, can approve it
# and write it into sources.yaml. Distinct credentials and a distinct
# session cookie keep "propose" and "sign off" as two deliberate actions,
# even when the same operator performs both.
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME") or DASHBOARD_USERNAME
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD") or ""
if not ADMIN_PASSWORD:
    ADMIN_PASSWORD = DASHBOARD_PASSWORD
    print("WARNING: ADMIN_PASSWORD not set. Admin Panel falls back to the dashboard password — "
          "set a distinct ADMIN_USERNAME/ADMIN_PASSWORD for real separation of duties.")

ADMIN_COOKIE_NAME = "dwitp_admin_session"
SOURCES_CONFIG = os.environ.get("SOURCES_CONFIG", "/app/config/sources.yaml")

admin_serializer = URLSafeTimedSerializer(DASHBOARD_SECRET_KEY, salt="admin-session")

app = FastAPI(title="DWITP Dashboard")

# Single-process in-memory rate limiter: 60 req/min per IP.
# WARNING: per-process state. If scaled to multiple replicas, move this
# to a shared store (Redis) or terminate TLS at a reverse proxy (nginx/Traefik).
_RATE_LIMIT_WINDOW = 60.0
_RATE_LIMIT_MAX = 60
_rate_buckets: dict[str, list[float]] = collections.defaultdict(list)


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "unknown"
    now = time.monotonic()
    bucket = _rate_buckets[client_ip]
    bucket[:] = [t for t in bucket if now - t < _RATE_LIMIT_WINDOW]
    if len(bucket) >= _RATE_LIMIT_MAX:
        from fastapi.responses import PlainTextResponse
        return PlainTextResponse("Rate limit exceeded", status_code=429)
    bucket.append(now)
    return await call_next(request)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    # Prevent the dashboard itself from being embedded in foreign frames
    response.headers["X-Frame-Options"] = "DENY"
    # Stop browsers from MIME-sniffing responses
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Restrict referrer info sent to third parties
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    # CSP: allow inline styles/scripts (needed for embedded templates) but
    # block all external resources and object/embed/base injection.
    # The srcdoc iframe uses its own sandbox attribute for script isolation.
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )
    return response


templates_dir = "/tmp/dwitp-dashboard-templates"
os.makedirs(templates_dir, exist_ok=True)
# Use direct Jinja2 Environment instead of Starlette's Jinja2Templates (cache bug)
jinja_env = Environment(loader=FileSystemLoader(templates_dir), autoescape=True)

STANDARD_ROUTES = {"/", "/findings", "/search", "/sources", "/actors", "/health"}


def prepare_html_preview(html_content: str) -> str:
    cleaned = re.sub(r'<script[^>]*>.*?</script>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
    cleaned = re.sub(r'<style[^>]*>.*?</style>', '', cleaned, flags=re.DOTALL | re.IGNORECASE)
    # Strip event handlers: quoted, unquoted, and backtick-quoted forms
    # e.g. onerror="...", onerror=alert(1), onerror=`alert(1)`
    cleaned = re.sub(r'\bon\w+\s*=\s*(?:["\'][^"\']*["\']|`[^`]*`|[^\s>]+)', '', cleaned, flags=re.IGNORECASE)
    # Strip javascript: and data: URIs in href/src/action attributes
    cleaned = re.sub(r'(href|src|action)\s*=\s*["\']?\s*(?:javascript|data|vbscript):[^"\'>\s]*["\']?', '', cleaned, flags=re.IGNORECASE)
    return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:system-ui,-apple-system,sans-serif;padding:1rem;line-height:1.5;word-wrap:break-word;margin:0;">
{cleaned.strip()}
</body>
</html>"""


class ReviewAction(BaseModel):
    finding_id: str
    action: Literal["approve", "dismiss"]
    reviewer: str = "analyst"


class LoginForm(BaseModel):
    username: str
    password: str


class SourceProposal(BaseModel):
    source_id: str
    url: str
    category: str
    risk_level: Literal["low", "medium", "high"] = "medium"
    review_notes: str = ""
    max_pages: int = Field(default=5, ge=1, le=1000)
    link_selector: str = ""
    queue_wait_seconds: int = Field(default=0, ge=0, le=300)


class RejectAction(BaseModel):
    reason: str = ""


class PromoteCandidateRequest(BaseModel):
    source_id: str
    category: str
    risk_level: Literal["low", "medium", "high"] = "medium"
    review_notes: str = ""
    max_pages: int = Field(default=5, ge=1, le=1000)
    link_selector: str = ""
    queue_wait_seconds: int = Field(default=0, ge=0, le=300)


class SourceStatusChange(BaseModel):
    status: Literal["approved", "pending", "retired", "quarantined"]


class CreateUserRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=256)
    role: Literal["analyst", "admin"] = "analyst"


class ResetPasswordRequest(BaseModel):
    password: str = Field(min_length=8, max_length=256)


class ChangeRoleRequest(BaseModel):
    role: Literal["analyst", "admin"]


def get_db():
    return psycopg2.connect(POSTGRES_DSN)


def get_opensearch():
    return OpenSearch(
        hosts=[{"host": OPENSEARCH_HOST, "port": int(OPENSEARCH_PORT)}],
        http_auth=(OPENSEARCH_USER, OPENSEARCH_PASSWORD),
        use_ssl=(OPENSEARCH_SCHEME == "https"),
        verify_certs=False,
    )


def authenticate_user(username: str, password: str) -> Optional[dict]:
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cur.fetchone()
            if not user or not user["active"] or not verify_password(password, user["password_hash"]):
                return None
            cur.execute("UPDATE users SET last_login_at = NOW() WHERE id = %s", (user["id"],))
            conn.commit()
            return dict(user)
    finally:
        conn.close()


def bootstrap_users() -> None:
    """Seed exactly one admin account on first startup so nobody is locked out once the
    users table replaces the old env-var-only login. Uses ADMIN_USERNAME/ADMIN_PASSWORD
    (which already fall back to DASHBOARD_USERNAME/PASSWORD if unset)."""
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM users")
            if cur.fetchone()[0] > 0:
                return
            cur.execute(
                "INSERT INTO users (username, password_hash, role, created_by) VALUES (%s, %s, 'admin', 'bootstrap')",
                (ADMIN_USERNAME, hash_password(ADMIN_PASSWORD)),
            )
            conn.commit()
        print(f"Bootstrapped initial admin user '{ADMIN_USERNAME}' — change this password via the Admin Panel.")
    finally:
        conn.close()


def append_source_to_yaml(entry: dict) -> None:
    """Append one approved source to config/sources.yaml. Appends rather than
    rewriting the whole document so the existing schema-comment header and
    any other entries are never reformatted or lost."""
    with open(SOURCES_CONFIG, "r") as f:
        raw = f.read()
        data = yaml.safe_load(raw) or {"sources": []}

    existing_ids = {s.get("source_id") for s in data.get("sources", [])}
    if entry["source_id"] in existing_ids:
        raise ValueError(f"source_id '{entry['source_id']}' already exists in sources.yaml")

    block_lines = yaml.safe_dump(entry, default_flow_style=False, sort_keys=False).splitlines()
    indented = ["  - " + block_lines[0]] + ["    " + line for line in block_lines[1:]]

    with open(SOURCES_CONFIG, "a") as f:
        if not raw.endswith("\n"):
            f.write("\n")
        f.write("\n".join(indented) + "\n")


def update_source_status_in_yaml(source_id: str, new_status: str) -> None:
    """Surgically flip one source's status: line in place (IR-001 quarantine/retire/
    reactivate actions) without rewriting the whole document — every other entry,
    and the schema-comment header, are left byte-for-byte untouched."""
    with open(SOURCES_CONFIG, "r") as f:
        lines = f.readlines()

    block_start = re.compile(r"^\s*-\s*source_id:\s*" + re.escape(source_id) + r"\s*$")
    next_item = re.compile(r"^\s*-\s*source_id:")
    status_line = re.compile(r"^(\s*status:\s*)\S+(\s*)$")

    start = None
    end = len(lines)
    for i, line in enumerate(lines):
        if block_start.match(line):
            start = i
        elif start is not None and i > start and next_item.match(line):
            end = i
            break

    if start is None:
        raise ValueError(f"source_id '{source_id}' not found in sources.yaml")

    for i in range(start, end):
        m = status_line.match(lines[i])
        if m:
            newline = "\n" if lines[i].endswith("\n") else ""
            lines[i] = f"{m.group(1)}{new_status}{newline}"
            break
    else:
        raise ValueError(f"no status field found for source_id '{source_id}'")

    with open(SOURCES_CONFIG, "w") as f:
        f.writelines(lines)


def create_session(username: str) -> str:
    data = {"user": username, "iat": datetime.now(timezone.utc).isoformat()}
    return serializer.dumps(data)


def verify_session(session_token: str) -> Optional[str]:
    try:
        data = serializer.loads(session_token, max_age=SESSION_MAX_AGE)
        return data.get("user")
    except (BadSignature, SignatureExpired):
        return None


def get_current_user(request: Request) -> Optional[str]:
    session_token = request.cookies.get(COOKIE_NAME)
    if not session_token:
        return None
    return verify_session(session_token)


def login_required(request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=303, detail="Login required")
    return user


def create_admin_session(username: str) -> str:
    data = {"user": username, "iat": datetime.now(timezone.utc).isoformat()}
    return admin_serializer.dumps(data)


def verify_admin_session(session_token: str) -> Optional[str]:
    try:
        data = admin_serializer.loads(session_token, max_age=SESSION_MAX_AGE)
        return data.get("user")
    except (BadSignature, SignatureExpired):
        return None


def get_current_admin(request: Request) -> Optional[str]:
    session_token = request.cookies.get(ADMIN_COOKIE_NAME)
    if not session_token:
        return None
    return verify_admin_session(session_token)


def admin_login_required(request: Request):
    admin = get_current_admin(request)
    if not admin:
        raise HTTPException(status_code=303, detail="Admin login required")
    return admin


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    user = get_current_user(request)
    if user:
        return RedirectResponse(url="/", status_code=303)
    template = jinja_env.get_template("login.html")
    return HTMLResponse(content=template.render(request=request))


@app.post("/login")
async def login(form: LoginForm, response: Response):
    user = authenticate_user(form.username, form.password)
    if not user:
        audit_log("login_failed", {"username": form.username}, severity="WARNING")
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_session(user["username"])
    audit_log("login_success", {"username": user["username"], "role": user["role"]})

    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=SESSION_MAX_AGE,
        httponly=True,
        samesite="strict",
        secure=DASHBOARD_USE_HTTPS,
    )

    if DASHBOARD_USE_HTTPS:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["HX-Redirect"] = "/"
    return {"status": "ok"}


@app.get("/logout")
async def logout(request: Request):
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie(COOKIE_NAME)
    return response


def _home_esc(s) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# Category -> bar/badge colour, by severity tier (consistent with the rest of the UI).
_HOME_RED = {"terrorism_extremism", "human_trafficking", "weapons_trafficking"}
_HOME_AMBER = {"ransomware", "malware_sale", "credential_leak", "access_broker",
               "data_leak", "drug_trafficking"}


def _home_cat_hex(category: str) -> str:
    if category in _HOME_RED:
        return "#da3633"
    if category in _HOME_AMBER:
        return "#d29922"
    if category == "scam":
        return "#1f6feb"
    return "#6e7681"


def _scalar(cur, sql: str, default=0):
    """Run a COUNT/scalar query, returning `default` on any error (missing table,
    empty DB) so one absent feature can't blank the whole homepage."""
    try:
        cur.execute(sql)
        row = cur.fetchone()
        if not row:
            return default
        return list(row.values())[0] if isinstance(row, dict) else row[0]
    except Exception:
        cur.connection.rollback()
        return default


@app.get("/", response_class=HTMLResponse)
async def index(request: Request, user: str = Depends(login_required)):
    conn = get_db()
    open_findings = needs_review = findings_24h = total_findings = 0
    active_sources = degraded_count = actor_count = pages_crawled = total_classifications = 0
    last_activity = None
    by_category: list = []
    degraded_sources: list = []
    recent: list = []
    tg_messages = tg_actors = 0
    tg_top = None
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            open_findings = _scalar(cur, "SELECT COUNT(*) c FROM intelligence_findings WHERE NOT reviewed")
            needs_review = _scalar(cur, "SELECT COUNT(*) c FROM intelligence_findings WHERE requires_human_review AND NOT reviewed")
            findings_24h = _scalar(cur, "SELECT COUNT(*) c FROM intelligence_findings WHERE created_at > NOW() - INTERVAL '24 hours'")
            total_findings = _scalar(cur, "SELECT COUNT(*) c FROM intelligence_findings")
            active_sources = _scalar(cur, "SELECT COUNT(*) c FROM source_registry WHERE active = TRUE")
            degraded_count = _scalar(cur, "SELECT COUNT(*) c FROM source_reputation WHERE status = 'degraded'")
            actor_count = _scalar(cur, "SELECT COUNT(*) c FROM threat_actors")
            pages_crawled = _scalar(cur, "SELECT COUNT(*) c FROM raw_evidence")
            total_classifications = _scalar(cur, "SELECT COUNT(*) c FROM classifications")
            last_activity = _scalar(cur, "SELECT MAX(collected_at) m FROM raw_evidence", default=None)

            try:
                cur.execute("SELECT category, COUNT(*) c FROM intelligence_findings GROUP BY category ORDER BY c DESC")
                by_category = cur.fetchall()
            except Exception:
                conn.rollback()

            try:
                cur.execute("SELECT source_name, poisoning_incidents FROM source_reputation "
                            "WHERE status = 'degraded' ORDER BY poisoning_incidents DESC LIMIT 5")
                degraded_sources = cur.fetchall()
            except Exception:
                conn.rollback()

            try:
                cur.execute("SELECT finding_id, category, confidence_level, source, summary, "
                            "requires_human_review, reviewed, created_at "
                            "FROM intelligence_findings ORDER BY created_at DESC LIMIT 8")
                recent = cur.fetchall()
            except Exception:
                conn.rollback()

            tg_messages = _scalar(cur, "SELECT COUNT(*) c FROM telegram_messages")
            tg_actors = _scalar(cur, "SELECT COUNT(*) c FROM telegram_actors")
            if tg_messages:
                try:
                    cur.execute("SELECT handle, tg_user_id, orchestrator_likelihood, inferred_role "
                                "FROM telegram_actors WHERE orchestrator_likelihood IS NOT NULL "
                                "ORDER BY orchestrator_likelihood DESC LIMIT 1")
                    tg_top = cur.fetchone()
                except Exception:
                    conn.rollback()
    finally:
        conn.close()

    # ── stat cards (label, value, href, danger?) ──
    cards = [
        ("Open Findings", open_findings, "/findings?reviewed=false", False),
        ("Needs Review", needs_review, "/findings?reviewed=false", needs_review > 0),
        ("Findings (24h)", findings_24h, "/findings", False),
        ("Active Sources", active_sources, "/sources", False),
        ("Threat Actors", actor_count, "/actors", False),
        ("Pages Crawled", f"{pages_crawled:,}", "/crawled", False),
    ]
    cards_html = ""
    for label, value, href, danger in cards:
        stat_cls = "stat stat-danger" if danger else "stat"
        cards_html += (f'<a class="stat-card-link" href="{href}"><div class="card">'
                       f'<div class="stat-label">{label}</div>'
                       f'<div class="{stat_cls}">{value}</div></div></a>')

    # ── findings by category bars ──
    if by_category:
        maxc = max(int(r["c"]) for r in by_category) or 1
        bars = ""
        for r in by_category:
            cat, c = r["category"], int(r["c"])
            pct = max(4, round(c / maxc * 100))
            bars += (f'<a class="bar-row" href="/findings?category={cat}">'
                     f'<span class="bar-label">{_home_esc(cat)}</span>'
                     f'<span class="bar-track"><span class="bar-fill" style="width:{pct}%;background:{_home_cat_hex(cat)}"></span></span>'
                     f'<span class="bar-count">{c}</span></a>')
        category_panel = bars
    else:
        category_panel = '<p class="empty">No findings yet.</p>'

    # ── pipeline & source health panel ──
    last_str = last_activity.strftime("%Y-%m-%d %H:%M UTC") if last_activity else "—"
    degraded_html = ""
    if degraded_sources:
        rows = "".join(
            f'<div class="kv"><span class="k">{_home_esc(d["source_name"])}</span>'
            f'<span><span class="badge badge-warning">{d["poisoning_incidents"]} PI</span></span></div>'
            for d in degraded_sources
        )
        degraded_html = f'<div style="margin-top:1rem;"><div class="stat-label" style="margin-bottom:.4rem;">Degraded sources</div>{rows}</div>'
    pipeline_panel = (
        f'<div class="kv"><span class="k">Active sources</span><span>{active_sources}</span></div>'
        f'<div class="kv"><span class="k">Degraded sources</span><span class="{"stat-danger" if degraded_count else ""}">{degraded_count}</span></div>'
        f'<div class="kv"><span class="k">Pages crawled</span><span>{pages_crawled:,}</span></div>'
        f'<div class="kv"><span class="k">Classifications</span><span>{total_classifications:,}</span></div>'
        f'<div class="kv"><span class="k">Total findings</span><span>{total_findings:,}</span></div>'
        f'<div class="kv"><span class="k">Last crawl</span><span>{last_str}</span></div>'
        f'{degraded_html}'
    )

    # ── recent findings table ──
    if recent:
        rows = ""
        for f in recent:
            cat_badge = "badge-danger" if f["requires_human_review"] else "badge-info"
            lvl = f.get("confidence_level") or "—"
            lvl_badge = ("badge-success" if lvl == "VERIFIED" else
                         "badge-warning" if lvl == "HIGH" else "badge-secondary")
            when = f["created_at"].strftime("%m-%d %H:%M") if f.get("created_at") else "—"
            summ = _home_esc((f.get("summary") or "")[:80])
            rev = '<span class="badge badge-secondary">reviewed</span>' if f["reviewed"] else ''
            rows += (f'<tr onclick="location.href=\'/findings/{f["finding_id"]}\'" style="cursor:pointer;">'
                     f'<td><span class="badge {cat_badge}">{_home_esc(f["category"])}</span> {rev}</td>'
                     f'<td><span class="badge {lvl_badge}">{lvl}</span></td>'
                     f'<td>{_home_esc(f.get("source") or "—")}</td>'
                     f'<td>{summ}</td><td style="color:#8b949e;white-space:nowrap;">{when}</td></tr>')
        recent_panel = (
            '<table class="mini"><thead><tr><th>Category</th><th>Level</th>'
            '<th>Source</th><th>Summary</th><th>When</th></tr></thead>'
            f'<tbody>{rows}</tbody></table>'
        )
    else:
        recent_panel = '<p class="empty">No findings yet — the pipeline will populate this as it classifies crawled pages.</p>'

    # ── telegram intelligence panel (only if there is data) ──
    tg_panel = ""
    if tg_messages:
        top_html = "—"
        if tg_top:
            role = tg_top.get("inferred_role") or "actor"
            ol = tg_top.get("orchestrator_likelihood")
            ol_str = f"{ol:.2f}" if ol is not None else "—"
            handle = _home_esc(tg_top.get("handle") or f'user {tg_top.get("tg_user_id")}')
            top_html = (f'<a href="/network/actor/{tg_top.get("tg_user_id")}">{handle}</a> '
                        f'<span class="badge badge-danger">{_home_esc(role)}</span> '
                        f'<span class="bar-count">orch {ol_str}</span>')
        tg_panel = (
            '<div class="card"><h3>Telegram Intelligence</h3>'
            '<div class="home-2col">'
            f'<div><div class="kv"><span class="k">Messages collected</span><span>{tg_messages:,}</span></div>'
            f'<div class="kv"><span class="k">Actors mapped</span><span>{tg_actors:,}</span></div></div>'
            f'<div><div class="stat-label" style="margin-bottom:.4rem;">Top orchestrator</div>{top_html}'
            '<div style="margin-top:.6rem;"><a class="btn" href="/network">Open network view →</a></div></div>'
            '</div></div>'
        )

    page_style = """<style>
        .home-head { display:flex; align-items:baseline; justify-content:space-between; flex-wrap:wrap; gap:.5rem; margin-bottom:1.2rem; }
        .home-sub { color:#8b949e; font-size:.85rem; }
        .home-2col { display:grid; grid-template-columns:1fr 1fr; gap:1rem; }
        @media (max-width:820px) { .home-2col { grid-template-columns:1fr; } }
        .stat-danger { color:#f85149; }
        .card h3 { font-size:1rem; margin-bottom:1rem; }
        .stat-card-link { text-decoration:none; color:inherit; display:block; }
        a.stat-card-link:hover .card { border-color:#58a6ff; }
        .bar-row { display:grid; grid-template-columns:150px 1fr 44px; align-items:center; gap:.6rem; margin-bottom:.55rem; font-size:.85rem; text-decoration:none; }
        .bar-label { color:#c9d1d9; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
        .bar-track { background:#0d1117; border:1px solid #30363d; border-radius:.25rem; height:14px; overflow:hidden; }
        .bar-fill { display:block; height:100%; border-radius:.25rem; }
        .bar-count { text-align:right; color:#8b949e; }
        .kv { display:flex; justify-content:space-between; padding:.4rem 0; border-bottom:1px solid #21262d; font-size:.88rem; }
        .kv:last-child { border-bottom:none; }
        .kv .k { color:#8b949e; }
        table.mini td, table.mini th { padding:.5rem .6rem; font-size:.85rem; }
    </style>"""

    nav = base_html.replace("{user_display}", f'{_home_esc(user)} · <a href="/logout">Logout</a>') \
                   .replace("</head>", '<meta http-equiv="refresh" content="60"></head>')

    body = page_style + f"""
    <div class="container">
        <div class="home-head">
            <h1 style="margin-bottom:0;">Operations Overview</h1>
            <span class="home-sub">auto-refresh 60s · last crawl {last_str}</span>
        </div>
        <div class="grid">{cards_html}</div>
        <div class="home-2col">
            <div class="card"><h3>Threat findings by category</h3>{category_panel}</div>
            <div class="card"><h3>Pipeline &amp; sources</h3>{pipeline_panel}</div>
        </div>
        {tg_panel}
        <div class="card"><h3>Recent findings</h3>{recent_panel}</div>
    </div>
</body>
</html>"""
    return HTMLResponse(nav + body)


@app.get("/findings", response_class=HTMLResponse)
async def list_findings(
    request: Request,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    reviewed: Optional[bool] = None,
    category: Optional[str] = None,
    user: str = Depends(login_required),
):
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            where_clauses = []
            params = []

            if reviewed is not None:
                where_clauses.append("reviewed = %s")
                params.append(reviewed)

            if category:
                where_clauses.append("category = %s")
                params.append(category)

            where_sql = " AND ".join(where_clauses) if where_clauses else "TRUE"

            offset = (page - 1) * per_page
            cur.execute(
                f"SELECT * FROM intelligence_findings WHERE {where_sql} "
                f"ORDER BY created_at DESC LIMIT %s OFFSET %s",
                params + [per_page, offset],
            )
            findings = cur.fetchall()

            cur.execute(
                f"SELECT COUNT(*) as total FROM intelligence_findings WHERE {where_sql}",
                params,
            )
            total = cur.fetchone()["total"]
    finally:
        conn.close()

    return HTMLResponse(content=jinja_env.get_template("findings.html").render({
        "request": request,
        "findings": findings,
        "page": page,
        "per_page": per_page,
        "total": total,
        "total_pages": (total + per_page - 1) // per_page,
        "filter_reviewed": reviewed,
        "filter_category": category,
        "user": user,
    }))


@app.get("/findings/{finding_id}", response_class=HTMLResponse)
async def view_finding(request: Request, finding_id: str, user: str = Depends(login_required)):
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM intelligence_findings WHERE finding_id = %s",
                (finding_id,),
            )
            finding = cur.fetchone()
            if not finding:
                raise HTTPException(status_code=404, detail="Finding not found")

            record_id = finding["record_id"]
            cur.execute(
                "SELECT raw_text, url FROM raw_evidence WHERE record_id = %s",
                (record_id,),
            )
            raw = cur.fetchone()

            cur.execute(
                "SELECT category, confidence, entities, summary FROM classifications WHERE record_id = %s",
                (record_id,),
            )
            classification = cur.fetchone()
    finally:
        conn.close()

    return HTMLResponse(content=jinja_env.get_template("finding_detail.html").render({
        "request": request,
        "finding": finding,
        "raw_evidence": prepare_html_preview(raw["raw_text"]) if raw else "",
        "raw_url": raw["url"] if raw else "",
        "entities": classification["entities"] if classification and classification["entities"] else {},
        "user": user,
    }))


@app.post("/findings/{finding_id}/review")
async def review_finding(
    finding_id: str,
    action: ReviewAction,
    request: Request,
    user: str = Depends(login_required),
):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """UPDATE intelligence_findings
                   SET reviewed = TRUE,
                       reviewed_by = %s,
                       reviewed_at = NOW()
                   WHERE finding_id = %s""",
                (user, finding_id),
            )
            conn.commit()

        audit_log("finding_reviewed", {
            "finding_id": finding_id,
            "reviewer": user,
            "action": action.action,
        })
    finally:
        conn.close()

    return {"status": "ok", "finding_id": finding_id, "action": action.action}


@app.get("/crawled", response_class=HTMLResponse)
async def list_crawled(
    request: Request,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    category: Optional[str] = None,
    source: Optional[str] = None,
    user: str = Depends(login_required),
):
    """Every crawled page (raw_evidence) with its AI classification joined in.

    LEFT JOIN so pages that classified as 'unknown' — or have not been
    classified yet — still appear. This is the full crawl ledger, not the
    high-risk subset that gets promoted into intelligence_findings.
    """
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            where_clauses = []
            params: list = []

            if category == "unclassified":
                where_clauses.append("c.category IS NULL")
            elif category:
                where_clauses.append("c.category = %s")
                params.append(category)

            if source:
                where_clauses.append("r.source = %s")
                params.append(source)

            where_sql = " AND ".join(where_clauses) if where_clauses else "TRUE"

            offset = (page - 1) * per_page
            cur.execute(
                f"""SELECT r.record_id, r.source, r.url, r.size_bytes, r.collected_at,
                           c.category, c.confidence, c.summary
                    FROM raw_evidence r
                    LEFT JOIN LATERAL (
                        SELECT category, confidence, summary
                        FROM classifications
                        WHERE record_id = r.record_id
                        ORDER BY created_at DESC
                        LIMIT 1
                    ) c ON TRUE
                    WHERE {where_sql}
                    ORDER BY r.collected_at DESC
                    LIMIT %s OFFSET %s""",
                params + [per_page, offset],
            )
            pages = cur.fetchall()

            cur.execute(
                f"""SELECT COUNT(*) as total
                    FROM raw_evidence r
                    LEFT JOIN LATERAL (
                        SELECT category FROM classifications
                        WHERE record_id = r.record_id
                        ORDER BY created_at DESC LIMIT 1
                    ) c ON TRUE
                    WHERE {where_sql}""",
                params,
            )
            total = cur.fetchone()["total"]

            cur.execute("SELECT DISTINCT source FROM raw_evidence ORDER BY source")
            sources = [row["source"] for row in cur.fetchall()]
    finally:
        conn.close()

    return HTMLResponse(content=jinja_env.get_template("crawled.html").render({
        "request": request,
        "pages": pages,
        "page": page,
        "per_page": per_page,
        "total": total,
        "total_pages": (total + per_page - 1) // per_page,
        "filter_category": category,
        "filter_source": source,
        "sources": sources,
        "user": user,
    }))


@app.get("/crawled/{record_id}", response_class=HTMLResponse)
async def view_crawled(request: Request, record_id: str, user: str = Depends(login_required)):
    """Full detail for any single crawled page, classified or not."""
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT record_id, sha256, source, url, raw_text, size_bytes, collected_at "
                "FROM raw_evidence WHERE record_id = %s",
                (record_id,),
            )
            page = cur.fetchone()
            if not page:
                raise HTTPException(status_code=404, detail="Crawled page not found")

            cur.execute(
                "SELECT category, confidence, entities, summary, created_at "
                "FROM classifications WHERE record_id = %s "
                "ORDER BY created_at DESC LIMIT 1",
                (record_id,),
            )
            classification = cur.fetchone()

            cur.execute(
                "SELECT title, author, entities, timestamp_posted "
                "FROM analysis_results WHERE record_id = %s "
                "ORDER BY created_at DESC LIMIT 1",
                (record_id,),
            )
            analysis = cur.fetchone()

            # Was this page promoted into a high-risk finding?
            cur.execute(
                "SELECT finding_id FROM intelligence_findings WHERE record_id = %s "
                "ORDER BY created_at DESC LIMIT 1",
                (record_id,),
            )
            finding = cur.fetchone()
    finally:
        conn.close()

    # Prefer classification entities; fall back to the analysis extraction.
    entities = {}
    if classification and classification.get("entities"):
        entities = classification["entities"]
    elif analysis and analysis.get("entities"):
        entities = analysis["entities"]

    return HTMLResponse(content=jinja_env.get_template("crawled_detail.html").render({
        "request": request,
        "page": page,
        "classification": classification,
        "analysis": analysis,
        "finding_id": finding["finding_id"] if finding else None,
        "entities": entities,
        "raw_evidence": prepare_html_preview(page["raw_text"]) if page.get("raw_text") else "",
        "user": user,
    }))


@app.get("/search", response_class=HTMLResponse)
async def search(
    request: Request,
    q: str = Query(""),
    page: int = Query(1, ge=1),
    user: str = Depends(login_required),
):
    results = []
    total = 0

    if q.strip():
        es = get_opensearch()
        try:
            resp = es.search(
                index="dwitp-classifications",
                body={
                    "query": {
                        "multi_match": {
                            "query": q,
                            "fields": ["summary", "category", "entities.*"],
                            # entities.* is dynamically mapped, so some sub-fields
                            # may be boolean/numeric; lenient skips those instead of
                            # failing the whole query with a 400 type-parse error.
                            "lenient": True,
                        }
                    },
                    "from": (page - 1) * 20,
                    "size": 20,
                },
            )
            results = [hit["_source"] for hit in resp["hits"]["hits"]]
            total = resp["hits"]["total"]["value"]
            record_ids = [r.get("record_id") for r in results if r.get("record_id")]
            if record_ids:
                conn = get_db()
                try:
                    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                        placeholders = ",".join("%s" for _ in record_ids)
                        cur.execute(
                            f"SELECT record_id, finding_id FROM intelligence_findings WHERE record_id IN ({placeholders})",
                            record_ids,
                        )
                        id_map = {row["record_id"]: row["finding_id"] for row in cur.fetchall()}
                        for r in results:
                            rid = r.get("record_id")
                            if rid and rid in id_map:
                                r["finding_id"] = id_map[rid]
                finally:
                    conn.close()
        except Exception:
            pass
    else:
        conn = get_db()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT f.finding_id, f.category, f.summary, f.confidence, f.created_at, "
                    "r.url, r.source "
                    "FROM intelligence_findings f "
                    "JOIN raw_evidence r ON f.record_id = r.record_id "
                    "ORDER BY f.created_at DESC LIMIT 20"
                )
                results = [dict(row) for row in cur.fetchall()]
                total = len(results)
        finally:
            conn.close()

    return HTMLResponse(content=jinja_env.get_template("search.html").render({
        "request": request,
        "query": q,
        "results": results,
        "total": total,
        "page": page,
        "user": user,
    }))


@app.get("/sources", response_class=HTMLResponse)
async def list_sources(request: Request, user: str = Depends(login_required)):
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT sr.*, s.status, s.reliability_score, s.risk_score "
                "FROM source_registry sr "
                "LEFT JOIN source_reputation s ON sr.name = s.source_name "
                "ORDER BY sr.name"
            )
            sources = cur.fetchall()

            cur.execute(
                "SELECT * FROM pending_sources WHERE status = 'pending_review' ORDER BY proposed_at DESC"
            )
            pending = cur.fetchall()
    finally:
        conn.close()

    return HTMLResponse(content=jinja_env.get_template("sources.html").render({
        "request": request,
        "sources": sources,
        "pending": pending,
        "user": user,
    }))


@app.post("/sources/propose")
async def propose_source(
    proposal: SourceProposal,
    user: str = Depends(login_required),
):
    if ".onion" not in proposal.url.lower():
        raise HTTPException(status_code=400, detail="Only .onion URLs are accepted")
    try:
        validate_url(proposal.url, allow_onion=True)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO pending_sources
                   (source_id, url, category, risk_level, review_notes,
                    max_pages, link_selector, queue_wait_seconds, proposed_by)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (
                    proposal.source_id,
                    proposal.url,
                    proposal.category,
                    proposal.risk_level,
                    proposal.review_notes,
                    proposal.max_pages,
                    proposal.link_selector,
                    proposal.queue_wait_seconds,
                    user,
                ),
            )
            conn.commit()
    finally:
        conn.close()

    audit_log("source_proposed", {"source_id": proposal.source_id, "url": proposal.url, "proposed_by": user})
    return {"status": "ok"}


@app.get("/actors", response_class=HTMLResponse)
async def list_actors(request: Request, user: str = Depends(login_required)):
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM threat_actors ORDER BY last_seen DESC NULLS LAST")
            actors = cur.fetchall()

            if not actors:
                cur.execute(
                    "SELECT DISTINCT split_part(r.url, '/u/', 2) AS actor_name, "
                    "COUNT(*) as mentions, MAX(r.collected_at) as last_seen "
                    "FROM raw_evidence r "
                    "WHERE r.url LIKE '%/u/%' "
                    "GROUP BY split_part(r.url, '/u/', 2) "
                    "ORDER BY mentions DESC LIMIT 50"
                )
                actors = [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()

    return HTMLResponse(content=jinja_env.get_template("actors.html").render({
        "request": request,
        "actors": actors,
        "user": user,
    }))


# ─── Admin Panel ─────────────────────────────────────────────────

@app.get("/admin/login", response_class=HTMLResponse)
async def admin_login_page(request: Request):
    admin = get_current_admin(request)
    if admin:
        return RedirectResponse(url="/admin", status_code=303)
    template = jinja_env.get_template("admin_login.html")
    return HTMLResponse(content=template.render(request=request))


@app.post("/admin/login")
async def admin_login(form: LoginForm, response: Response):
    user = authenticate_user(form.username, form.password)
    if not user or user["role"] != "admin":
        audit_log("admin_login_failed", {"username": form.username}, severity="WARNING")
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_admin_session(user["username"])
    audit_log("admin_login_success", {"username": user["username"]})

    response.set_cookie(
        key=ADMIN_COOKIE_NAME,
        value=token,
        max_age=SESSION_MAX_AGE,
        httponly=True,
        samesite="strict",
        secure=DASHBOARD_USE_HTTPS,
    )
    response.headers["HX-Redirect"] = "/admin"
    return {"status": "ok"}


@app.get("/admin/logout")
async def admin_logout():
    response = RedirectResponse(url="/admin/login", status_code=303)
    response.delete_cookie(ADMIN_COOKIE_NAME)
    return response


@app.get("/admin", response_class=HTMLResponse)
async def admin_panel(request: Request, admin: str = Depends(admin_login_required)):
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM pending_sources ORDER BY "
                "(status = 'pending_review') DESC, proposed_at DESC LIMIT 100"
            )
            pending_sources = cur.fetchall()

            cur.execute(
                "SELECT * FROM candidate_sources WHERE status = 'pending_review' "
                "ORDER BY discovered_at DESC LIMIT 100"
            )
            candidates = cur.fetchall()
    finally:
        conn.close()

    return HTMLResponse(content=jinja_env.get_template("admin_panel.html").render({
        "request": request,
        "pending_sources": pending_sources,
        "candidates": candidates,
        "admin": admin,
    }))


@app.post("/admin/candidates/{candidate_id}/promote")
async def admin_promote_candidate(
    candidate_id: str,
    req: PromoteCandidateRequest,
    admin: str = Depends(admin_login_required),
):
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM candidate_sources WHERE id = %s", (candidate_id,))
            candidate = cur.fetchone()
            if not candidate:
                raise HTTPException(status_code=404, detail="Candidate not found")
            if candidate["status"] != "pending_review":
                raise HTTPException(status_code=400, detail=f"Already {candidate['status']}")

            cur.execute(
                """INSERT INTO pending_sources
                   (source_id, url, category, risk_level, review_notes,
                    max_pages, link_selector, queue_wait_seconds, proposed_by)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (
                    req.source_id,
                    candidate["url"],
                    req.category,
                    req.risk_level,
                    req.review_notes or f"Promoted from discovered candidate (found via {candidate['discovered_from']})",
                    req.max_pages,
                    req.link_selector,
                    req.queue_wait_seconds,
                    admin,
                ),
            )
            cur.execute(
                """UPDATE candidate_sources
                   SET status = 'approved', reviewed_by = %s, reviewed_at = NOW()
                   WHERE id = %s""",
                (admin, candidate_id),
            )
            conn.commit()
    finally:
        conn.close()

    audit_log("candidate_promoted", {
        "candidate_id": candidate_id, "url": candidate["url"], "source_id": req.source_id, "promoted_by": admin,
    })
    return {"status": "ok"}


@app.post("/admin/candidates/{candidate_id}/reject")
async def admin_reject_candidate(
    candidate_id: str,
    action: RejectAction,
    admin: str = Depends(admin_login_required),
):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """UPDATE candidate_sources
                   SET status = 'rejected', reviewed_by = %s, reviewed_at = NOW(), rejection_reason = %s
                   WHERE id = %s AND status = 'pending_review'""",
                (admin, action.reason, candidate_id),
            )
            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail="Candidate not found or already reviewed")
            conn.commit()
    finally:
        conn.close()

    audit_log("candidate_rejected", {"candidate_id": candidate_id, "rejected_by": admin, "reason": action.reason})
    return {"status": "ok"}


@app.post("/admin/sources/{pending_id}/approve")
async def admin_approve_source(pending_id: str, admin: str = Depends(admin_login_required)):
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM pending_sources WHERE id = %s", (pending_id,))
            proposal = cur.fetchone()
            if not proposal:
                raise HTTPException(status_code=404, detail="Proposal not found")
            if proposal["status"] != "pending_review":
                raise HTTPException(status_code=400, detail=f"Already {proposal['status']}")

            today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            entry = {
                "source_id": proposal["source_id"],
                "url": proposal["url"],
                "category": proposal["category"],
                "status": "approved",
                "approved_by": admin,
                "approved_date": today,
                "approval_signature": "dashboard-admin-signoff",
                "review_notes": proposal["review_notes"] or "",
                "risk_level": proposal["risk_level"],
                "last_reviewed": today,
                "max_pages": proposal["max_pages"],
                "link_selector": proposal["link_selector"] or "",
                "queue_wait_seconds": proposal["queue_wait_seconds"],
            }

            try:
                CrawlTarget(**entry)
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"Invalid source entry: {e}")

            try:
                append_source_to_yaml(entry)
            except ValueError as e:
                raise HTTPException(status_code=409, detail=str(e))

            cur.execute(
                """INSERT INTO source_registry (name, url, category, approved_by, approved_date, active)
                   VALUES (%s, %s, %s, %s, %s, TRUE)
                   ON CONFLICT (name) DO NOTHING""",
                (entry["source_id"], entry["url"], entry["category"], admin, today),
            )

            cur.execute(
                """UPDATE pending_sources
                   SET status = 'approved', reviewed_by = %s, reviewed_at = NOW()
                   WHERE id = %s""",
                (admin, pending_id),
            )
            conn.commit()
    finally:
        conn.close()

    audit_log("source_approved", {"pending_id": pending_id, "source_id": entry["source_id"], "approved_by": admin},
              severity="WARNING")
    return {"status": "ok"}


@app.post("/admin/sources/{pending_id}/reject")
async def admin_reject_source(
    pending_id: str,
    action: RejectAction,
    admin: str = Depends(admin_login_required),
):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """UPDATE pending_sources
                   SET status = 'rejected', reviewed_by = %s, reviewed_at = NOW(), rejection_reason = %s
                   WHERE id = %s AND status = 'pending_review'""",
                (admin, action.reason, pending_id),
            )
            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail="Proposal not found or already reviewed")
            conn.commit()
    finally:
        conn.close()

    audit_log("source_rejected", {"pending_id": pending_id, "rejected_by": admin, "reason": action.reason})
    return {"status": "ok"}


# ─── Admin Panel — Source Lifecycle & Incident Response (IR-001) ─
# Maps directly to IR-001 playbook actions: "Prompt Injection Campaign" ->
# quarantine source + disable AI; "Data Poisoning Event" -> freeze source +
# require analyst review + recalculate confidence (reset reputation here).

_REPUTATION_STATUS_MAP = {"approved": "active", "pending": "active", "retired": "retired", "quarantined": "quarantined"}


@app.get("/admin/registry", response_class=HTMLResponse)
async def admin_registry(request: Request, admin: str = Depends(admin_login_required)):
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT sr.*, s.status AS reputation_status, s.reliability_score, s.risk_score, "
                "s.poisoning_incidents "
                "FROM source_registry sr "
                "LEFT JOIN source_reputation s ON sr.name = s.source_name "
                "ORDER BY sr.name"
            )
            sources = cur.fetchall()
    finally:
        conn.close()

    return HTMLResponse(content=jinja_env.get_template("admin_registry.html").render({
        "request": request,
        "sources": sources,
        "admin": admin,
    }))


@app.post("/admin/registry/{name}/status")
async def admin_change_source_status(name: str, req: SourceStatusChange, admin: str = Depends(admin_login_required)):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            try:
                update_source_status_in_yaml(name, req.status)
            except ValueError as e:
                raise HTTPException(status_code=404, detail=str(e))

            cur.execute("UPDATE source_registry SET active = %s WHERE name = %s", (req.status == "approved", name))
            cur.execute(
                """INSERT INTO source_reputation (source_name, status)
                   VALUES (%s, %s)
                   ON CONFLICT (source_name) DO UPDATE SET status = EXCLUDED.status, updated_at = NOW()""",
                (name, _REPUTATION_STATUS_MAP[req.status]),
            )
            conn.commit()
    finally:
        conn.close()

    audit_log("source_status_changed", {"source": name, "new_status": req.status, "changed_by": admin},
              severity="WARNING" if req.status in ("quarantined", "retired") else "INFO")
    return {"status": "ok"}


@app.post("/admin/registry/{name}/reset_reputation")
async def admin_reset_reputation(name: str, admin: str = Depends(admin_login_required)):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO source_reputation (source_name, poisoning_incidents, status)
                   VALUES (%s, 0, 'active')
                   ON CONFLICT (source_name) DO UPDATE SET
                       poisoning_incidents = 0, status = 'active', updated_at = NOW()""",
                (name,),
            )
            conn.commit()
    finally:
        conn.close()

    audit_log("source_reputation_reset", {"source": name, "reset_by": admin}, severity="WARNING")
    return {"status": "ok"}


@app.post("/admin/ai/disable")
async def admin_disable_ai(admin: str = Depends(admin_login_required)):
    client = QueueClient()
    try:
        client.publish_to_exchange("control.ai", {"action": "disable", "by": admin})
    finally:
        client.close()

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO system_settings (key, value, updated_by)
                   VALUES ('ai_processing_enabled', 'false', %s)
                   ON CONFLICT (key) DO UPDATE SET value = 'false', updated_by = %s, updated_at = NOW()""",
                (admin, admin),
            )
            conn.commit()
    finally:
        conn.close()

    audit_log("ai_disable_requested", {"requested_by": admin}, severity="CRITICAL")
    return {"status": "ok"}


@app.post("/admin/ai/enable")
async def admin_enable_ai(admin: str = Depends(admin_login_required)):
    client = QueueClient()
    try:
        client.publish_to_exchange("control.ai", {"action": "enable", "by": admin})
    finally:
        client.close()

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO system_settings (key, value, updated_by)
                   VALUES ('ai_processing_enabled', 'true', %s)
                   ON CONFLICT (key) DO UPDATE SET value = 'true', updated_by = %s, updated_at = NOW()""",
                (admin, admin),
            )
            conn.commit()
    finally:
        conn.close()

    audit_log("ai_enable_requested", {"requested_by": admin})
    return {"status": "ok"}


# ─── Admin Panel — Audit Log Viewer ─────────────────────────────
# NOTE: this only shows events logged by the dashboard process itself (logins,
# source proposals/approvals/rejections, user management). Each pipeline service
# (crawler/sanitizer/ai_layer/db_writer) writes its own audit.log inside its own
# container on tmpfs — there is no shared volume aggregating them, so their events
# are not visible here. See those containers' logs directly for crawl/classification
# audit events (prompt_injection_detected, source_degraded_poisoning, etc).

def read_audit_log(limit: int = 300) -> list[dict]:
    if not os.path.isfile(AUDIT_LOG_PATH):
        return []
    with open(AUDIT_LOG_PATH, "r", encoding="utf-8") as f:
        lines = f.readlines()
    entries = []
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(decrypt_log_entry(line))
        except Exception:
            continue
        if len(entries) >= limit:
            break
    return entries


@app.get("/admin/audit", response_class=HTMLResponse)
async def admin_audit_log(request: Request, admin: str = Depends(admin_login_required)):
    entries = read_audit_log(limit=300)
    return HTMLResponse(content=jinja_env.get_template("admin_audit.html").render({
        "request": request,
        "entries": entries,
        "admin": admin,
    }))


# ─── Admin Panel — User Management ──────────────────────────────

@app.get("/admin/users", response_class=HTMLResponse)
async def admin_list_users(request: Request, admin: str = Depends(admin_login_required)):
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM users ORDER BY created_at")
            users = cur.fetchall()
    finally:
        conn.close()

    return HTMLResponse(content=jinja_env.get_template("admin_users.html").render({
        "request": request,
        "users": users,
        "admin": admin,
    }))


@app.post("/admin/users")
async def admin_create_user(req: CreateUserRequest, admin: str = Depends(admin_login_required)):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM users WHERE username = %s", (req.username,))
            if cur.fetchone():
                raise HTTPException(status_code=409, detail="Username already exists")
            cur.execute(
                "INSERT INTO users (username, password_hash, role, created_by) VALUES (%s, %s, %s, %s)",
                (req.username, hash_password(req.password), req.role, admin),
            )
            conn.commit()
    finally:
        conn.close()

    audit_log("user_created", {"username": req.username, "role": req.role, "created_by": admin}, severity="WARNING")
    return {"status": "ok"}


@app.post("/admin/users/{user_id}/deactivate")
async def admin_deactivate_user(user_id: str, admin: str = Depends(admin_login_required)):
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT username FROM users WHERE id = %s", (user_id,))
            target = cur.fetchone()
            if not target:
                raise HTTPException(status_code=404, detail="User not found")
            if target["username"] == admin:
                raise HTTPException(status_code=400, detail="Cannot deactivate your own account")
            cur.execute("UPDATE users SET active = FALSE WHERE id = %s", (user_id,))
            conn.commit()
    finally:
        conn.close()

    audit_log("user_deactivated", {"username": target["username"], "deactivated_by": admin}, severity="WARNING")
    return {"status": "ok"}


@app.post("/admin/users/{user_id}/reactivate")
async def admin_reactivate_user(user_id: str, admin: str = Depends(admin_login_required)):
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT username FROM users WHERE id = %s", (user_id,))
            target = cur.fetchone()
            if not target:
                raise HTTPException(status_code=404, detail="User not found")
            cur.execute("UPDATE users SET active = TRUE WHERE id = %s", (user_id,))
            conn.commit()
    finally:
        conn.close()

    audit_log("user_reactivated", {"username": target["username"], "reactivated_by": admin})
    return {"status": "ok"}


@app.post("/admin/users/{user_id}/role")
async def admin_change_role(user_id: str, req: ChangeRoleRequest, admin: str = Depends(admin_login_required)):
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT username, role FROM users WHERE id = %s", (user_id,))
            target = cur.fetchone()
            if not target:
                raise HTTPException(status_code=404, detail="User not found")
            if target["username"] == admin and req.role != "admin":
                raise HTTPException(status_code=400, detail="Cannot demote your own account")
            cur.execute("UPDATE users SET role = %s WHERE id = %s", (req.role, user_id))
            conn.commit()
    finally:
        conn.close()

    audit_log("user_role_changed", {
        "username": target["username"], "old_role": target["role"], "new_role": req.role, "changed_by": admin,
    }, severity="WARNING")
    return {"status": "ok"}


@app.post("/admin/users/{user_id}/reset_password")
async def admin_reset_password(user_id: str, req: ResetPasswordRequest, admin: str = Depends(admin_login_required)):
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT username FROM users WHERE id = %s", (user_id,))
            target = cur.fetchone()
            if not target:
                raise HTTPException(status_code=404, detail="User not found")
            cur.execute("UPDATE users SET password_hash = %s WHERE id = %s", (hash_password(req.password), user_id))
            conn.commit()
    finally:
        conn.close()

    audit_log("user_password_reset", {"username": target["username"], "reset_by": admin}, severity="WARNING")
    return {"status": "ok"}


@app.get("/health")
async def health():
    db_ok = False
    try:
        conn = get_db()
        conn.close()
        db_ok = True
    except Exception:
        pass

    return {
        "status": "ok" if db_ok else "degraded",
        "database": db_ok,
    }


# -- Template definitions (embedded to keep deployment single-file) --

base_html = """<!DOCTYPE html>
<html>
<head>
    <title>DWITP Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; }
        nav { background: #161b22; padding: 1rem 2rem; border-bottom: 1px solid #30363d; display: flex; gap: 1.5rem; align-items: center; }
        nav a { color: #58a6ff; text-decoration: none; font-size: 0.9rem; }
        nav a:hover { text-decoration: underline; }
        nav .brand { color: #f0f6fc; font-weight: 600; font-size: 1.1rem; }
        nav .user-info { margin-left: auto; color: #8b949e; font-size: 0.85rem; }
        nav .user-info a { margin-left: 0.5rem; }
        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
        h1, h2, h3 { color: #f0f6fc; margin-bottom: 1rem; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 1rem; }
        th, td { padding: 0.75rem; text-align: left; border-bottom: 1px solid #30363d; }
        th { color: #8b949e; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; }
        tr:hover { background: #161b22; }
        .badge { display: inline-block; padding: 0.2rem 0.5rem; border-radius: 0.25rem; font-size: 0.75rem; font-weight: 600; }
        .badge-danger { background: #da3633; color: #fff; }
        .badge-warning { background: #d29922; color: #fff; }
        .badge-info { background: #1f6feb; color: #fff; }
        .badge-success { background: #238636; color: #fff; }
        .badge-secondary { background: #30363d; color: #c9d1d9; }
        .btn { display: inline-block; padding: 0.5rem 1rem; border-radius: 0.25rem; border: 1px solid #30363d; background: #21262d; color: #c9d1d9; cursor: pointer; text-decoration: none; font-size: 0.85rem; }
        .btn:hover { background: #30363d; }
        .btn-primary { background: #238636; border-color: #2ea043; }
        .btn-primary:hover { background: #2ea043; }
        .btn-danger { background: #da3633; border-color: #f85149; }
        .btn-danger:hover { background: #f85149; }
        input, select { padding: 0.5rem; border-radius: 0.25rem; border: 1px solid #30363d; background: #0d1117; color: #c9d1d9; font-size: 0.9rem; }
        .pagination { display: flex; gap: 0.5rem; align-items: center; margin: 1rem 0; }
        .pagination a { color: #58a6ff; }
        .card { background: #161b22; border: 1px solid #30363d; border-radius: 0.5rem; padding: 1.5rem; margin-bottom: 1rem; }
        .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 1rem; }
        .stat { font-size: 2rem; font-weight: 700; color: #f0f6fc; }
        .stat-label { font-size: 0.85rem; color: #8b949e; }
        form { display: flex; gap: 0.5rem; margin-bottom: 1rem; flex-wrap: wrap; }
        .empty { color: #8b949e; text-align: center; padding: 3rem; }
        .login-container { max-width: 400px; margin: 4rem auto; padding: 2rem; background: #161b22; border: 1px solid #30363d; border-radius: 0.5rem; }
        .login-container h1 { text-align: center; margin-bottom: 2rem; }
        .login-container form { flex-direction: column; }
        .login-container input { width: 100%; }
        .login-container .error { color: #f85149; text-align: center; margin-bottom: 1rem; }
    </style>
</head>
<body>
    <nav>
        <span class="brand">DWITP</span>
        <a href="/">Home</a>
        <a href="/findings">Findings</a>
        <a href="/crawled">Crawled Pages</a>
        <a href="/search">Search</a>
        <a href="/sources">Sources</a>
        <a href="/actors">Actors</a>
        <a href="/network">Network</a>
        <span class="user-info">{user_display}</span>
    </nav>
"""

admin_base_html = base_html.replace(
    '<span class="brand">DWITP</span>',
    '<span class="brand" style="color:#d29922;">DWITP — Admin Panel</span>',
).replace(
    '<a href="/">Home</a>\n        <a href="/findings">Findings</a>\n        '
    '<a href="/crawled">Crawled Pages</a>\n        '
    '<a href="/search">Search</a>\n        <a href="/sources">Sources</a>\n        '
    '<a href="/actors">Actors</a>',
    '<a href="/admin">Sign-off Queue</a>\n        <a href="/admin/registry">Source Registry</a>\n        '
    '<a href="/admin/users">Users</a>\n        '
    '<a href="/admin/audit">Audit Log</a>\n        <a href="/sources">Back to Dashboard</a>',
).replace("{user_display}", '<a href="/admin/logout">Logout</a>')


def create_template_files() -> None:
    login_html = """<!DOCTYPE html>
<html>
<head>
    <title>DWITP Dashboard — Login</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .login-container { max-width: 400px; width: 100%; padding: 2rem; background: #161b22; border: 1px solid #30363d; border-radius: 0.5rem; }
        .login-container h1 { text-align: center; margin-bottom: 2rem; color: #f0f6fc; }
        .login-container form { display: flex; flex-direction: column; gap: 1rem; }
        .login-container label { color: #8b949e; font-size: 0.85rem; }
        .login-container input { padding: 0.75rem; border-radius: 0.25rem; border: 1px solid #30363d; background: #0d1117; color: #c9d1d9; font-size: 0.9rem; width: 100%; }
        .login-container .btn { padding: 0.75rem; background: #238636; border: 1px solid #2ea043; color: #fff; border-radius: 0.25rem; cursor: pointer; font-size: 0.9rem; text-align: center; }
        .login-container .btn:hover { background: #2ea043; }
        .login-container .error { color: #f85149; text-align: center; margin-bottom: 1rem; display: none; }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>DWITP Dashboard</h1>
        <div class="error" id="error"></div>
        <form id="loginForm">
            <label for="username">Username</label>
            <input type="text" id="username" name="username" required autocomplete="username">
            <label for="password">Password</label>
            <input type="password" id="password" name="password" required autocomplete="current-password">
            <button type="submit" class="btn">Sign In</button>
        </form>
    </div>
    <script>
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const errorEl = document.getElementById('error');
            try {
                const resp = await fetch('/login', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({username, password}),
                });
                if (resp.ok) {
                    window.location.href = '/';
                } else {
                    const data = await resp.json();
                    errorEl.textContent = data.detail || 'Invalid credentials';
                    errorEl.style.display = 'block';
                }
            } catch (err) {
                errorEl.textContent = 'Connection error';
                errorEl.style.display = 'block';
            }
        });
    </script>
</body>
</html>"""

    with open(os.path.join(templates_dir, "login.html"), "w", encoding="utf-8") as f:
        f.write(login_html)

    admin_login_html = """<!DOCTYPE html>
<html>
<head>
    <title>DWITP Admin Panel — Sign In</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .login-container { max-width: 400px; width: 100%; padding: 2rem; background: #161b22; border: 1px solid #d29922; border-radius: 0.5rem; }
        .login-container h1 { text-align: center; margin-bottom: 0.5rem; color: #f0f6fc; }
        .login-container p.subtitle { text-align: center; margin-bottom: 2rem; color: #d29922; font-size: 0.85rem; }
        .login-container form { display: flex; flex-direction: column; gap: 1rem; }
        .login-container label { color: #8b949e; font-size: 0.85rem; }
        .login-container input { padding: 0.75rem; border-radius: 0.25rem; border: 1px solid #30363d; background: #0d1117; color: #c9d1d9; font-size: 0.9rem; width: 100%; }
        .login-container .btn { padding: 0.75rem; background: #d29922; border: 1px solid #d29922; color: #0d1117; border-radius: 0.25rem; cursor: pointer; font-size: 0.9rem; text-align: center; font-weight: 600; }
        .login-container .btn:hover { background: #e3b341; }
        .login-container .error { color: #f85149; text-align: center; margin-bottom: 1rem; display: none; }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>Admin Panel</h1>
        <p class="subtitle">Sign-off authority — separate from analyst login</p>
        <div class="error" id="error"></div>
        <form id="loginForm">
            <label for="username">Username</label>
            <input type="text" id="username" name="username" required autocomplete="username">
            <label for="password">Password</label>
            <input type="password" id="password" name="password" required autocomplete="current-password">
            <button type="submit" class="btn">Sign In</button>
        </form>
    </div>
    <script>
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const errorEl = document.getElementById('error');
            try {
                const resp = await fetch('/admin/login', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({username, password}),
                });
                if (resp.ok) {
                    window.location.href = '/admin';
                } else {
                    const data = await resp.json();
                    errorEl.textContent = data.detail || 'Invalid credentials';
                    errorEl.style.display = 'block';
                }
            } catch (err) {
                errorEl.textContent = 'Connection error';
                errorEl.style.display = 'block';
            }
        });
    </script>
</body>
</html>"""

    with open(os.path.join(templates_dir, "admin_login.html"), "w", encoding="utf-8") as f:
        f.write(admin_login_html)

    footer = '\n    </div>\n</body>\n</html>'

    template_content = {
        "findings.html": base_html.replace("{user_display}", '<a href="/logout">Logout</a>') + """
    <div class="container">
    <h1>Intelligence Findings</h1>
    <form method="get" action="/findings">
        <select name="reviewed">
            <option value="">All Status</option>
            <option value="false" {% if filter_reviewed == false %}selected{% endif %}>Unreviewed</option>
            <option value="true" {% if filter_reviewed == true %}selected{% endif %}>Reviewed</option>
        </select>
        <select name="category">
            <option value="">All Categories</option>
            {% for cat in ['ransomware', 'malware_sale', 'credential_leak', 'access_broker', 'data_leak', 'scam', 'unknown'] %}
                <option value="{{ cat }}" {% if filter_category == cat %}selected{% endif %}>{{ cat }}</option>
            {% endfor %}
        </select>
        <button type="submit" class="btn">Filter</button>
    </form>

    {% if findings %}
    <table>
        <thead>
            <tr>
                <th>Finding ID</th>
                <th>Category</th>
                <th>Confidence</th>
                <th>Source</th>
                <th>Requires Review</th>
                <th>Reviewed</th>
                <th>Created</th>
                <th></th>
            </tr>
        </thead>
        <tbody>
            {% for f in findings %}
            <tr>
                <td><a href="/findings/{{ f.finding_id }}">{{ f.finding_id[:8] }}...</a></td>
                <td><span class="badge badge-{{ 'danger' if f.requires_human_review else 'info' }}">{{ f.category }}</span></td>
                <td>{{ "%.2f"|format(f.confidence) }}</td>
                <td>{{ f.source[:20] }}</td>
                <td>{{ 'Yes' if f.requires_human_review else 'No' }}</td>
                <td>{{ 'Yes' if f.reviewed else 'No' }}</td>
                <td>{{ f.created_at.strftime('%Y-%m-%d %H:%M') if f.created_at else '' }}</td>
                <td><a href="/findings/{{ f.finding_id }}" class="btn">View</a></td>
            </tr>
            {% endfor %}
        </tbody>
    </table>

    <div class="pagination">
        {% if page > 1 %}<a href="?page={{ page-1 }}{% if filter_reviewed is not none %}&reviewed={{ filter_reviewed }}{% endif %}{% if filter_category %}&category={{ filter_category }}{% endif %}">Previous</a>{% endif %}
        <span>Page {{ page }} of {{ total_pages }}</span>
        {% if page < total_pages %}<a href="?page={{ page+1 }}{% if filter_reviewed is not none %}&reviewed={{ filter_reviewed }}{% endif %}{% if filter_category %}&category={{ filter_category }}{% endif %}">Next</a>{% endif %}
    </div>
    {% else %}
    <div class="empty">No findings match the current filters.</div>
    {% endif %}
""" + footer,

        "crawled.html": base_html.replace("{user_display}", '<a href="/logout">Logout</a>') + """
    <div class="container">
    <h1>Crawled Pages</h1>
    <p style="color:#8b949e; margin-bottom:1rem;">Every page collected by the crawler with its AI classification. Pages that scored as <code>unknown</code> or are not yet classified are included &mdash; this is the full crawl ledger, not just high-risk findings. <strong>{{ total }}</strong> pages total.</p>
    <form method="get" action="/crawled">
        <select name="category">
            <option value="">All Categories</option>
            <option value="unclassified" {% if filter_category == 'unclassified' %}selected{% endif %}>(unclassified)</option>
            {% for cat in ['ransomware', 'malware_sale', 'credential_leak', 'access_broker', 'data_leak', 'scam', 'drug_trafficking', 'weapons_trafficking', 'terrorism_extremism', 'human_trafficking', 'unknown'] %}
                <option value="{{ cat }}" {% if filter_category == cat %}selected{% endif %}>{{ cat }}</option>
            {% endfor %}
        </select>
        <select name="source">
            <option value="">All Sources</option>
            {% for s in sources %}
                <option value="{{ s }}" {% if filter_source == s %}selected{% endif %}>{{ s }}</option>
            {% endfor %}
        </select>
        <button type="submit" class="btn">Filter</button>
    </form>

    {% if pages %}
    <table>
        <thead>
            <tr>
                <th>Category</th>
                <th>Confidence</th>
                <th>Source</th>
                <th>URL</th>
                <th>Size</th>
                <th>Summary</th>
                <th>Collected</th>
                <th></th>
            </tr>
        </thead>
        <tbody>
            {% for p in pages %}
            <tr style="cursor:pointer;" onclick="window.location='/crawled/{{ p.record_id }}'">
                <td>
                    {% if p.category in ['terrorism_extremism', 'human_trafficking'] %}
                        <span class="badge badge-danger">{{ p.category }}</span>
                    {% elif p.category in ['drug_trafficking', 'weapons_trafficking', 'ransomware', 'access_broker', 'credential_leak'] %}
                        <span class="badge badge-warning">{{ p.category }}</span>
                    {% elif p.category and p.category != 'unknown' %}
                        <span class="badge badge-info">{{ p.category }}</span>
                    {% elif p.category == 'unknown' %}
                        <span class="badge badge-secondary">unknown</span>
                    {% else %}
                        <span class="badge badge-secondary">unclassified</span>
                    {% endif %}
                </td>
                <td>{{ "%.2f"|format(p.confidence) if p.confidence is not none else '—' }}</td>
                <td>{{ p.source[:24] }}</td>
                <td style="max-width:340px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;"><span title="{{ p.url }}">{{ p.url }}</span></td>
                <td>{{ "{:,}".format(p.size_bytes) if p.size_bytes else 0 }}</td>
                <td style="max-width:360px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;"><span title="{{ p.summary }}">{{ p.summary or '' }}</span></td>
                <td>{{ p.collected_at.strftime('%Y-%m-%d %H:%M') if p.collected_at else '' }}</td>
                <td><a href="/crawled/{{ p.record_id }}" class="btn" onclick="event.stopPropagation()">View</a></td>
            </tr>
            {% endfor %}
        </tbody>
    </table>

    <div class="pagination">
        {% if page > 1 %}<a href="?page={{ page-1 }}{% if filter_category %}&category={{ filter_category }}{% endif %}{% if filter_source %}&source={{ filter_source }}{% endif %}">Previous</a>{% endif %}
        <span>Page {{ page }} of {{ total_pages }}</span>
        {% if page < total_pages %}<a href="?page={{ page+1 }}{% if filter_category %}&category={{ filter_category }}{% endif %}{% if filter_source %}&source={{ filter_source }}{% endif %}">Next</a>{% endif %}
    </div>
    {% else %}
    <div class="empty">No crawled pages match the current filters.</div>
    {% endif %}
""" + footer,

        "crawled_detail.html": base_html.replace("{user_display}", '<a href="/logout">Logout</a>') + """
    <div class="container">
    <h1>Crawled Page Detail</h1>
    <div class="card">
        <table>
            <tr><th>Record ID</th><td>{{ page.record_id }}</td></tr>
            <tr><th>Category</th><td>
                {% if classification and classification.category %}
                    {% if classification.category in ['terrorism_extremism', 'human_trafficking'] %}
                        <span class="badge badge-danger">{{ classification.category }}</span>
                    {% elif classification.category in ['drug_trafficking', 'weapons_trafficking', 'ransomware', 'access_broker', 'credential_leak'] %}
                        <span class="badge badge-warning">{{ classification.category }}</span>
                    {% elif classification.category != 'unknown' %}
                        <span class="badge badge-info">{{ classification.category }}</span>
                    {% else %}
                        <span class="badge badge-secondary">unknown</span>
                    {% endif %}
                {% else %}
                    <span class="badge badge-secondary">unclassified</span>
                {% endif %}
            </td></tr>
            {% if classification and classification.confidence is not none %}
            <tr><th>Confidence</th><td>{{ "%.3f"|format(classification.confidence) }}</td></tr>
            {% endif %}
            <tr><th>Source</th><td>{{ page.source }}</td></tr>
            <tr><th>URL</th><td style="max-width:560px;word-break:break-all;"><a href="{{ page.url }}" target="_blank" rel="noopener noreferrer">{{ page.url }}</a></td></tr>
            {% if analysis and analysis.title %}
            <tr><th>Title</th><td>{{ analysis.title }}</td></tr>
            {% endif %}
            {% if analysis and analysis.author %}
            <tr><th>Author</th><td>{{ analysis.author }}</td></tr>
            {% endif %}
            {% if classification and classification.summary %}
            <tr><th>AI Summary</th><td>{{ classification.summary }}</td></tr>
            {% endif %}
            <tr><th>Size</th><td>{{ "{:,}".format(page.size_bytes) if page.size_bytes else 0 }} bytes</td></tr>
            <tr><th>SHA-256</th><td style="font-family:monospace;font-size:0.8rem;word-break:break-all;">{{ page.sha256 }}</td></tr>
            <tr><th>Collected</th><td>{{ page.collected_at }}</td></tr>
            {% if finding_id %}
            <tr><th>Promoted Finding</th><td><a href="/findings/{{ finding_id }}">{{ finding_id[:8] }}… (view finding)</a></td></tr>
            {% endif %}
        </table>
    </div>

    {% if entities %}
    <h2>Extracted Entities</h2>
    <div class="card">
        <table>
            {% for key, values in entities.items() %}
            {% if values %}
            <tr>
                <th>{{ key.replace('_', ' ')|title }}</th>
                <td>
                    {% if values is mapping %}
                        {% for k, v in values.items() %}
                            <div>{{ k }}: {{ v }}</div>
                        {% endfor %}
                    {% elif values is sequence and values is not string %}
                        {{ values | join(', ') }}
                    {% else %}
                        {{ values }}
                    {% endif %}
                </td>
            </tr>
            {% endif %}
            {% endfor %}
        </table>
    </div>
    {% endif %}

    {% if raw_evidence %}
    <h2>Raw Crawled Page</h2>
    <p style="color:#8b949e;font-size:0.85rem;">Rendered in a sandboxed frame &mdash; scripts, styles and active content stripped.</p>
    <iframe srcdoc="{{ raw_evidence | e }}" sandbox style="width:100%;height:600px;border:1px solid #444;border-radius:4px;background:#fff;color:#000;"></iframe>
    {% else %}
    <div class="empty">No raw page content stored for this record.</div>
    {% endif %}

    <a href="/crawled" class="btn" style="margin-top:1rem;">Back to Crawled Pages</a>
""" + footer,

        "finding_detail.html": base_html.replace("{user_display}", '<a href="/logout">Logout</a>') + """
    <div class="container">
    <h1>Finding Detail</h1>
    <div class="card">
        <table>
            <tr><th>Finding ID</th><td>{{ finding.finding_id }}</td></tr>
            <tr><th>Category</th><td><span class="badge badge-{{ 'danger' if finding.requires_human_review else 'info' }}">{{ finding.category }}</span></td></tr>
            <tr><th>Confidence</th><td>{{ "%.3f"|format(finding.confidence) }}</td></tr>
            <tr><th>Source</th><td>{{ finding.source }}</td></tr>
            {% if raw_url %}
            <tr><th>URL</th><td style="max-width:500px;overflow:hidden;text-overflow:ellipsis;word-break:break-all;"><a href="{{ raw_url }}" target="_blank" rel="noopener noreferrer">{{ raw_url }}</a></td></tr>
            {% endif %}
            <tr><th>Summary</th><td>{{ finding.summary }}</td></tr>
            <tr><th>Requires Human Review</th><td>{{ 'Yes' if finding.requires_human_review else 'No' }}</td></tr>
            <tr><th>Corroborating Sources</th><td>{{ finding.corroborating_sources }}</td></tr>
            <tr><th>Confidence Level</th><td><span class="badge badge-{{ 'success' if finding.confidence_level == 'VERIFIED' else 'warning' if finding.confidence_level == 'HIGH' else 'secondary' }}">{{ finding.confidence_level }}</span></td></tr>
            <tr><th>Created</th><td>{{ finding.created_at }}</td></tr>
            {% if finding.reviewed %}
            <tr><th>Reviewed By</th><td>{{ finding.reviewed_by }}</td></tr>
            <tr><th>Reviewed At</th><td>{{ finding.reviewed_at }}</td></tr>
            {% endif %}
        </table>
    </div>

    {% if raw_evidence %}
    <h3>Raw Evidence</h3>
    {% if raw_url %}<p><a href="{{ raw_url }}" target="_blank" rel="noopener noreferrer">{{ raw_url }}</a></p>{% endif %}
    <iframe srcdoc="{{ raw_evidence | e }}" sandbox style="width:100%;height:600px;border:1px solid #444;border-radius:4px;background:#fff;color:#000;"></iframe>
    {% endif %}

    {% if entities %}
    <h2>Extracted Entities</h2>
    <div class="card">
        <table>
            {% for key, values in entities.items() %}
            {% if values %}
            <tr>
                <th>{{ key.replace('_', ' ')|title }}</th>
                <td>
                    {% if values is mapping %}
                        {% for k, v in values.items() %}
                            <div>{{ k }}: {{ v }}</div>
                        {% endfor %}
                    {% elif values is sequence and values is not string %}
                        {{ values | join(', ') }}
                    {% else %}
                        {{ values }}
                    {% endif %}
                </td>
            </tr>
            {% endif %}
            {% endfor %}
        </table>
    </div>
    {% endif %}

    {% if not finding.reviewed %}
    <h2>Review</h2>
    <form method="post" action="/findings/{{ finding.finding_id }}/review">
        <input type="hidden" name="finding_id" value="{{ finding.finding_id }}">
        <input type="hidden" name="reviewer" value="{{ user }}">
        <button type="submit" name="action" value="approve" class="btn btn-primary">Approve</button>
        <button type="submit" name="action" value="dismiss" class="btn btn-danger">Dismiss</button>
    </form>
    {% endif %}

    <a href="/findings" class="btn" style="margin-top:1rem;">Back to Findings</a>

    <script>
        document.querySelectorAll('form[action*="/review"]').forEach(form => {
            form.addEventListener('submit', async (e) => {
                e.preventDefault();
                const action = e.submitter.value;
                const findingId = form.querySelector('[name=finding_id]').value;
                const reviewer = form.querySelector('[name=reviewer]').value;
                const resp = await fetch(`/findings/${findingId}/review`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({finding_id: findingId, action, reviewer}),
                });
                if (resp.ok) { location.reload(); }
            });
        });
    </script>
""" + footer,

        "search.html": base_html.replace("{user_display}", '<a href="/logout">Logout</a>') + """
    <div class="container">
    <h1>Search Intelligence</h1>
    <form method="get" action="/search">
        <input type="text" name="q" value="{{ query }}" placeholder="Search keywords, CVE IDs, emails..." style="flex:1;">
        <button type="submit" class="btn btn-primary">Search</button>
    </form>

    {% if query %}
        {% if total > 0 %}
            <p>{{ total }} result(s) for "{{ query }}"</p>
            {% for r in results %}
            <div class="card" onclick="window.location='/findings/{{ r.finding_id }}'" style="cursor:pointer;">
                <strong>{{ r.category }}</strong> (confidence: {{ "%.2f"|format(r.confidence) }})<br>
                {{ r.summary[:300] }}
            </div>
            {% endfor %}
        {% else %}
            <div class="empty">No results found.</div>
        {% endif %}
    {% else %}
        <h2>Recent Findings</h2>
        {% if total > 0 %}
            <table>
                <thead>
                    <tr>
                        <th>Category</th>
                        <th>Source</th>
                        <th>URL</th>
                        <th>Summary</th>
                        <th>Confidence</th>
                        <th>Date</th>
                    </tr>
                </thead>
                <tbody>
                    {% for r in results %}
                    <tr onclick="window.location='/findings/{{ r.finding_id }}'" style="cursor:pointer;">
                        <td><span class="badge badge-{{ r.category }}">{{ r.category }}</span></td>
                        <td>{{ r.source }}</td>
                        <td style="max-width:250px;overflow:hidden;text-overflow:ellipsis;">{{ r.url }}</td>
                        <td>{{ r.summary[:200] }}</td>
                        <td>{{ "%.2f"|format(r.confidence) }}</td>
                        <td>{{ r.created_at.strftime('%Y-%m-%d %H:%M') if r.created_at else '' }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        {% else %}
            <div class="empty">No findings yet. Data will appear as the pipeline processes content.</div>
        {% endif %}
    {% endif %}
""" + footer,

        "sources.html": base_html.replace("{user_display}", '<a href="/logout">Logout</a>') + """
    <div class="container">
    <h1>Source Registry</h1>
    <table>
        <thead>
            <tr>
                <th>Name</th>
                <th>URL</th>
                <th>Category</th>
                <th>Status</th>
                <th>Reliability</th>
                <th>Risk Score</th>
                <th>Active</th>
            </tr>
        </thead>
        <tbody>
            {% for s in sources %}
            <tr>
                <td>{{ s.name }}</td>
                <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;">{{ s.url }}</td>
                <td>{{ s.category }}</td>
                <td><span class="badge badge-{{ 'success' if s.status == 'active' else 'danger' if s.status == 'quarantined' else 'warning' }}">{{ s.status }}</span></td>
                <td>{{ "%.2f"|format(s.reliability_score) if s.reliability_score else 'N/A' }}</td>
                <td>{{ "%.2f"|format(s.risk_score) if s.risk_score else 'N/A' }}</td>
                <td>{{ 'Yes' if s.active else 'No' }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>

    <h2>Pending Proposals</h2>
    <p style="color:#8b949e;font-size:0.85rem;">
        Proposing a source here does <strong>not</strong> start crawling it. Per INV-04, every new
        source must be signed off in the <a href="/admin">Admin Panel</a> before it's added to
        the crawl registry.
    </p>
    {% if pending %}
    <table>
        <thead>
            <tr>
                <th>Source ID</th>
                <th>URL</th>
                <th>Category</th>
                <th>Risk</th>
                <th>Proposed By</th>
                <th>Proposed At</th>
            </tr>
        </thead>
        <tbody>
            {% for p in pending %}
            <tr>
                <td>{{ p.source_id }}</td>
                <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;">{{ p.url }}</td>
                <td>{{ p.category }}</td>
                <td>{{ p.risk_level }}</td>
                <td>{{ p.proposed_by }}</td>
                <td>{{ p.proposed_at.strftime('%Y-%m-%d %H:%M') if p.proposed_at else '' }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    {% else %}
    <div class="empty">No proposals awaiting sign-off.</div>
    {% endif %}

    <h2>Propose a New Source</h2>
    <div class="card" id="error" style="display:none;color:#f85149;"></div>
    <form id="proposeForm">
        <label>Source ID</label>
        <input type="text" name="source_id" required placeholder="e.g. example_forum">
        <label>URL (.onion)</label>
        <input type="text" name="url" required placeholder="http://....onion/">
        <label>Category</label>
        <input type="text" name="category" required placeholder="forum | marketplace | paste | ...">
        <label>Risk Level</label>
        <select name="risk_level">
            <option value="low">low</option>
            <option value="medium" selected>medium</option>
            <option value="high">high</option>
        </select>
        <label>Review Notes</label>
        <input type="text" name="review_notes" placeholder="Why this source matters">
        <label>Max Pages</label>
        <input type="number" name="max_pages" value="5" min="1" max="1000">
        <label>Link Selector (CSS, optional)</label>
        <input type="text" name="link_selector" placeholder="a[href*='post/']">
        <label>Queue Wait Seconds</label>
        <input type="number" name="queue_wait_seconds" value="0" min="0" max="300">
        <button type="submit" class="btn btn-primary" style="margin-top:1rem;">Submit Proposal</button>
    </form>

    <script>
        document.getElementById('proposeForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const form = e.target;
            const errorEl = document.getElementById('error');
            const body = {
                source_id: form.source_id.value,
                url: form.url.value,
                category: form.category.value,
                risk_level: form.risk_level.value,
                review_notes: form.review_notes.value,
                max_pages: parseInt(form.max_pages.value, 10),
                link_selector: form.link_selector.value,
                queue_wait_seconds: parseInt(form.queue_wait_seconds.value, 10),
            };
            const resp = await fetch('/sources/propose', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(body),
            });
            if (resp.ok) {
                location.reload();
            } else {
                const data = await resp.json();
                errorEl.textContent = data.detail || 'Failed to submit proposal';
                errorEl.style.display = 'block';
            }
        });
    </script>
""" + footer,

        "actors.html": base_html.replace("{user_display}", '<a href="/logout">Logout</a>') + """
    <div class="container">
    <h1>Threat Actors</h1>
    {% if actors and actors[0].primary_alias is defined %}
    <table>
        <thead>
            <tr>
                <th>Alias</th>
                <th>Aliases</th>
                <th>Wallets</th>
                <th>Telegram</th>
                <th>First Seen</th>
                <th>Last Seen</th>
            </tr>
        </thead>
        <tbody>
            {% for a in actors %}
            <tr>
                <td><strong>{{ a.primary_alias }}</strong></td>
                <td>{{ a.aliases|length if a.aliases else 0 }}</td>
                <td>{{ a.wallets.keys()|list|length if a.wallets else 0 }}</td>
                <td>{{ a.telegram_handles|join(', ') if a.telegram_handles else '-' }}</td>
                <td>{{ a.first_seen.strftime('%Y-%m-%d') if a.first_seen else '-' }}</td>
                <td>{{ a.last_seen.strftime('%Y-%m-%d') if a.last_seen else '-' }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    {% elif actors %}
    <table>
        <thead>
            <tr>
                <th>Actor Name</th>
                <th>Mentions</th>
                <th>Last Seen</th>
            </tr>
        </thead>
        <tbody>
            {% for a in actors %}
            <tr>
                <td><strong>{{ a.actor_name }}</strong></td>
                <td>{{ a.mentions }}</td>
                <td>{{ a.last_seen.strftime('%Y-%m-%d %H:%M') if a.last_seen else '-' }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    {% else %}
    <div class="empty">No threat actors tracked yet.</div>
    {% endif %}
""" + footer,

        "admin_panel.html": admin_base_html + """
    <div class="container">
    <h1>Admin Panel — Sign-off Queue</h1>

    <div class="card" style="border-color:#d29922;margin-bottom:1.5rem;">
        <h3 style="margin-bottom:0.5rem;">AI Processing Kill Switch (IR-001)</h3>
        <p style="color:#8b949e;font-size:0.85rem;margin-bottom:1rem;">
            Broadcasts to every AI layer replica. In-memory only — if a replica restarts it
            comes back up enabled, same as the existing auto-disable-on-poisoning-campaign behavior.
        </p>
        <button class="btn btn-danger" onclick="setAi('disable')">Disable AI Processing</button>
        <button class="btn btn-primary" onclick="setAi('enable')">Re-enable AI Processing</button>
    </div>

    <p style="color:#8b949e;font-size:0.85rem;margin-bottom:1.5rem;">
        Approving a source here appends it to <code>config/sources.yaml</code> and the crawler will
        start crawling it on its next cycle (per INV-04, this is the only path that activates a source).
    </p>

    <table>
        <thead>
            <tr>
                <th>Source ID</th>
                <th>URL</th>
                <th>Category</th>
                <th>Risk</th>
                <th>Proposed By</th>
                <th>Proposed At</th>
                <th>Status</th>
                <th>Action</th>
            </tr>
        </thead>
        <tbody>
            {% for p in pending_sources %}
            <tr>
                <td>{{ p.source_id }}</td>
                <td style="max-width:280px;overflow:hidden;text-overflow:ellipsis;">{{ p.url }}</td>
                <td>{{ p.category }}</td>
                <td>{{ p.risk_level }}</td>
                <td>{{ p.proposed_by }}</td>
                <td>{{ p.proposed_at.strftime('%Y-%m-%d %H:%M') if p.proposed_at else '' }}</td>
                <td><span class="badge badge-{{ 'success' if p.status == 'approved' else 'danger' if p.status == 'rejected' else 'warning' }}">{{ p.status }}</span></td>
                <td>
                    {% if p.status == 'pending_review' %}
                    <button class="btn btn-primary" onclick="approveSource('{{ p.id }}')">Approve</button>
                    <button class="btn btn-danger" onclick="rejectSource('{{ p.id }}')">Reject</button>
                    {% else %}
                    {{ p.reviewed_by }}
                    {% endif %}
                </td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    {% if not pending_sources %}
    <div class="empty">No source proposals yet.</div>
    {% endif %}

    <h2 style="margin-top:2rem;">Discovered Candidates</h2>
    <p style="color:#8b949e;font-size:0.85rem;margin-bottom:1.5rem;">
        URLs the analysis stage found embedded in crawled content. Promoting one creates a
        full proposal in the queue above (still requires its own separate Approve click) —
        nothing here is ever crawled directly.
    </p>
    <table>
        <thead>
            <tr>
                <th>URL</th>
                <th>Discovered From</th>
                <th>Discovered At</th>
                <th>Action</th>
            </tr>
        </thead>
        <tbody>
            {% for c in candidates %}
            <tr>
                <td style="max-width:320px;overflow:hidden;text-overflow:ellipsis;">{{ c.url }}</td>
                <td>{{ c.discovered_from }}</td>
                <td>{{ c.discovered_at.strftime('%Y-%m-%d %H:%M') if c.discovered_at else '' }}</td>
                <td>
                    <button class="btn btn-primary" onclick="promoteCandidate('{{ c.id }}', '{{ c.url }}')">Promote</button>
                    <button class="btn btn-danger" onclick="rejectCandidate('{{ c.id }}')">Reject</button>
                </td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    {% if not candidates %}
    <div class="empty">No discovered candidates awaiting review.</div>
    {% endif %}

    <script>
        async function approveSource(id) {
            if (!confirm('Approve this source? It will start being crawled on the next cycle.')) return;
            const resp = await fetch(`/admin/sources/${id}/approve`, { method: 'POST' });
            if (resp.ok) { location.reload(); }
            else { const d = await resp.json(); alert(d.detail || 'Failed to approve'); }
        }
        async function rejectSource(id) {
            const reason = prompt('Rejection reason (optional):', '') || '';
            const resp = await fetch(`/admin/sources/${id}/reject`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ reason }),
            });
            if (resp.ok) { location.reload(); }
            else { const d = await resp.json(); alert(d.detail || 'Failed to reject'); }
        }
        async function promoteCandidate(id, url) {
            const source_id = prompt('source_id for this candidate:', '');
            if (!source_id) return;
            const category = prompt('category (forum | marketplace | paste | ...):', 'forum');
            if (!category) return;
            const resp = await fetch(`/admin/candidates/${id}/promote`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ source_id, category, risk_level: 'medium' }),
            });
            if (resp.ok) { location.reload(); }
            else { const d = await resp.json(); alert(d.detail || 'Failed to promote'); }
        }
        async function rejectCandidate(id) {
            const reason = prompt('Rejection reason (optional):', '') || '';
            const resp = await fetch(`/admin/candidates/${id}/reject`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ reason }),
            });
            if (resp.ok) { location.reload(); }
            else { const d = await resp.json(); alert(d.detail || 'Failed to reject'); }
        }
        async function setAi(action) {
            if (!confirm(`${action === 'disable' ? 'Disable' : 'Re-enable'} AI processing pipeline-wide?`)) return;
            const resp = await fetch(`/admin/ai/${action}`, { method: 'POST' });
            if (resp.ok) { alert('Done.'); }
            else { const d = await resp.json(); alert(d.detail || 'Failed'); }
        }
    </script>
""" + footer,

        "admin_users.html": admin_base_html + """
    <div class="container">
    <h1>User Management</h1>

    <table>
        <thead>
            <tr>
                <th>Username</th>
                <th>Role</th>
                <th>Active</th>
                <th>Created</th>
                <th>Last Login</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            {% for u in users %}
            <tr>
                <td>{{ u.username }}</td>
                <td><span class="badge badge-{{ 'success' if u.role == 'admin' else 'info' }}">{{ u.role }}</span></td>
                <td>{{ 'Yes' if u.active else 'No' }}</td>
                <td>{{ u.created_at.strftime('%Y-%m-%d') if u.created_at else '' }}</td>
                <td>{{ u.last_login_at.strftime('%Y-%m-%d %H:%M') if u.last_login_at else 'Never' }}</td>
                <td>
                    {% if u.active %}
                    <button class="btn btn-danger" onclick="deactivateUser('{{ u.id }}')">Deactivate</button>
                    {% else %}
                    <button class="btn btn-primary" onclick="reactivateUser('{{ u.id }}')">Reactivate</button>
                    {% endif %}
                    <button class="btn" onclick="changeRole('{{ u.id }}', '{{ u.role }}')">Change Role</button>
                    <button class="btn" onclick="resetPassword('{{ u.id }}')">Reset Password</button>
                </td>
            </tr>
            {% endfor %}
        </tbody>
    </table>

    <h2>Create User</h2>
    <div class="card" id="error" style="display:none;color:#f85149;"></div>
    <form id="createUserForm">
        <label>Username</label>
        <input type="text" name="username" required minlength="3" maxlength="64">
        <label>Password</label>
        <input type="password" name="password" required minlength="8" maxlength="256">
        <label>Role</label>
        <select name="role">
            <option value="analyst" selected>analyst</option>
            <option value="admin">admin</option>
        </select>
        <button type="submit" class="btn btn-primary" style="margin-top:1rem;">Create User</button>
    </form>

    <script>
        document.getElementById('createUserForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const form = e.target;
            const errorEl = document.getElementById('error');
            const resp = await fetch('/admin/users', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    username: form.username.value,
                    password: form.password.value,
                    role: form.role.value,
                }),
            });
            if (resp.ok) { location.reload(); }
            else {
                const data = await resp.json();
                errorEl.textContent = data.detail || 'Failed to create user';
                errorEl.style.display = 'block';
            }
        });

        async function deactivateUser(id) {
            if (!confirm('Deactivate this user? They will no longer be able to log in.')) return;
            const resp = await fetch(`/admin/users/${id}/deactivate`, { method: 'POST' });
            if (resp.ok) { location.reload(); } else { const d = await resp.json(); alert(d.detail || 'Failed'); }
        }
        async function reactivateUser(id) {
            const resp = await fetch(`/admin/users/${id}/reactivate`, { method: 'POST' });
            if (resp.ok) { location.reload(); } else { const d = await resp.json(); alert(d.detail || 'Failed'); }
        }
        async function changeRole(id, currentRole) {
            const newRole = currentRole === 'admin' ? 'analyst' : 'admin';
            if (!confirm(`Change role to ${newRole}?`)) return;
            const resp = await fetch(`/admin/users/${id}/role`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ role: newRole }),
            });
            if (resp.ok) { location.reload(); } else { const d = await resp.json(); alert(d.detail || 'Failed'); }
        }
        async function resetPassword(id) {
            const password = prompt('New password (min 8 characters):', '');
            if (!password) return;
            const resp = await fetch(`/admin/users/${id}/reset_password`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ password }),
            });
            if (resp.ok) { alert('Password reset.'); } else { const d = await resp.json(); alert(d.detail || 'Failed'); }
        }
    </script>
""" + footer,

        "admin_registry.html": admin_base_html + """
    <div class="container">
    <h1>Source Registry — Lifecycle Management</h1>
    <p style="color:#8b949e;font-size:0.85rem;margin-bottom:1.5rem;">
        Quarantine/retire edits the source's <code>status:</code> line in
        <code>config/sources.yaml</code> directly — the crawler stops crawling it on its
        next cycle. Reset Reputation clears poisoning_incidents after manual review
        (IR-001 Data Poisoning Event).
    </p>

    <table>
        <thead>
            <tr>
                <th>Name</th>
                <th>URL</th>
                <th>Category</th>
                <th>Reputation Status</th>
                <th>Poisoning Incidents</th>
                <th>Reliability</th>
                <th>Active</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            {% for s in sources %}
            <tr>
                <td>{{ s.name }}</td>
                <td style="max-width:260px;overflow:hidden;text-overflow:ellipsis;">{{ s.url }}</td>
                <td>{{ s.category }}</td>
                <td><span class="badge badge-{{ 'success' if s.reputation_status == 'active' else 'danger' if s.reputation_status in ['quarantined','retired'] else 'warning' }}">{{ s.reputation_status or 'unknown' }}</span></td>
                <td>{{ s.poisoning_incidents if s.poisoning_incidents is not none else 0 }}</td>
                <td>{{ "%.2f"|format(s.reliability_score) if s.reliability_score else 'N/A' }}</td>
                <td>{{ 'Yes' if s.active else 'No' }}</td>
                <td>
                    <button class="btn btn-danger" onclick="setStatus('{{ s.name }}', 'quarantined')">Quarantine</button>
                    <button class="btn" onclick="setStatus('{{ s.name }}', 'retired')">Retire</button>
                    <button class="btn btn-primary" onclick="setStatus('{{ s.name }}', 'approved')">Reactivate</button>
                    <button class="btn" onclick="resetReputation('{{ s.name }}')">Reset Reputation</button>
                </td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    {% if not sources %}
    <div class="empty">No sources in the registry yet.</div>
    {% endif %}

    <script>
        async function setStatus(name, status) {
            if (!confirm(`Set '${name}' status to ${status}?`)) return;
            const resp = await fetch(`/admin/registry/${encodeURIComponent(name)}/status`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ status }),
            });
            if (resp.ok) { location.reload(); }
            else { const d = await resp.json(); alert(d.detail || 'Failed'); }
        }
        async function resetReputation(name) {
            if (!confirm(`Reset reputation/poisoning count for '${name}'?`)) return;
            const resp = await fetch(`/admin/registry/${encodeURIComponent(name)}/reset_reputation`, { method: 'POST' });
            if (resp.ok) { location.reload(); }
            else { const d = await resp.json(); alert(d.detail || 'Failed'); }
        }
    </script>
""" + footer,

        "admin_audit.html": admin_base_html + """
    <div class="container">
    <h1>Audit Log</h1>
    <p style="color:#8b949e;font-size:0.85rem;margin-bottom:1.5rem;">
        Dashboard-originated events only (logins, source sign-off, user management).
        Crawler/sanitizer/AI-layer/db-writer events live in their own containers'
        logs, not here.
    </p>

    {% if entries %}
    <table>
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>Severity</th>
                <th>Component</th>
                <th>Event</th>
                <th>Details</th>
            </tr>
        </thead>
        <tbody>
            {% for e in entries %}
            <tr>
                <td style="white-space:nowrap;">{{ e.timestamp }}</td>
                <td><span class="badge badge-{{ 'danger' if e.severity == 'CRITICAL' else 'warning' if e.severity == 'WARNING' else 'secondary' }}">{{ e.severity }}</span></td>
                <td>{{ e.component }}</td>
                <td>{{ e.event }}</td>
                <td style="max-width:400px;overflow:hidden;text-overflow:ellipsis;">{{ e.details }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    {% else %}
    <div class="empty">No audit events recorded yet.</div>
    {% endif %}
""" + footer,
    }

    for filename, content in template_content.items():
        with open(os.path.join(templates_dir, filename), "w", encoding="utf-8") as f:
            f.write(content)


def main() -> None:
    create_template_files()
    bootstrap_users()
    import uvicorn

    ssl_kwargs = {}
    if DASHBOARD_USE_HTTPS:
        ssl_kwargs["ssl_certfile"] = DASHBOARD_HTTPS_CERT
        ssl_kwargs["ssl_keyfile"] = DASHBOARD_HTTPS_KEY

    uvicorn.run(
        app,
        host=DASHBOARD_HOST,
        port=DASHBOARD_PORT,
        log_level="info",
        **ssl_kwargs,
    )


if __name__ == "__main__":
    main()
