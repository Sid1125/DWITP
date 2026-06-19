-- DWITP Database Initialization
-- Security: raw_evidence is append-only (no UPDATE/DELETE for app roles)

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ─── Users (dashboard + admin panel accounts) ─────────────────
CREATE TABLE IF NOT EXISTS users (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username        TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    role            TEXT NOT NULL DEFAULT 'analyst' CHECK (role IN ('analyst', 'admin')),
    active          BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by      TEXT,
    last_login_at   TIMESTAMPTZ
);

-- ─── System Settings (key/value control flags, e.g. AI kill switch) ─
CREATE TABLE IF NOT EXISTS system_settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_by  TEXT,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─── Source Registry ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS source_registry (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name        TEXT NOT NULL UNIQUE,
    url         TEXT NOT NULL,
    category    TEXT NOT NULL,
    approved_by TEXT NOT NULL,
    approved_date DATE NOT NULL,
    active      BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─── Raw Evidence (append-only) ───────────────────────────────
CREATE TABLE IF NOT EXISTS raw_evidence (
    record_id   UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    sha256      TEXT NOT NULL,
    source      TEXT NOT NULL,
    url         TEXT NOT NULL,
    raw_text    TEXT NOT NULL,
    size_bytes  INTEGER NOT NULL DEFAULT 0,
    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Content-hash lookup for the db_writer dedup guard (skip pages already stored).
CREATE INDEX IF NOT EXISTS idx_raw_evidence_sha256 ON raw_evidence (sha256);

-- ─── Candidate Sources (discovery queue) ──────────────────────
CREATE TABLE IF NOT EXISTS candidate_sources (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    url             TEXT NOT NULL UNIQUE,
    discovered_from TEXT NOT NULL,
    discovered_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status          TEXT NOT NULL DEFAULT 'pending_review'
                        CHECK (status IN ('pending_review', 'approved', 'rejected')),
    reviewed_by     TEXT,
    reviewed_at     TIMESTAMPTZ,
    rejection_reason TEXT
);

-- ─── Pending Sources (operator-proposed, awaiting admin sign-off) ─
-- Analysts can propose a new crawl target from the main dashboard, but per
-- INV-04 (config/sources.yaml is read-only at runtime, never written by a
-- runtime API) nothing here is ever crawled directly. An admin must review
-- and approve in the Admin Panel, which appends the entry to sources.yaml.
CREATE TABLE IF NOT EXISTS pending_sources (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    source_id           TEXT NOT NULL,
    url                 TEXT NOT NULL,
    category            TEXT NOT NULL,
    risk_level          TEXT NOT NULL DEFAULT 'medium' CHECK (risk_level IN ('low', 'medium', 'high')),
    review_notes        TEXT DEFAULT '',
    max_pages           INTEGER NOT NULL DEFAULT 5,
    link_selector       TEXT DEFAULT '',
    queue_wait_seconds  INTEGER NOT NULL DEFAULT 0,
    proposed_by         TEXT NOT NULL,
    proposed_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status              TEXT NOT NULL DEFAULT 'pending_review'
                            CHECK (status IN ('pending_review', 'approved', 'rejected')),
    reviewed_by         TEXT,
    reviewed_at         TIMESTAMPTZ,
    rejection_reason    TEXT
);

-- ─── Sanitized Records ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sanitized_records (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    record_id   UUID NOT NULL REFERENCES raw_evidence(record_id),
    source      TEXT NOT NULL,
    url         TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    collected_at TIMESTAMPTZ NOT NULL,
    content_sanitized TEXT NOT NULL,
    injection_patterns_detected JSONB DEFAULT '[]',
    sanitized_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─── Analysis Results ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS analysis_results (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    record_id   UUID NOT NULL REFERENCES raw_evidence(record_id),
    source      TEXT NOT NULL,
    url         TEXT NOT NULL,
    title       TEXT DEFAULT '',
    author      TEXT,
    timestamp_posted TIMESTAMPTZ,
    entities    JSONB NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─── AI Classifications ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS classifications (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    record_id   UUID NOT NULL REFERENCES raw_evidence(record_id),
    category    TEXT NOT NULL,
    confidence  REAL NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    entities    JSONB NOT NULL DEFAULT '{}',
    summary     TEXT NOT NULL DEFAULT '',
    mitre_ttps  JSONB DEFAULT '[]',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─── Intelligence Findings ────────────────────────────────────
CREATE TABLE IF NOT EXISTS intelligence_findings (
    finding_id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    record_id           UUID NOT NULL REFERENCES raw_evidence(record_id),
    category            TEXT NOT NULL,
    confidence          REAL NOT NULL,
    source              TEXT NOT NULL,
    summary             TEXT NOT NULL,
    corroborating_sources INTEGER NOT NULL DEFAULT 0,
    confidence_level    TEXT NOT NULL DEFAULT 'UNCONFIRMED'
                            CHECK (confidence_level IN ('UNCONFIRMED', 'LOW', 'MEDIUM', 'HIGH', 'VERIFIED')),
    requires_human_review BOOLEAN NOT NULL DEFAULT FALSE,
    reviewed            BOOLEAN NOT NULL DEFAULT FALSE,
    reviewed_by         TEXT,
    reviewed_at         TIMESTAMPTZ,
    alert_triggered     BOOLEAN NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─── Source Reputation ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS source_reputation (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    source_name         TEXT NOT NULL UNIQUE,
    reliability_score   REAL NOT NULL DEFAULT 0.5 CHECK (reliability_score >= 0.0 AND reliability_score <= 1.0),
    activity_score      REAL NOT NULL DEFAULT 0.5 CHECK (activity_score >= 0.0 AND activity_score <= 1.0),
    risk_score          REAL NOT NULL DEFAULT 0.5 CHECK (risk_score >= 0.0 AND risk_score <= 1.0),
    last_seen           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    poisoning_incidents INTEGER NOT NULL DEFAULT 0,
    status              TEXT NOT NULL DEFAULT 'active'
                            CHECK (status IN ('active', 'degraded', 'quarantined', 'retired')),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─── Audit Log (append-only) ──────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_log (
    id          BIGSERIAL PRIMARY KEY,
    event       TEXT NOT NULL,
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    details     JSONB NOT NULL DEFAULT '{}'
);

-- ─── Threat Actor Profiles ────────────────────────────────────
CREATE TABLE IF NOT EXISTS threat_actors (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    primary_alias   TEXT NOT NULL UNIQUE,
    aliases         JSONB DEFAULT '[]',
    pgp_keys        JSONB DEFAULT '[]',
    wallets         JSONB DEFAULT '{}',
    telegram_handles JSONB DEFAULT '[]',
    jabber_ids      JSONB DEFAULT '[]',
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ,
    notes           TEXT DEFAULT ''
);

-- ─── Telegram Group Intelligence (INTEL-002) ──────────────────
-- Parallel governance surface for approved Telegram groups. A group is a SOURCE
-- and is governed exactly like the crawl sources (INV-04): it enters as
-- 'pending_review' and an admin must approve it. Collection is observation-only;
-- the collector has no send path (TG-G3 / ARCH-001 non-interaction).

CREATE TABLE IF NOT EXISTS telegram_groups (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tg_group_id     BIGINT NOT NULL UNIQUE,
    title           TEXT NOT NULL,
    username        TEXT,
    -- HOW the authorized account lawfully became a member. This is an attestation
    -- of an out-of-band, human, legally-authorized act — NOT a software capability.
    -- The collector NEVER joins by deception, persona fabrication, or social
    -- engineering (TG-G1). Closed / hard-to-reach groups are supported ONLY when
    -- access was obtained lawfully out-of-band and recorded here.
    access_method   TEXT NOT NULL CHECK (access_method IN (
                        'public_link',           -- openly joinable / publicly posted invite link
                        'authorized_undercover', -- access under documented legal authority/warrant
                        'cooperating_source',    -- a lawful member shares access
                        'lawful_compulsion'      -- compelled disclosure under legal process
                    )),
    status          TEXT NOT NULL DEFAULT 'pending_review'
                        CHECK (status IN ('pending_review','approved','quarantined','retired')),
    legal_basis_ref TEXT,                        -- REQUIRED before approval (TG-G2)
    risk_level      TEXT NOT NULL DEFAULT 'high' CHECK (risk_level IN ('low','medium','high')),
    proposed_by     TEXT,
    proposed_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    approved_by     TEXT,
    approved_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Hard gate (TG-G2): a group may NOT be 'approved' without a legal basis on
    -- file. Enforced at the database layer so no API path can bypass it.
    CONSTRAINT telegram_groups_legal_basis_required
        CHECK (status <> 'approved' OR legal_basis_ref IS NOT NULL)
);

-- Append-only message ledger; natural-key dedup on (group, message).
CREATE TABLE IF NOT EXISTS telegram_messages (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tg_group_id     BIGINT NOT NULL,
    tg_message_id   BIGINT NOT NULL,
    sender_id       BIGINT,
    sender_handle   TEXT,
    sent_at         TIMESTAMPTZ NOT NULL,
    text_sanitized  TEXT,
    reply_to_msg_id BIGINT,
    mentions        JSONB NOT NULL DEFAULT '[]',
    forward_from_id BIGINT,
    category        TEXT,                        -- ai_layer classification
    confidence      REAL CHECK (confidence IS NULL OR (confidence >= 0.0 AND confidence <= 1.0)),
    collected_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tg_group_id, tg_message_id)
);

-- Denormalized actor profiles; SNA scores written by the (future) graph_analytics job.
CREATE TABLE IF NOT EXISTS telegram_actors (
    id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tg_user_id              BIGINT NOT NULL UNIQUE,
    handle                  TEXT,
    display_name            TEXT,
    first_seen              TIMESTAMPTZ,
    last_seen               TIMESTAMPTZ,
    message_count           INTEGER NOT NULL DEFAULT 0,
    explicit_role           TEXT,                -- owner/admin/member (API ground truth)
    inferred_role           TEXT,                -- leader/lieutenant/operator/peripheral
    pagerank                REAL,
    betweenness             REAL,
    in_reply_degree         INTEGER,
    influence_score         REAL,                -- composite
    orchestrator_likelihood REAL,                -- betweenness↑ + in-reply↑ + volume↓
    cell_id                 INTEGER,             -- Louvain community
    primary_mo              TEXT,
    threat_actor_id         UUID REFERENCES threat_actors(id),  -- cross-source link
    requires_review         BOOLEAN NOT NULL DEFAULT TRUE,      -- AI-001: analyst confirms
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tg_groups_status ON telegram_groups(status);
CREATE INDEX IF NOT EXISTS idx_tg_messages_group ON telegram_messages(tg_group_id);
CREATE INDEX IF NOT EXISTS idx_tg_messages_sender ON telegram_messages(sender_id);
CREATE INDEX IF NOT EXISTS idx_tg_actors_user ON telegram_actors(tg_user_id);

-- The message ledger is evidence: append-only, like raw_evidence.
REVOKE UPDATE ON TABLE telegram_messages FROM PUBLIC;
REVOKE DELETE ON TABLE telegram_messages FROM PUBLIC;

-- ─── Indexes ──────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_raw_evidence_sha256 ON raw_evidence(sha256);
CREATE INDEX IF NOT EXISTS idx_raw_evidence_source ON raw_evidence(source);
CREATE INDEX IF NOT EXISTS idx_raw_evidence_collected_at ON raw_evidence(collected_at);
CREATE INDEX IF NOT EXISTS idx_sanitized_records_record_id ON sanitized_records(record_id);
CREATE INDEX IF NOT EXISTS idx_classifications_record_id ON classifications(record_id);
CREATE INDEX IF NOT EXISTS idx_classifications_category ON classifications(category);
CREATE INDEX IF NOT EXISTS idx_findings_category ON intelligence_findings(category);
CREATE INDEX IF NOT EXISTS idx_findings_confidence ON intelligence_findings(confidence);
CREATE INDEX IF NOT EXISTS idx_findings_reviewed ON intelligence_findings(reviewed);
CREATE INDEX IF NOT EXISTS idx_audit_log_event ON audit_log(event);
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_candidate_sources_status ON candidate_sources(status);

-- ─── Role Permissions (REVOKE UPDATE/DELETE on raw_evidence) ──
REVOKE UPDATE ON TABLE raw_evidence FROM PUBLIC;
REVOKE DELETE ON TABLE raw_evidence FROM PUBLIC;

-- Insert default source reputations
INSERT INTO source_reputation (source_name, reliability_score, activity_score, risk_score)
VALUES
    ('dread_forum', 0.6, 0.8, 0.7),
    ('ahmia_search', 0.5, 0.9, 0.4),
    ('ransomware_live', 0.7, 0.7, 0.5)
ON CONFLICT (source_name) DO NOTHING;
