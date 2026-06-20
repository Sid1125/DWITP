# INTEL-002 — Telegram Group Intelligence & Actor-Network Analysis
## Dark Web Intelligence & Threat Monitoring Platform (DWITP)

**Version:** 0.1 (Draft / Plan of Action)
**Classification:** Intelligence Capability Design
**Status:** Proposed — pending Phase 0 decisions
**Related:** ARCH-001 (Architecture), AI-001 (AI Governance), IR-001 (Incident Response), INTEL-001 (Intelligence Requirements), Dwitp_vibe_security_spec.md (INV-04/05)

---

# Purpose

Define a new DWITP capability that ingests message data from **approved Telegram groups** and produces **social-network and behavioral intelligence**: who participates, who orchestrates, the informal hierarchy, sub-cell structure, per-actor modus operandi, and cross-source actor linkage.

This is **not** a page crawler. It analyzes the full conversational record of a group to infer structure and influence that the participants do not publish.

---

# Scope & Relationship to Existing Standards

This capability **extends** the existing pipeline (ARCH-001) and inherits its constraints. It does **not** introduce a new trust model.

**In scope:**
- Passive ingestion of messages, membership, and explicit roles from Telegram groups that are *approved sources*.
- Interaction-graph construction (replies, mentions, forwards).
- Social Network Analysis (centrality, community detection) and behavioral inference.
- Per-actor MO classification and cross-source actor unification.
- Analyst-facing network visualization and actor profiles.

**Explicitly out of scope (non-goals):**
- **No interaction with threat actors.** ARCH-001 states the system "is not designed to interact with threat actors." This capability *observes*; it does not post, reply, DM, or participate.
- **No persona fabrication, impersonation, or social-engineering tooling.**
- **No anti-ban / detection-evasion tradecraft.**
- **No penetration of closed cells via deception.**
- **No automated harvesting of personal data beyond what is required** for the intelligence product.

The boundary is the *access method*, not the *depth of analysis*. Deep SNA over a lawfully accessible group is in scope; gaining access through deception is not.

---

# Legal & Ethical Guardrails (MANDATORY)

These are enforced in code and process, not left to operator discretion.

| ID | Guardrail |
|----|-----------|
| TG-G1 | A Telegram group is a **source**. It must pass the candidate → admin-approval flow (INV-04) before any collection. No ad-hoc targeting. |
| TG-G2 | Each approved group must carry a **documented legal basis reference** (`legal_basis_ref`). Collection is blocked without it. |
| TG-G3 | Collection is **observation only** — no message is ever sent (ARCH-001 non-interaction principle). The collector has no send path. |
| TG-G4 | **CSAM / trafficking-of-persons content → auto-quarantine, do NOT retain, escalate** per IR-001. Retention of such material is itself unlawful and triggers mandatory reporting. Enforced at `db_writer`. |
| TG-G5 | **PII minimization**: store platform identifiers (user id, handle) and behavioral metadata, not unnecessary personal data. Configurable retention window with a purge job. |
| TG-G6 | All findings remain `requires_human_review`. The AI is an **analyst, not an operator** (AI-001). No automated actioning. |
| TG-G7 | Identity links via **hard identifiers** (shared wallet/PGP/handle) may be asserted; links via **behavioral/stylometric inference are probabilistic** and surfaced for human review only — never auto-merged. |
| TG-G8 | Collector is covered by the **AI/collection kill-switch** and the full **audit log**. |

---

# Intelligence Products (per INTEL-001 style)

This capability produces these analyst-facing products:

- **Group Roster & Hierarchy** — members, explicit roles (owner/admin/member), inferred informal roles.
- **Influence Ranking** — actors ranked by network influence, distinct from raw message volume.
- **Orchestrator Identification** — likely controllers/coordinators (high betweenness + high in-reply + low volume signature).
- **Sub-cell Map** — community-detected clusters and their local lieutenants.
- **Actor MO Profile** — per-actor role (vendor / launderer / recruiter / tech / enforcer / peripheral).
- **Cross-Source Actor Linkage** — unification of Telegram personas with existing dark-web threat actors.
- **Temporal Activity Profile** — activity rhythm, burst initiation, timezone inference.

---

# Architecture Overview

```
                         approved Telegram groups (sources)
                                      │
                          ┌───────────▼────────────┐
                          │   telegram_collector    │  (NEW — observation only)
                          │  MTProto/Bot, read-only │
                          └───────────┬────────────┘
                                      │ telegram.raw (RabbitMQ)
                          ┌───────────▼────────────┐
                          │      sanitizer          │  (REUSED)
                          └───────────┬────────────┘
                          ┌───────────▼────────────┐
                          │   analysis (EXTENDED)   │  + reply/mention/forward edges
                          └───────────┬────────────┘
                          ┌───────────▼────────────┐
                          │   ai_layer (EXTENDED)   │  + per-actor MO tagging
                          └───────────┬────────────┘
                          ┌───────────▼────────────┐
                          │   db_writer (EXTENDED)  │  → Postgres (messages/actors)
                          │                         │  → Neo4j  (actor graph)
                          └───────────┬────────────┘
                          ┌───────────▼────────────┐
                          │ graph_analytics (NEW)   │  Neo4j GDS: PageRank,
                          │  scheduled / on-demand  │  betweenness, Louvain → scores
                          └───────────┬────────────┘
                          ┌───────────▼────────────┐
                          │  dashboard "Network"    │  (NEW VIEW) graph + rankings
                          └─────────────────────────┘
```

**New components:** `telegram_collector`, `graph_analytics`, dashboard Network view.
**Extended:** `analysis`, `ai_layer`, `db_writer`, source-approval flow, init-db schema.
**Reused unchanged:** RabbitMQ transport, `sanitizer`, audit log, kill-switch, `threat_actors`.

---

# Collection Methodology

## Decision: Bot API vs MTProto (Phase 0 — must resolve first)

| | Bot API | MTProto user-client (Telethon/Pyrogram) |
|---|---|---|
| History before join | No | Yes |
| Full member roster | No | Yes (capped on large supergroups) |
| Explicit roles | Limited | Yes |
| ToS / ban risk | Low | Grey-area; account-ban risk |
| Intel value | Weak | Strong |

**Recommendation:** MTProto client on a **dedicated, lawfully-operated account**, scoped to groups that can be **openly joined**. It is the only option that yields history + roles. Document legal basis (TG-G2) before enabling.

**Hard constraint:** whichever is chosen, the collector is **read-only** — no send capability exists in the codebase (TG-G3).

## Member enumeration reality

Telegram caps full member-list retrieval on large supergroups. Admins are always visible. Therefore **hierarchy = explicit roles (where available) + behavioral inference from messages**. The behavioral graph is the primary and more robust signal.

---

# Data Models

## Postgres (additions to scripts/init-db.sql)

```sql
-- Approved Telegram groups (governed exactly like source_registry; INV-04)
CREATE TABLE IF NOT EXISTS telegram_groups (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tg_group_id     BIGINT NOT NULL UNIQUE,
    title           TEXT NOT NULL,
    username        TEXT,
    join_method     TEXT NOT NULL CHECK (join_method IN ('public_link','invite','username')),
    status          TEXT NOT NULL DEFAULT 'pending_review'
                        CHECK (status IN ('pending_review','approved','quarantined','retired')),
    approved_by     TEXT,
    approved_at     TIMESTAMPTZ,
    legal_basis_ref TEXT,                       -- REQUIRED before collection (TG-G2)
    risk_level      TEXT NOT NULL DEFAULT 'high' CHECK (risk_level IN ('low','medium','high')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Append-only message ledger (dedup on natural key)
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
    confidence      REAL,
    collected_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tg_group_id, tg_message_id)
);
CREATE INDEX IF NOT EXISTS idx_tg_messages_group ON telegram_messages (tg_group_id);
CREATE INDEX IF NOT EXISTS idx_tg_messages_sender ON telegram_messages (sender_id);

-- Denormalized actor profiles (SNA scores written by graph_analytics)
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
    requires_review         BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

## Neo4j (the graph payoff)

```cypher
// Constraints
CREATE CONSTRAINT actor_id IF NOT EXISTS FOR (a:Actor) REQUIRE a.user_id IS UNIQUE;
CREATE CONSTRAINT group_id IF NOT EXISTS FOR (g:Group) REQUIRE g.group_id IS UNIQUE;

// Nodes & relationships
(:Actor {user_id, handle, role})
(:Group {group_id, title})
(:Message {msg_id, ts, category})

(:Actor)-[:MEMBER_OF {role, joined}]->(:Group)
(:Actor)-[:REPLIED_TO {count, avg_latency_sec}]->(:Actor)   // directed, weighted
(:Actor)-[:MENTIONED {count}]->(:Actor)
(:Actor)-[:POSTED]->(:Message)-[:IN]->(:Group)
```

Edges are upserted with `MERGE` + counter increments by `db_writer`.

---

# Pipeline Integration

## Queue envelope (`telegram.raw`)

Mirrors the existing `raw.crawl` record so the downstream stages need minimal change:

```json
{
  "record_id": "uuid",
  "source": "telegram:<group_id>",
  "platform": "telegram",
  "sha256": "<hash of text>",
  "url": "tg://<group_id>/<message_id>",
  "raw_text": "<message text>",
  "tg": {
    "group_id": 123, "message_id": 456, "sender_id": 789,
    "sender_handle": "@x", "sent_at": "ISO8601",
    "reply_to_msg_id": 455, "mentions": ["@y"], "forward_from_id": null,
    "sender_role": "member"
  }
}
```

## Stage responsibilities

- **sanitizer** — unchanged (strips injection patterns, redacts as today).
- **analysis (extended)** — emit the `reply_to`, `mentions`, `forward_from` edges and per-message sender metadata into the structured record; reuse existing entity extraction (`telegram_handles`, wallets, PGP).
- **ai_layer (extended)** — classify message content (existing categories) and contribute to per-actor MO aggregation.
- **db_writer (extended)** — write `telegram_messages`; upsert `Actor`/`Group`/`Message` nodes and interaction edges in Neo4j; enforce TG-G4 (CSAM quarantine) and content-hash dedup.

---

# SNA & Behavioral Methodology

## Why volume ≠ control

The loudest account is frequently a hype-man or low-level vendor. The controller's signature is **structural**, surfaced by different metrics:

| Metric (Neo4j GDS) | Reveals |
|---|---|
| Degree / message volume | Activity (not power) |
| **In-degree of REPLIED_TO / MENTIONED** | Who others direct queries to → authority |
| **Betweenness centrality** | Brokers bridging sub-cells (often quiet) |
| **PageRank / eigenvector** | Influence weighted by who you connect to |
| **Louvain community detection** | Sub-cells; each cell's local lieutenant |
| **Burst initiation (temporal)** | Who posts first; others follow → directive role |
| **Response-time asymmetry** | Fast replies to leader, slow to peers → deference |

**Orchestrator likelihood** = composite favoring *high betweenness + high in-reply + low volume*.

## Hierarchy = formal + informal

- **Formal:** explicit owner/admin/member roles from the API (ground truth).
- **Informal:** inferred from imperative vs. interrogative language, announce-vs-ask behavior, deference patterns, and cell membership.

## Cross-source unification

Shared **hard identifiers** (wallet, PGP fingerprint, reused handle) link a Telegram actor to an existing `threat_actors` row (assert). **Stylometric / behavioral** similarity is probabilistic → `requires_review = TRUE`, analyst confirms (TG-G7).

---

# Governance Integration

- **Source approval (INV-04):** groups enter via candidate → admin sign-off; `legal_basis_ref` required (TG-G2).
- **Source reputation (INV-05):** a group can be quarantined/retired; manipulated/poisoned groups degrade.
- **Audit:** collection start/stop, per-group ingestion, actor merges, quarantines — all logged.
- **Kill-switch:** halts the collector and the analytics job.
- **AI-as-analyst (AI-001):** all actor findings `requires_human_review`.
- **IR-001:** CSAM/trafficking detection routes to the incident playbook (quarantine + escalate).

---

# Phased Plan of Action & Task Breakdown

## Phase 0 — Decisions & Governance (gate)
- T0.1 Resolve Bot API vs MTProto (recommendation: MTProto, controlled account).
- T0.2 Document legal basis + per-jurisdiction review; define `legal_basis_ref` process.
- T0.3 Write retention & redaction policy (window, purge, CSAM rule).
- T0.4 Extend source governance with a `platform` dimension; design Telegram approval UI in Admin Panel.
- **Exit:** API chosen, legal basis documented, retention policy written, schema supports `platform: telegram`.

## Phase 1 — Collector & Ingestion
- T1.1 `telegram_collector` service skeleton (read-only, reads approved `telegram_groups`).
- T1.2 Message streaming + member/role pull; dedup on `(group_id, message_id)`; persistent "seen" state on named volume.
- T1.3 Publish `telegram.raw` envelope; wire `sanitizer` to consume it.
- T1.4 `telegram_messages` table + `db_writer` persistence path.
- T1.5 Rate-limit/backoff handling; kill-switch wiring; audit events.
- **Exit:** one approved group's messages ingested, classified, listed in dashboard.

## Phase 2 — Actor Graph Construction
- T2.1 Extend `analysis` to emit reply/mention/forward edges + sender metadata.
- T2.2 `db_writer` Neo4j upserts: Actor/Group/Message nodes + weighted edges.
- T2.3 Neo4j constraints + indexes; idempotent MERGE counters.
- **Exit:** interaction graph queryable in Neo4j ("top repliers-to X").

## Phase 3 — SNA Analytics
- T3.1 `graph_analytics` job (scheduled/on-demand) using Neo4j GDS.
- T3.2 Compute PageRank, betweenness, in-reply degree, Louvain cells, temporal features.
- T3.3 Composite `influence_score` + `orchestrator_likelihood`; write back to `telegram_actors`.
- **Exit:** actors ranked; orchestrators/lieutenants flagged distinct from volume.

## Phase 4 — Dashboard "Network" View
- T4.1 Network tab: actor ranking table (volume, influence, in-reply, role, cell).
- T4.2 Force-directed graph render colored by community.
- T4.3 Actor profile page (messages, MO, role, cell, cross-source links).
- **Exit:** analyst can open a group, see the inferred org chart, drill into actors.

## Phase 5 — MO Profiling & Cross-Source Linking
- T5.1 Per-actor MO aggregation in `ai_layer`.
- T5.2 Hard-identifier unification into `threat_actors`.
- T5.3 Probabilistic-link review queue (TG-G7).
- **Exit:** an actor seen on dread + Telegram shows one unified, review-flagged profile.

## Phase 6 — Hardening & Operations
- T6.1 Rate-limit/ban-aware backoff; graceful degradation.
- T6.2 Retention purge job + CSAM auto-quarantine live and tested.
- T6.3 Full audit coverage; kill-switch verification.
- T6.4 Backfill/replay safety; idempotent graph rebuild.
- **Exit:** production-safe, policy-enforced, observable.

**Sequencing:** 0 → (1+2 together) → 3 → 4 → 5 → 6. Phases 1–4 are the MVP demonstrating "who orchestrates."

---

# Challenges & Risks

| # | Challenge | Mitigation |
|---|-----------|------------|
| C1 | **API choice ceiling** — Bot API too weak; MTProto risky | Phase-0 decision; MTProto on controlled account, openly-joinable groups only |
| C2 | **Account ban / rate limits** (MTProto) | Backoff, conservative pacing, graceful degradation, no evasion tradecraft (out of scope) |
| C3 | **Member enumeration caps** on large supergroups | Lean on explicit roles + behavioral inference; behavioral graph is primary signal |
| C4 | **Volume / throughput** — busy groups flood the LLM | Same bottleneck as web pipeline; parallel `ai_layer` workers, queue backpressure; SNA edges don't need the LLM |
| C5 | **Identity resolution ambiguity** | Hard IDs assert; behavioral links → human review only (TG-G7) |
| C6 | **Adversarial manipulation** — actors aware of monitoring use sockpuppets / fake deference to distort the graph | Treat graph as evidence not truth; corroboration scoring (INV-05); flag anomalous patterns for analyst |
| C7 | **Legal basis variance by jurisdiction** | `legal_basis_ref` required per group; counsel review (Phase 0) |
| C8 | **CSAM / trafficking material** | Auto-quarantine, no-retain, mandatory escalation (TG-G4 / IR-001) — non-negotiable |
| C9 | **Graph staleness vs compute cost** | Scheduled incremental analytics; on-demand recompute for active investigations |
| C10 | **Scope creep toward interaction/infiltration** | Hard architectural constraint: no send path; reviewed at design gate |

---

# Open Decisions (block where noted)

1. **[BLOCKS Phase 1]** Bot API vs MTProto, and the controlled account's provenance/legal basis.
2. Retention window length and purge cadence.
3. Whether Telegram groups share the existing source-approval tables (with a `platform` column) or get a parallel approval surface.
4. GDS edition (Community covers PageRank/betweenness/Louvain — sufficient; confirm no Enterprise-only algos needed).
5. Graph-analytics cadence (continuous vs. per-investigation).

---

# Testing & Acceptance

- **Unit:** edge extraction (reply/mention/forward), dedup keys, CSAM-quarantine rule, hard-identifier merge.
- **Graph:** golden-dataset group with a known orchestrator → analytics must rank them above the highest-volume account.
- **Governance:** collection blocked without `legal_basis_ref`; kill-switch halts collector; audit entries present for every collection and merge.
- **Acceptance (MVP, end of Phase 4):** for an approved test group, an analyst can view the member roster, the influence ranking, the flagged orchestrator(s), the sub-cell map, and drill into any actor — all from lawfully ingested data, fully audited.

---

# Appendix A — Service/Config Footprint

- **New services:** `telegram_collector`, `graph_analytics` (compose services, kill-switch + audit wired).
- **New queue:** `telegram.raw`.
- **Config:** approved groups in the governed source registry (not ad-hoc); collector reads them like the crawler reads `sources.yaml`.
- **Secrets:** Telegram API credentials via environment/secret store; never in the repo.

---

*This document is a plan of action. Phase 0 decisions — especially the collection API and the documented legal basis — gate implementation. Phases 1–2 are the foundation and carry no analysis risk; they are the recommended starting point once Phase 0 is closed.*
