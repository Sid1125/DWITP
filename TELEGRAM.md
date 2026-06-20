# DWITP — Telegram Group Intelligence (INTEL-002)

Status doc for the Telegram capability: the goal, the hard guardrails, what is built, what is left, and how to actually switch it on. The authoritative design is `INTEL-002_Telegram_Group_Intelligence.md`; this file tracks **implementation reality** against it.

**One-line status:** the full *collection → analysis → graph → SNA scoring* backend is built and proven end-to-end with synthetic data, but it is **idle** (no credentials, no approved group), the **dashboard Network view is not built**, and the **CSAM auto-quarantine guardrail (TG-G4) is not yet enforced in code**.

---

## 1. Goal

Ingest the message record of **lawfully-accessible, approved Telegram groups** and produce **social-network and behavioral intelligence** that participants do not publish:

- Who participates, and the informal hierarchy (not just admin/member).
- **Who orchestrates** — the controller's signature is *structural* (high betweenness + high in-reply + low volume), not loudness. "Volume ≠ control."
- Sub-cell structure (community detection) and each cell's local lieutenant.
- Per-actor modus operandi and **cross-source linkage** to existing dark-web threat actors.

This is **not** a page crawler — it analyzes the full conversational graph to infer influence and structure.

---

## 2. Hard Guardrails (non-negotiable, enforced in code/DB)

These are the boundary of the whole capability. They are *why* the design looks the way it does.

| ID | Guardrail | Enforced where |
|----|-----------|----------------|
| TG-G1 | A group is a governed **source** — candidate → admin approval, no ad-hoc targeting | `telegram_groups.status` + intended admin flow |
| TG-G2 | Approved group **must** carry a `legal_basis_ref` | DB `CHECK (status <> 'approved' OR legal_basis_ref IS NOT NULL)` + re-checked in collector |
| TG-G3 | **Observation only** — no send/post/reply/DM path exists anywhere | `telegram_collector` uses Telethon **read** methods only |
| TG-G4 | **CSAM / trafficking content → auto-quarantine, do not retain, escalate** | ✅ implemented — `child_exploitation` detected by the classifier; `db_writer` quarantine gate drops all content and emits a CRITICAL escalation (no raw_evidence/classification/finding written). Retention *purge* job (TG-G5) still pending |
| TG-G5 | PII minimization + retention window + purge job | ⚠️ partial — minimal fields stored; **no purge job** |
| TG-G6 | All actor findings stay `requires_human_review` (AI is analyst, not operator) | `telegram_actors.requires_review DEFAULT TRUE` |
| TG-G7 | Hard-ID links may assert; behavioral links are probabilistic → human review only | design; linking logic not built yet |
| TG-G8 | Covered by the collection kill-switch and full audit log | `control.collection` fanout + `audit_log` |

**Explicit non-goals (refused by design):** no infiltration, persona fabrication, impersonation, vetting-bypass, social-engineering of admins, anti-ban / detection-evasion, or deception-based entry to closed groups. The collector *observes* groups the operating account is **already a lawful member of**; access is obtained out-of-band under documented legal authority and recorded as `access_method` + `legal_basis_ref`. The boundary is the *access method*, not the depth of analysis.

---

## 3. Architecture & Data Flow

```
approved telegram_groups (governed source, legal_basis_ref required)
        │
        ▼
  telegram_collector   ← read-only Telethon user-session, Tor egress, idle w/o creds
        │  telegram.raw (RabbitMQ)
        ▼
  sanitizer  →  analysis  →  ai_layer (classifier)  →  db_writer
  (reused)     (+edges)      (rule-lexicon)            │
                                                       ├─→ Postgres: telegram_messages, telegram_actors
                                                       └─→ Neo4j:    Actor/Group/Message + REPLIED_TO/MENTIONED
        │
        ▼
  graph_analytics   ← periodic networkx SNA (PageRank/betweenness/Louvain/in-reply)
        │             writes scores back to telegram_actors + Neo4j nodes
        ▼
  dashboard "Network" view   ← ⚠️ NOT BUILT (nav link exists, route/template do not)
```

Reuses the existing pipeline unchanged from `telegram.raw` onward; the only platform-specific code is the collector, the `tg` passthrough in each stage, the db_writer Telegram path, and the SNA job.

---

## 4. Current Operational Status

- **Idle.** The collector runs but sleeps: no `TELEGRAM_API_ID/HASH/SESSION` configured, and no `telegram_groups` row is approved. This is intentional — it never crash-loops and never logs in interactively.
- **Validated with synthetic data.** The whole path (collector envelope → sanitizer → analysis → classifier → db_writer → Neo4j graph → `graph_analytics` SNA) was exercised end-to-end with injected test messages; the SNA correctly ranked a quiet orchestrator above the highest-volume account. Test data was then purged.
- **Services live:** `telegram_collector` and `graph_analytics` containers are up (idle/looping).

---

## 5. What's DONE

### Collector (`src/telegram_collector/main.py`) — Phase 1 ✅ (core)
- Read-only Telethon user-client; **no send path**.
- Reads only `status='approved' AND legal_basis_ref IS NOT NULL` groups (TG-G2 re-checked).
- `public_link` groups openly joined; all others read from an already-lawful session (never joins by deception).
- Incremental ingestion via per-group **high-water mark** (last message id), persisted to a named volume.
- Publishes the `telegram.raw` envelope; **Tor SOCKS5 egress**.
- **Collection kill-switch** (`control.collection` fanout) + audit events (`telegram_collection_start`, `telegram_group_ingested`, …).
- Idle-safe without credentials; `_halt()` fail-closed if Postgres/queue unreachable or session unauthorized.

### Pipeline passthrough — Phase 1/2 ✅
- **sanitizer** passes `platform` + `tg` block through untouched.
- **analysis** promotes extracted `@handles` into `tg.mentions` (mention edges); carries `reply_to_msg_id`, `forward_from_id`, sender metadata.
- **ai_layer / classifier** classifies message text with the same offline rule-lexicon engine; `tg` block + sanitized text passed to db_writer.
- New durable queue `telegram.raw`.

### Persistence & graph (`src/db_writer/main.py`) — Phase 1/2 ✅
- `write_telegram_message()` — insert into `telegram_messages` with **natural-key dedup** `(tg_group_id, tg_message_id)`; upserts a minimal `telegram_actors` row (handle, first/last seen, message_count).
- `update_telegram_graph()` — Neo4j `MERGE` of `Actor/Group/Message` nodes and `MEMBER_OF / POSTED / IN`, plus weighted `REPLIED_TO` (best-effort, links when the replied-to message exists) and `MENTIONED` (by handle) edges, idempotent counter increments.
- `telegram_messages` is append-only (`REVOKE UPDATE/DELETE`).

### SNA analytics (`src/graph_analytics/main.py`) — Phase 3 ✅
- Periodic job (`GRAPH_ANALYTICS_INTERVAL`, default 300s); honors an `analytics_enabled` pause flag.
- Reads actors/volume from Postgres + edges from Neo4j; **resolves handle-only mention placeholders to canonical user-ids** (fixes split in-reply signal from out-of-order messages).
- Computes **PageRank, betweenness, weighted in-reply degree, Louvain communities** (networkx, in-process — no Neo4j GDS plugin needed).
- Composite `influence_score` (0.5·pagerank + 0.3·in-reply + 0.2·betweenness) and `orchestrator_likelihood` (0.4·betweenness + 0.4·in-reply + 0.2·(1−volume)).
- Infers role: **leader / lieutenant / operator / peripheral**. Writes scores back to `telegram_actors` and annotates Neo4j nodes.

### Data model (`scripts/init-db.sql`) — Phase 0 schema ✅
- `telegram_groups`, `telegram_messages`, `telegram_actors` (see §7), with the legal-basis DB gate and append-only message ledger.

### Infra ✅
- Compose services `telegram_collector` (tor + queue + db nets, Tor egress, `collector_state` volume) and `graph_analytics` (db net, networkx+scipy image), both `restart: always`, audit-wired.

---

## 6. What's LEFT (and the critical gaps)

### ⚠️ Critical / safety
- **TG-G4 CSAM auto-quarantine — now implemented.** `db_writer.process_classification` intercepts `QUARANTINE_CATEGORIES` (`child_exploitation`) **before any persistence** (web *or* telegram path): content is dropped, nothing is written to `raw_evidence`/`classifications`/`intelligence_findings`, and a CRITICAL `quarantine_no_retain` audit event fans out to the notifier for NCMEC/LE escalation. ai_layer also redacts the content from the queue envelope, and the classifier never emits a verbatim CSAM `evidence_quote`. *Still to tune:* the CSAM lexicon's precision/recall on real data.
- **Retention / purge job (TG-G5) not built** — no configurable retention window, no purge cadence, no PII expiry.

### Phase 4 — Dashboard "Network" view ❌ (not built)
- The `/network` nav link and the homepage Telegram panel link to it, but **no `/network` route or template exists** (would 404).
- Missing: actor ranking table (volume vs influence vs in-reply, role, cell), force-directed community-colored graph, and the per-actor profile page.
- This is the MVP payoff (an analyst opening a group and seeing the org chart with the orchestrator flagged) — the data behind it is ready; only the view is missing.

### Phase 1/2 — partial
- **Member roster & explicit roles not pulled.** `collect_group()` ingests messages but does not call `get_participants`; `telegram_actors.explicit_role` is never populated. Hierarchy is currently **behavioral-only** (which the spec accepts as the primary signal, but formal roles are still a TODO).
- **Forward edges** carried in the envelope but not yet modeled as a distinct Neo4j relationship (only reply/mention are).
- **Neo4j uniqueness constraints** (`actor_id`, `group_id`) not formally created — `MERGE` dedups in practice but the constraints aren't declared.
- **Rate-limit / ban-aware backoff** is minimal (fixed poll interval); no adaptive backoff (Phase 6 / C2).

### Phase 3 — partial
- **Temporal features not computed** — burst initiation, response-time asymmetry, timezone inference (all listed in the spec's SNA table) are not implemented.

### Phase 5 — MO profiling & cross-source linking ❌ (not built)
- No per-actor MO aggregation (`telegram_actors.primary_mo` unused).
- No hard-identifier unification into `threat_actors` (the `threat_actor_id` FK exists but nothing populates it).
- No probabilistic-link review queue (TG-G7).

### Governance UI — not built
- **No Admin Panel UI** to propose/approve Telegram groups. The DB enforces the legal-basis gate, but a group must currently be inserted/approved via direct SQL. The candidate→approval flow (TG-G1) has no front-end yet.

### Phase 0 — policy docs
- Retention & redaction policy and per-jurisdiction `legal_basis_ref` process are described in the spec but not finalized as operational policy.

---

## 7. Data Model (as implemented)

### Postgres
- **`telegram_groups`** — `tg_group_id` (unique), title, username, **`access_method`** ∈ `{public_link, authorized_undercover, cooperating_source, lawful_compulsion}`, `status` ∈ `{pending_review, approved, quarantined, retired}`, **`legal_basis_ref`**, `risk_level`, proposed/approved metadata. DB gate: cannot be `approved` without `legal_basis_ref`.
- **`telegram_messages`** — append-only ledger, unique `(tg_group_id, tg_message_id)`; sender id/handle, `sent_at`, `text_sanitized`, `reply_to_msg_id`, `mentions` (jsonb), `forward_from_id`, `category`, `confidence`. `REVOKE UPDATE/DELETE`.
- **`telegram_actors`** — `tg_user_id` (unique), handle/display, first/last seen, `message_count`, `explicit_role`, `inferred_role`, `pagerank`, `betweenness`, `in_reply_degree`, `influence_score`, `orchestrator_likelihood`, `cell_id`, `primary_mo`, `threat_actor_id` (FK → `threat_actors`), `requires_review`.

### Neo4j
- Nodes `(:Actor {user_id, handle, role, influence_score, orchestrator_likelihood, cell_id})`, `(:Group {group_id})`, `(:Message {msg_id, ts, category})`.
- Edges `(:Actor)-[:MEMBER_OF]->(:Group)`, `(:Actor)-[:POSTED]->(:Message)-[:IN]->(:Group)`, weighted `(:Actor)-[:REPLIED_TO {count}]->(:Actor)`, `(:Actor)-[:MENTIONED {count}]->(:Actor)`.

### `telegram.raw` envelope
```json
{
  "record_id": "uuid", "source": "telegram:<gid>", "platform": "telegram",
  "sha256": "<hash>", "url": "tg://<gid>/<mid>", "raw_text": "<text>",
  "tg": { "group_id": 0, "message_id": 0, "sender_id": 0, "sender_handle": "@x",
          "sent_at": "ISO8601", "reply_to_msg_id": null, "mentions": [],
          "forward_from_id": null, "sender_role": null }
}
```

> **Schema note / divergence from spec:** the spec's `join_method (public_link/invite/username)` was deliberately replaced with the stronger **`access_method (public_link/authorized_undercover/cooperating_source/lawful_compulsion)`** — an attestation of a lawful, out-of-band human act, reflecting the "no infiltration" boundary rather than a software capability.

---

## 8. How to actually turn it on

1. **Build CSAM quarantine first (TG-G4).** Do not collect from a real group until this exists.
2. **Provision credentials out-of-band** (never commit): set `TELEGRAM_API_ID`, `TELEGRAM_API_HASH`, and a `TELEGRAM_SESSION` string for a dedicated, lawfully-operated account that is *already a member* of the target group.
3. **Approve a group with a legal basis** (currently via SQL until the Admin UI exists):
   ```sql
   INSERT INTO telegram_groups (tg_group_id, title, username, access_method, status, legal_basis_ref)
   VALUES (<gid>, '<title>', '<username>', 'authorized_undercover', 'approved', '<warrant/case ref>');
   ```
4. The collector picks it up next poll, ingests history (high-water incremental), and the pipeline classifies + graphs it. `graph_analytics` scores actors on its interval.
5. Inspect results in Postgres (`telegram_actors` ordered by `orchestrator_likelihood`) / Neo4j until the dashboard Network view is built.

---

## 9. Code Map

| Concern | File |
|---|---|
| Collector (read-only) | `src/telegram_collector/main.py` |
| `telegram.raw` queue | `src/common/queue.py` |
| `tg` passthrough | `src/sanitizer/main.py`, `src/analysis/main.py`, `src/ai_layer/main.py` |
| Persistence + Neo4j graph | `src/db_writer/main.py` (`write_telegram_message`, `update_telegram_graph`) |
| SNA scoring | `src/graph_analytics/main.py` |
| Schema | `scripts/init-db.sql` (telegram_* tables) |
| Compose services | `infra/docker-compose.yml` (`telegram_collector`, `graph_analytics`) |
| Design spec | `INTEL-002_Telegram_Group_Intelligence.md` |

---

## 10. Phase scorecard (vs INTEL-002 plan)

| Phase | Scope | Status |
|---|---|---|
| 0 | Decisions & governance | ✅ API chosen (MTProto), schema + legal-basis gate; ⚠️ retention policy/admin UI pending |
| 1 | Collector & ingestion | ✅ core done; ⚠️ no member-roster/explicit-role pull; "listed in dashboard" pending Phase 4 |
| 2 | Actor graph construction | ✅ reply/mention edges + nodes; ⚠️ forward edge + formal Neo4j constraints pending |
| 3 | SNA analytics | ✅ PageRank/betweenness/in-reply/Louvain + scores; ⚠️ temporal features pending |
| 4 | Dashboard Network view | ❌ not built (dead `/network` link) |
| 5 | MO profiling & cross-source linking | ❌ not built |
| 6 | Hardening & ops | ⚠️ kill-switch + audit + idempotency done; ❌ CSAM quarantine, retention purge, adaptive backoff |

**MVP (Phases 1–4) is ~75% there:** the intelligence engine works; the analyst-facing view and the CSAM safety gate are the two things standing between "proven in a test" and "usable on a real group."
