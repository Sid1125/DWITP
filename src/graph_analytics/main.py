"""DWITP Graph Analytics — Social Network Analysis over the Telegram actor graph
(INTEL-002, Phase 3).

Reads the interaction graph (Actors + weighted REPLIED_TO / MENTIONED edges) built
by db_writer, computes the SNA metrics, and writes per-actor scores back to
`telegram_actors` (for the dashboard) and onto the Neo4j Actor nodes (for graph
colouring). Runs on an interval; honours an `analytics_enabled` pause flag.

Why volume != control: the loudest account is usually a hype-man. The controller's
signature is STRUCTURAL — high betweenness (bridges sub-cells) + high in-reply
(others direct queries to them) + LOW message volume. `orchestrator_likelihood`
encodes exactly that, so a quiet broker ranks above the noisiest poster.

Metrics (computed with networkx — same algorithms Neo4j GDS would run):
  * pagerank              — influence weighted by who connects to you
  * betweenness           — brokers on many shortest paths between sub-cells
  * in_reply_degree       — weighted count of replies/mentions directed AT an actor
  * cell_id               — Louvain community (sub-cell)
  * influence_score       — composite (pagerank + in-reply + betweenness)
  * orchestrator_likelihood — betweenness + in-reply + (low) volume
  * inferred_role         — leader / lieutenant / operator / peripheral
"""
from __future__ import annotations

import os
import sys
import time

import networkx as nx
import psycopg2
from neo4j import GraphDatabase

from src.common.security import audit_log

# ─── Config ───────────────────────────────────────────────────
POSTGRES_DSN = " ".join([
    f"host={os.environ.get('POSTGRES_HOST', 'postgres')}",
    f"port={os.environ.get('POSTGRES_PORT', '5432')}",
    f"dbname={os.environ.get('POSTGRES_DB', 'dwitp')}",
    f"user={os.environ.get('POSTGRES_USER', 'dwitp')}",
    f"password={os.environ.get('POSTGRES_PASSWORD', '')}",
    f"sslmode={os.environ.get('POSTGRES_SSLMODE', 'require')}",
    f"sslrootcert={os.environ.get('PGSSLROOTCERT', '/etc/dwitp/tls/ca/ca.crt')}",
])

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt+ssc://neo4j:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "")

INTERVAL = int(os.environ.get("GRAPH_ANALYTICS_INTERVAL", "300"))
# Edge weighting: a reply is a stronger "directs attention to" signal than a mention.
W_REPLY = float(os.environ.get("SNA_W_REPLY", "1.0"))
W_MENTION = float(os.environ.get("SNA_W_MENTION", "0.5"))


def _neo4j():
    return GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))


# ─── Read the graph ───────────────────────────────────────────
def read_graph() -> tuple[dict[int, str], list[tuple[int, int, float]], dict[int, int]]:
    """Return ({user_id: handle}, [(src, dst, weight)], {user_id: volume}).

    Actors + handle->id map + volume come from the authoritative telegram_actors
    table. Edges come from Neo4j. Mention targets are resolved to a canonical
    user_id via the handle map: db_writer keys senders by user_id but mention
    targets by handle, so a person mentioned before they were identified ends up
    on a handle-only placeholder node — we fold those back onto the real actor
    here so dropped/out-of-order messages don't split an actor's in-reply signal."""
    actors: dict[int, str] = {}
    volume: dict[int, int] = {}
    handle2uid: dict[str, int] = {}
    conn = psycopg2.connect(POSTGRES_DSN)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT tg_user_id, handle, message_count FROM telegram_actors")
            for uid, handle, cnt in cur.fetchall():
                uid = int(uid)
                actors[uid] = handle
                volume[uid] = int(cnt or 0)
                if handle:
                    handle2uid[handle] = uid
    finally:
        conn.close()

    edges: dict[tuple[int, int], float] = {}

    def add(s, d, w):
        if s is None or d is None or s == d:
            return
        key = (int(s), int(d))
        edges[key] = edges.get(key, 0.0) + w

    driver = _neo4j()
    try:
        with driver.session() as s:
            for rec in s.run(
                "MATCH (a:Actor)-[r:REPLIED_TO]->(b:Actor) "
                "WHERE a.user_id IS NOT NULL AND b.user_id IS NOT NULL "
                "RETURN a.user_id AS s, b.user_id AS d, coalesce(r.count,1) AS c"
            ):
                add(rec["s"], rec["d"], float(rec["c"]) * W_REPLY)
            for rec in s.run(
                "MATCH (a:Actor)-[r:MENTIONED]->(b:Actor) WHERE a.user_id IS NOT NULL "
                "RETURN a.user_id AS s, b.user_id AS duid, b.handle AS dhandle, "
                "coalesce(r.count,1) AS c"
            ):
                d = rec["duid"]
                if d is None:
                    d = handle2uid.get(rec["dhandle"])   # resolve placeholder -> real actor
                add(rec["s"], d, float(rec["c"]) * W_MENTION)
    finally:
        driver.close()

    return actors, [(s, d, w) for (s, d), w in edges.items()], volume


def analytics_paused() -> bool:
    """Honour the kill-switch: a system_settings row analytics_enabled='false'
    halts scoring. Absent -> enabled (default)."""
    try:
        conn = psycopg2.connect(POSTGRES_DSN)
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT value FROM system_settings WHERE key = 'analytics_enabled'")
                row = cur.fetchone()
                return bool(row) and str(row[0]).lower() == "false"
        finally:
            conn.close()
    except Exception:
        return False


# ─── Scoring ──────────────────────────────────────────────────
def _norm(d: dict[int, float]) -> dict[int, float]:
    if not d:
        return {}
    vals = list(d.values())
    lo, hi = min(vals), max(vals)
    if hi - lo < 1e-12:
        return {k: 0.0 for k in d}
    return {k: (v - lo) / (hi - lo) for k, v in d.items()}


def _infer_role(influence_n: float, orchestrator_n: float, volume_n: float) -> str:
    if orchestrator_n >= 0.66:
        return "leader"        # quiet broker / top orchestrator
    if influence_n >= 0.66:
        return "lieutenant"    # active sub-cell authority
    if volume_n >= 0.66:
        return "operator"      # loud, low influence
    return "peripheral"


def compute_scores(actors: dict[int, str], edges: list[tuple[int, int, float]],
                   volume: dict[int, int]) -> list[tuple]:
    G = nx.DiGraph()
    for uid, handle in actors.items():
        G.add_node(uid, handle=handle)
    for s, d, w in edges:
        if G.has_edge(s, d):
            G[s][d]["weight"] += w
        else:
            G.add_edge(s, d, weight=w)

    nodes = list(G.nodes())
    if not nodes:
        return []

    has_edges = G.number_of_edges() > 0
    # PageRank weights by tie strength; betweenness (unweighted) finds brokers on
    # the most shortest paths; in-reply is the weighted in-degree of attention.
    pagerank = nx.pagerank(G, weight="weight") if has_edges else {n: 0.0 for n in nodes}
    betweenness = nx.betweenness_centrality(G) if has_edges else {n: 0.0 for n in nodes}
    in_reply = {n: float(sum(w for _, _, w in G.in_edges(n, data="weight"))) for n in nodes}

    UG = G.to_undirected()
    if UG.number_of_edges() > 0:
        communities = nx.community.louvain_communities(UG, weight="weight", seed=42)
    else:
        communities = [{n} for n in nodes]
    cell = {n: i for i, comm in enumerate(communities) for n in comm}

    prn, betn, irn = _norm(pagerank), _norm(betweenness), _norm(in_reply)
    voln = _norm({n: float(volume.get(n, 0)) for n in nodes})

    rows = []
    for n in nodes:
        influence = 0.5 * prn.get(n, 0) + 0.3 * irn.get(n, 0) + 0.2 * betn.get(n, 0)
        orchestrator = 0.4 * betn.get(n, 0) + 0.4 * irn.get(n, 0) + 0.2 * (1 - voln.get(n, 0))
        role = _infer_role(influence, orchestrator, voln.get(n, 0))
        rows.append((
            round(pagerank.get(n, 0), 6),
            round(betweenness.get(n, 0), 6),
            int(in_reply.get(n, 0)),
            round(influence, 6),
            round(orchestrator, 6),
            cell.get(n),
            role,
            n,
        ))
    return rows


# ─── Write back ───────────────────────────────────────────────
def write_back(rows: list[tuple]) -> None:
    conn = psycopg2.connect(POSTGRES_DSN)
    try:
        with conn.cursor() as cur:
            cur.executemany(
                """UPDATE telegram_actors SET
                       pagerank = %s, betweenness = %s, in_reply_degree = %s,
                       influence_score = %s, orchestrator_likelihood = %s,
                       cell_id = %s, inferred_role = %s, updated_at = NOW()
                   WHERE tg_user_id = %s""",
                rows,
            )
            conn.commit()
    finally:
        conn.close()

    # Annotate Neo4j nodes for the dashboard graph (cell colour + influence size).
    try:
        driver = _neo4j()
        with driver.session() as s:
            s.run(
                """UNWIND $rows AS row
                   MATCH (a:Actor {user_id: row.uid})
                   SET a.influence_score = row.influence,
                       a.orchestrator_likelihood = row.orchestrator,
                       a.cell_id = row.cell,
                       a.inferred_role = row.role""",
                rows=[{"uid": r[7], "influence": r[3], "orchestrator": r[4],
                       "cell": r[5], "role": r[6]} for r in rows],
            )
        driver.close()
    except Exception as e:
        audit_log("neo4j_annotate_error", {"error": str(e)}, severity="ERROR")


def run_once() -> int:
    if analytics_paused():
        audit_log("graph_analytics_paused", {}, severity="WARNING")
        return 0
    actors, edges, volume = read_graph()
    if not actors:
        return 0
    rows = compute_scores(actors, edges, volume)
    write_back(rows)
    top = max(rows, key=lambda r: r[4], default=None)  # highest orchestrator_likelihood
    audit_log("graph_analytics_run", {
        "actors": len(rows),
        "edges": len(edges),
        "top_orchestrator_user_id": top[7] if top else None,
        "top_orchestrator_likelihood": top[4] if top else None,
    })
    return len(rows)


def main() -> None:
    print("DWITP Graph Analytics started — SNA over the Telegram actor graph (INTEL-002 Phase 3)")
    while True:
        try:
            n = run_once()
            if n:
                print(f"Scored {n} actor(s)")
        except Exception as e:
            audit_log("graph_analytics_error", {"error": str(e)}, severity="ERROR")
        time.sleep(INTERVAL)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
