# graph_analytics (INTEL-002, Phase 3)

Social Network Analysis over the Telegram actor graph. Reads the interaction graph
(Actors + weighted `REPLIED_TO` / `MENTIONED` edges) that `db_writer` builds in
Neo4j, computes per-actor SNA metrics, and writes them back to `telegram_actors`
(Postgres, for the dashboard) and onto the Neo4j Actor nodes (for graph colouring).

Runs on an interval (`GRAPH_ANALYTICS_INTERVAL`, default 300s). Honours an
`analytics_enabled='false'` row in `system_settings` as a pause/kill switch.

## Why volume ≠ control
The loudest account is usually a hype-man. The controller's signature is
**structural**: high betweenness (bridges sub-cells) + high in-reply (others
direct queries to them) + **low** message volume. `orchestrator_likelihood`
encodes that, so a quiet broker ranks above the noisiest poster.

## Metrics (networkx — same algorithms Neo4j GDS would run)
| Column written | Metric |
|---|---|
| `pagerank` | influence weighted by who connects to you |
| `betweenness` | brokers on the most shortest paths between sub-cells |
| `in_reply_degree` | weighted replies/mentions directed *at* the actor |
| `cell_id` | Louvain community (sub-cell) |
| `influence_score` | `0.5·pagerank + 0.3·in_reply + 0.2·betweenness` (normalized) |
| `orchestrator_likelihood` | `0.4·betweenness + 0.4·in_reply + 0.2·(1−volume)` |
| `inferred_role` | leader / lieutenant / operator / peripheral |

## Why networkx instead of Neo4j GDS
The `neo4j:5.20-community` image does not ship the GDS plugin (it would need an
internet-at-startup download + a Neo4j restart). The algorithms used (PageRank,
betweenness, Louvain) are identical; computing them in-process is dependency-free
and works offline. Swappable for `CALL gds.*` later if desired.
