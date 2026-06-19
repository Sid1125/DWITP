# DB Writer Module

Pipeline consumer that writes classified data to PostgreSQL, indexes to OpenSearch, and updates Neo4j graph. Consumes `ai.output` queue.

## API

- `write_to_postgres(record)` — upserts into `classifications` table, inserts into `intelligence_findings` for high-risk categories.
- `index_to_opensearch(record)` — indexes to `dwitp-classifications` index.
- `update_neo4j_graph(record)` — merges `Classification` node.
- `process_classification(record)` — calls all three stores sequentially.

## Threat Model

- **DB credential exposure** — credentials sourced from environment variables only, never logged.
- **Injection via stored content** — mitigated by parameterized queries (psycopg2 `%s` placeholders).
- **Connection failure** — caught and logged as `ERROR`; downstream stores attempted independently.

## Test Coverage

Not tested — requires live PostgreSQL, OpenSearch, and Neo4j services. Infra-dependent exclusion documented in `pyproject.toml`.
