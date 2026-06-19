#!/usr/bin/env bash
# DWITP Deployment Health Check
# Usage: ./scripts/healthcheck.sh
set -euo pipefail

cd "$(cd "$(dirname "$0")/.." && pwd)"

PASS=0
FAIL=0

pass() { echo "  PASS  $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL  $1"; FAIL=$((FAIL + 1)); }

docker_exec() {
    # Usage: docker_exec <container> <command...>
    docker exec "$1" "${@:2}" 2>/dev/null
}

container_healthy() {
    # Returns 0 if container is running AND health status is "healthy" (or no healthcheck)
    local cid="dwitp-$1"
    local running status
    running=$(docker inspect --format="{{.State.Running}}" "$cid" 2>/dev/null) || return 1
    [ "$running" = "true" ] || return 1
    status=$(docker inspect --format="{{.State.Health.Status}}" "$cid" 2>/dev/null)
    # If no healthcheck defined, status is empty — treat as healthy
    [ -z "$status" ] || [ "$status" = "healthy" ] || return 1
    return 0
}

container_exists() {
    docker inspect "dwitp-$1" &>/dev/null
}

echo "=== DWITP Health Check ==="
echo ""

# ─── Infrastructure ───────────────────────────────────────────────
echo "[infrastructure]"
docker info --format "{{.ServerVersion}}" &>/dev/null && pass "docker engine" || fail "docker engine"

# ─── Running Containers ──────────────────────────────────────────
echo ""
echo "[containers]"
for svc in tor rabbitmq postgres opensearch neo4j ollama \
           crawler sanitizer analysis ai_layer dashboard db_writer; do
    if container_exists "$svc"; then
        if container_healthy "$svc"; then
            pass "dwitp-$svc"
        else
            fail "dwitp-$svc (not healthy)"
        fi
    else
        # tls-init and ollama-pull are one-shot — may have exited
        if [ "$svc" = "tls-init" ] || [ "$svc" = "ollama-pull" ]; then
            pass "dwitp-$svc (one-shot, may be exited)"
        else
            fail "dwitp-$svc (not found)"
        fi
    fi
done

# ─── RabbitMQ ─────────────────────────────────────────────────────
echo ""
echo "[rabbitmq]"
if container_exists rabbitmq; then
    docker_exec dwitp-rabbitmq rabbitmq-diagnostics status --silent &>/dev/null \
        && pass "rabbitmq status" \
        || fail "rabbitmq status"
    docker_exec dwitp-rabbitmq sh -c "ss -tln | grep -q :5671" &>/dev/null \
        && pass "listening :5671" \
        || fail "listening :5671"
fi

# ─── PostgreSQL ───────────────────────────────────────────────────
echo ""
echo "[postgres]"
if container_exists postgres; then
    docker_exec dwitp-postgres pg_isready -U dwitp -d dwitp &>/dev/null \
        && pass "pg_isready" \
        || fail "pg_isready"
    docker_exec dwitp-postgres sh -c "ss -tln | grep -q :5432" &>/dev/null \
        && pass "listening :5432" \
        || fail "listening :5432"
fi

# ─── OpenSearch ───────────────────────────────────────────────────
echo ""
echo "[opensearch]"
if container_exists opensearch; then
    docker_exec dwitp-opensearch sh -c \
        "curl -sf -u admin:\$OPENSEARCH_INITIAL_ADMIN_PASSWORD \
         https://localhost:9200/_cluster/health" &>/dev/null \
        && pass "cluster reachable" \
        || fail "cluster reachable"
    docker_exec dwitp-opensearch sh -c \
        "curl -sf -u admin:\$OPENSEARCH_INITIAL_ADMIN_PASSWORD \
         https://localhost:9200/_cluster/health" \
        | grep -q '"status":"red"' && fail "cluster is red" || pass "cluster not red"
fi

# ─── Neo4j ────────────────────────────────────────────────────────
echo ""
echo "[neo4j]"
if container_exists neo4j; then
    docker_exec dwitp-neo4j sh -c "ss -tln | grep -q :7687" &>/dev/null \
        && pass "listening :7687" \
        || fail "listening :7687"
fi

# ─── Ollama ───────────────────────────────────────────────────────
echo ""
echo "[ollama]"
if container_exists ollama; then
    docker_exec dwitp-ollama sh -c \
        "curl -sf http://localhost:11434/api/tags" &>/dev/null \
        && pass "API reachable" \
        || fail "API reachable"
fi

# ─── Dashboard ────────────────────────────────────────────────────
echo ""
echo "[dashboard]"
if container_exists dashboard; then
    docker_exec dwitp-dashboard python3 -c "
import http.client
c = http.client.HTTPConnection('localhost', 8080)
c.request('GET', '/')
r = c.getresponse()
exit(0 if r.status == 200 else 1)
" &>/dev/null && pass "HTTP 200" || fail "HTTP 200"
fi

# ─── Pipeline connectivity ────────────────────────────────────────
echo ""
echo "[pipeline]"
if container_exists sanitizer; then
    docker exec dwitp-sanitizer \
        python3 -c "
import sys
sys.path.insert(0, '/app')
from src.common.queue import QueueClient
c = QueueClient()
c.connect()
c.close()
print('OK')
" &>/dev/null && pass "sanitizer → rabbitmq" || fail "sanitizer → rabbitmq"
fi

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
exit $FAIL
