#!/usr/bin/env bash
# DWITP Deployment Health Check
# Usage: ./scripts/healthcheck.sh
set -uo pipefail

cd "$(cd "$(dirname "$0")/.." && pwd)"

PASS=0; FAIL=0
pass() { echo "  PASS  $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL  $1"; FAIL=$((FAIL + 1)); }
dx() { docker exec "$1" "${@:2}" 2>/dev/null; }

container_healthy() {
    local cid="dwitp-$1" running status
    running=$(docker inspect -f '{{.State.Running}}' "$cid" 2>/dev/null) || return 1
    [ "$running" = "true" ] || return 1
    status=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$cid" 2>/dev/null)
    # empty status = no healthcheck defined -> treat "running" as healthy
    [ -z "$status" ] || [ "$status" = "healthy" ]
}
container_exists() { docker inspect "dwitp-$1" &>/dev/null; }

echo "=== DWITP Health Check ==="
echo ""
echo "[infrastructure]"
docker info -f '{{.ServerVersion}}' &>/dev/null && pass "docker engine" || fail "docker engine"

# Container short-names use HYPHENS (dwitp-ai-layer, dwitp-db-writer, ...).
echo ""
echo "[containers]"
for svc in tor rabbitmq postgres opensearch neo4j \
           crawler sanitizer analysis ai-layer db-writer dashboard \
           telegram-collector graph-analytics; do
    if container_exists "$svc"; then
        container_healthy "$svc" && pass "dwitp-$svc" || fail "dwitp-$svc (not healthy)"
    else
        fail "dwitp-$svc (not found)"
    fi
done

echo ""
echo "[postgres]"
container_exists postgres && { dx dwitp-postgres pg_isready -U "${POSTGRES_USER:-dwitp}" &>/dev/null \
    && pass "pg_isready" || fail "pg_isready"; }

echo ""
echo "[opensearch]"
# Security plugin is disabled in this deployment => plain HTTP, no auth.
if container_exists opensearch; then
    health=$(dx dwitp-opensearch curl -s http://localhost:9200/_cluster/health)
    echo "$health" | grep -q '"status"' && pass "cluster reachable" || fail "cluster reachable"
    echo "$health" | grep -q '"status":"red"' && fail "cluster is red" || pass "cluster not red"
fi

echo ""
echo "[neo4j]"
# Verify bolt connectivity from db-writer (which holds the driver + creds).
if container_exists db-writer; then
    dx dwitp-db-writer python -c "
import os
from neo4j import GraphDatabase
d = GraphDatabase.driver(os.environ['NEO4J_URI'], auth=(os.environ['NEO4J_USER'], os.environ['NEO4J_PASSWORD']))
d.verify_connectivity(); d.close()
" && pass "bolt connectivity" || fail "bolt connectivity"
fi

echo ""
echo "[dashboard]"
if container_exists dashboard; then
    dx dwitp-dashboard python -c "
import http.client, ssl
c = http.client.HTTPSConnection('localhost', 8080, context=ssl._create_unverified_context(), timeout=5)
c.request('GET', '/health'); exit(0 if c.getresponse().status == 200 else 1)" \
        && pass "/health 200 (https)" || fail "/health 200 (https)"
fi

echo ""
echo "[pipeline]"
if container_exists sanitizer; then
    dx dwitp-sanitizer python -c "
from src.common.queue import QueueClient
c = QueueClient(); c.connect(); c.close()" \
        && pass "sanitizer -> rabbitmq (TLS)" || fail "sanitizer -> rabbitmq (TLS)"
fi

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
exit $FAIL
