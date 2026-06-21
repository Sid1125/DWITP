#!/usr/bin/env bash
# DWITP End-to-End Pipeline Test
# Injects a synthetic crawl record through the real (TLS) queue and polls the DB
# at the stages that actually persist: raw_evidence and classifications.
# Usage: ./scripts/e2e_test.sh [--cleanup]
set -euo pipefail

cd "$(cd "$(dirname "$0")/.." && pwd)"

CLEANUP="${1:-}"
PASS=0; FAIL=0
pass() { echo "  PASS  $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL  $1"; FAIL=$((FAIL + 1)); }
info() { echo "        $1"; }
docker_exec() { docker exec "$1" "${@:2}" 2>/dev/null; }

MAX_POLL=30; POLL_INTERVAL=5
poll_for() {
    local label="$1"; shift
    for ((a=0; a<MAX_POLL; a++)); do
        if "$@" 2>/dev/null; then pass "$label"; return 0; fi
        sleep $POLL_INTERVAL
    done
    fail "$label (timeout after $((MAX_POLL * POLL_INTERVAL))s)"; return 1
}

echo ""
echo "=== DWITP End-to-End Pipeline Test ==="

# A valid UUID is required — raw_evidence.record_id / classifications.record_id are uuid columns.
TEST_ID=$(docker exec dwitp-crawler python -c "import uuid; print(uuid.uuid4())")
TEST_SHA="e2e$(date +%s)$(printf '%060d' 0)"; TEST_SHA="${TEST_SHA:0:64}"
echo "  Test record_id: $TEST_ID"
echo ""

# ─── 1. Pipeline containers running ───────────────────────────────
echo "[check] Pipeline containers running..."
for svc in rabbitmq postgres sanitizer analysis ai-layer db-writer dashboard; do
    [ "$(docker inspect -f '{{.State.Running}}' dwitp-$svc 2>/dev/null)" = "true" ] \
        && pass "dwitp-$svc" || fail "dwitp-$svc (not running)"
done

# ─── 2. Required tables exist ─────────────────────────────────────
echo ""
echo "[check] Database schema..."
for table in raw_evidence classifications intelligence_findings; do
    docker_exec dwitp-postgres psql -U dwitp -d dwitp -tAc \
        "SELECT to_regclass('public.${table}') IS NOT NULL;" | grep -qi t \
        && pass "table $table" || fail "table $table missing"
done

# ─── 3. Inject via the real TLS queue (crawler's QueueClient) ─────
echo ""
echo "[publish] Injecting synthetic record on raw.crawl (TLS)..."
docker exec dwitp-crawler python -c "
from src.common.queue import QueueClient
from datetime import datetime, timezone
QueueClient().publish('raw.crawl', {
    'record_id': '${TEST_ID}',
    'source': 'e2e-test',
    'url': 'http://e2e-${TEST_ID}.onion/',
    'raw_text': 'End-to-end pipeline test record ${TEST_ID} cocaine for sale stealth shipping.',
    'sha256': '${TEST_SHA}',
    'timestamp_utc': datetime.now(timezone.utc).isoformat(),
    'risk_score': 0.5,
})
print('published')
" 2>&1 | grep -q published && pass "record published" || fail "record published"

# ─── 4. Poll the stages that persist ──────────────────────────────
echo ""
echo "[pipeline] Polling DB (raw_evidence -> classifications)..."
poll_for "raw_evidence written" \
    bash -c "docker exec dwitp-postgres psql -U dwitp -d dwitp -tAc \"SELECT 1 FROM raw_evidence WHERE record_id='${TEST_ID}'\" 2>/dev/null | grep -q 1"
poll_for "classified" \
    bash -c "docker exec dwitp-postgres psql -U dwitp -d dwitp -tAc \"SELECT 1 FROM classifications WHERE record_id='${TEST_ID}'\" 2>/dev/null | grep -q 1"
CAT=$(docker_exec dwitp-postgres psql -U dwitp -d dwitp -tAc "SELECT category FROM classifications WHERE record_id='${TEST_ID}'" | tr -d '[:space:]')
info "classified as: ${CAT:-<none>}"

# ─── 5. Dashboard ─────────────────────────────────────────────────
echo ""
echo "[dashboard] /health over HTTPS..."
docker_exec dwitp-dashboard python -c "
import http.client, ssl
c=http.client.HTTPSConnection('localhost',8080,context=ssl._create_unverified_context(),timeout=5)
c.request('GET','/health'); exit(0 if c.getresponse().status==200 else 1)" \
    && pass "dashboard /health 200" || fail "dashboard /health 200"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$CLEANUP" = "--cleanup" ]; then
    info "Cleaning up test data..."
    docker_exec dwitp-postgres psql -U dwitp -d dwitp -c \
        "DELETE FROM classifications WHERE record_id='${TEST_ID}'; DELETE FROM raw_evidence WHERE record_id='${TEST_ID}';" >/dev/null 2>&1 || true
    echo "  Done."
fi
exit $FAIL
