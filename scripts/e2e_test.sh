#!/usr/bin/env bash
# DWITP End-to-End Pipeline Test
# Injects a synthetic crawl record and polls each pipeline stage.
# Usage: ./scripts/e2e_test.sh [--cleanup]
set -euo pipefail

cd "$(cd "$(dirname "$0")/.." && pwd)"

CLEANUP="${1:-}"
TEST_ID="e2e-$(date +%s)"
TEST_SOURCE="e2e-test"
TEST_URL="http://e2e-test-${TEST_ID}.onion/"
TEST_TEXT="End-to-end pipeline test record ${TEST_ID}."
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

MAX_POLL=30      # 30 attempts × 5s = 150s max wait
POLL_INTERVAL=5

PASS=0
FAIL=0

pass() { echo "  PASS  $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL  $1"; FAIL=$((FAIL + 1)); }
info() { echo "        $1"; }

poll_for() {
    # Usage: poll_for <label> <command...>
    local label="$1"; shift
    local attempt=0
    while [ $attempt -lt $MAX_POLL ]; do
        if "$@" 2>/dev/null; then
            pass "$label"
            return 0
        fi
        attempt=$((attempt + 1))
        sleep $POLL_INTERVAL
    done
    fail "$label (timeout after $((MAX_POLL * POLL_INTERVAL))s)"
    return 1
}

docker_exec() {
    docker exec "$1" "${@:2}" 2>/dev/null
}

cleanup_data() {
    echo ""
    info "Cleaning up test data..."
    for table in raw_evidence sanitized_records analysis_results classifications; do
        docker_exec dwitp-postgres psql -U dwitp -d dwitp -c \
            "DELETE FROM $table WHERE record_id = '${TEST_ID}';" 2>/dev/null || true
    done
    echo "  Done."
}

# ─── 1. Verify prerequisites ──────────────────────────────────────
echo ""
echo "=== DWITP End-to-End Pipeline Test ==="
echo "  Test ID:   $TEST_ID"
echo "  Source:    $TEST_SOURCE"
echo "  Max wait:  $((MAX_POLL * POLL_INTERVAL))s"
echo ""

# ─── 2. Check pipeline containers are healthy ─────────────────────
echo "[check] Pipeline containers..."
for svc in rabbitmq sanitizer analysis ai_layer db_writer postgres dashboard; do
    if docker inspect --format="{{.State.Health.Status}}" "dwitp-$svc" 2>/dev/null | \
       grep -q "healthy"; then
        pass "dwitp-$svc"
    else
        fail "dwitp-$svc (not healthy)"
    fi
done

# ─── 3. Verify database schema ────────────────────────────────────
echo ""
echo "[check] Database schema..."
for table in raw_evidence sanitized_records analysis_results classifications \
             intelligence_findings source_reputation; do
    docker_exec dwitp-postgres psql -U dwitp -d dwitp -t -c \
        "SELECT 1 FROM information_schema.tables \
         WHERE table_name = '${table}';" | grep -q 1 \
        && pass "table $table exists" \
        || fail "table $table missing"
done

# ─── 4. Publish synthetic record ──────────────────────────────────
echo ""
echo "[publish] Injecting synthetic record..."
RABBITMQ_PASS=$(docker exec dwitp-rabbitmq sh -c 'echo $RABBITMQ_DEFAULT_PASS' 2>/dev/null || true)
if [ -z "$RABBITMQ_PASS" ]; then
    # Fallback: read from .env
    RABBITMQ_PASS=$(grep RABBITMQ_PASSWORD .env | cut -d= -f2)
fi

docker exec dwitp-crawler python3 -c "
import json, pika, os
os.environ.setdefault('RABBITMQ_USE_SSL', 'false')
params = pika.ConnectionParameters(
    host='rabbitmq', port=5672,
    credentials=pika.PlainCredentials('dwitp', '$RABBITMQ_PASS'),
    virtual_host='/dwitp')
conn = pika.BlockingConnection(params)
chan = conn.channel()
chan.queue_declare(queue='raw.crawl', durable=True)
chan.basic_publish(
    exchange='', routing_key='raw.crawl',
    body=json.dumps({
        'record_id': '$TEST_ID',
        'source': '$TEST_SOURCE',
        'url': '$TEST_URL',
        'raw_text': '$TEST_TEXT',
        'sha256': 'e2e-test-synthetic',
        'timestamp_utc': '$TIMESTAMP',
        'collected_at': '$TIMESTAMP',
    }))
conn.close()
print('Published: $TEST_ID')
" 2>&1 | head -1 && pass "record published" || fail "record published"

# ─── 5. Verify pipeline processing ───────────────────────────────
echo ""
echo "[pipeline] Polling for record at each stage..."

poll_for "raw_evidence" \
    docker_exec dwitp-postgres psql -U dwitp -d dwitp -t -c \
        "SELECT record_id FROM raw_evidence WHERE record_id = '${TEST_ID}';" \
        | grep -q "${TEST_ID}"

poll_for "sanitized_records" \
    docker_exec dwitp-postgres psql -U dwitp -d dwitp -t -c \
        "SELECT record_id FROM sanitized_records WHERE record_id = '${TEST_ID}';" \
        | grep -q "${TEST_ID}"

poll_for "analysis_results" \
    docker_exec dwitp-postgres psql -U dwitp -d dwitp -t -c \
        "SELECT record_id FROM analysis_results WHERE record_id = '${TEST_ID}';" \
        | grep -q "${TEST_ID}"

poll_for "classifications" \
    docker_exec dwitp-postgres psql -U dwitp -d dwitp -t -c \
        "SELECT record_id FROM classifications WHERE record_id = '${TEST_ID}';" \
        | grep -q "${TEST_ID}"

# ─── 6. Dashboard check ──────────────────────────────────────────
echo ""
echo "[dashboard] Verifying dashboard..."
docker_exec dwitp-dashboard sh -c \
    "curl -sf -o /dev/null -w '%{http_code}' http://localhost:8080/" \
    | grep -q 200 && pass "dashboard HTTP 200" || fail "dashboard HTTP 200"

# ─── Results ─────────────────────────────────────────────────────
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$CLEANUP" = "--cleanup" ]; then
    cleanup_data
fi

exit $FAIL
